// Memory-sink obligation extractor — the AIxCC fidelity borrow.
//
// The winning CRSs don't ask an LLM to *spot* memory bugs while free-reading; a static
// pass (Infer/Joern) enumerates dangerous sinks and the LLM's job is to DISCHARGE each
// one — prove the bound holds, or report the overflow. That converts "read 3,000 lines
// and notice the bug" (which Sonnet AND Opus missed on redis) into a finite checklist of
// concrete obligations over the exact dangerous primitives. This is that enumerator:
// deterministic, language-aware for C-family/native code, cheap (regex over the file).
//
// Each obligation is a SITE the agent must reason about, not a finding — it carries the
// line + the primitive + what must be proven. Precision-agnostic on purpose: false sites
// are fine (the agent discharges them as safe); the goal is to never let a real one go
// unlooked-at.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

const NATIVE_EXT = new Set([".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".m", ".mm", ".rs", ".go"]);

// (regex, kind, obligation) — kept deliberately broad. `kind` groups them; `obligation`
// is the exact thing the agent must prove.
const RULES = [
  [/\b[A-Za-z_]\w*\s+\**\w+\s*\[\s*[A-Za-z_][\w]*\s*\]/, "fixed-size-buffer",
    "a fixed-size (constant-bounded) buffer — prove every write index/length stays < its capacity for all attacker-influenced inputs, or it overflows"],
  [/\b(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsprintf|alloca|gets|scanf|read|recv)\s*\(/, "raw-copy",
    "a raw memory copy/format — prove the destination is large enough for the (attacker-influenced) length, or it overflows"],
  [/\b(malloc|calloc|realloc|zmalloc|zrealloc|xmalloc|kmalloc)\s*\([^;]*[*+][^;]*\)/, "alloc-arith",
    "an allocation size computed with arithmetic — prove it cannot integer-overflow/under-allocate for attacker-influenced operands"],
  // Integer-overflow → OOB. Overflow-prone arithmetic (a binary multiply, a left-shift, or a length
  // MINUS a product) feeding a memory length, index, or offset. Generalizes `alloc-arith` past malloc
  // to copy-lengths and index/offset math. This is the class a small-input fuzzer categorically CANNOT
  // reach when the overflow needs a huge operand — e.g. a 32-bit `count`/`sep` accumulator in a lexer's
  // long-bracket length math (`buflen - 2*(2+sep)`), where the wrap only happens past ~2^30 of input.
  // Structural only: keys on the arithmetic shape + an index bracket or a size/length/offset cue word.
  [/(?:\[[^\]\n]*[\w)]\s*(?:<<|\*)\s*[(\w][^\]\n]*\])|(?:\b\w*(?:len|size|count|sep|off|idx|index|nbytes|nmemb|width|height|cap)\w*\b[^;\n]*?[-+]\s*\w+\s*\*\s*[(\w])/i, "int-overflow-size",
    "a memory length/index/offset computed with overflow-prone arithmetic (multiply, shift, or a length minus a product) — prove no signed/`int` counter can overflow/wrap and no unsigned length can underflow for attacker-influenced sizes, else integer-overflow → out-of-bounds read/write (CWE-190 → CWE-125/787)"],
  [/\b(luaS_new|lua_|incr_top|setsvalue|sethvalue|setobj|gc_)/, "gc-rooting",
    "an allocation/stack op in a GC'd runtime — prove the object is rooted/anchored before any call that can allocate or trigger GC (else use-after-free)"],
  // Lifetime/release primitive — the shape of a use-after-free / double-free. Keyed on
  // UNIVERSAL release verbs (C free-family, C++ delete/reset, Python C-API DECREF, generic
  // release/destroy) — never on any project symbol or CVE line — so it fires on any native
  // codebase. Placed LAST so a `realloc(n*sz)` still tags alloc-arith first (first-match wins).
  [/\b(free|kfree|vfree|g_free|xfree|delete|Py_DECREF|Py_XDECREF|RefCount|release|destroy)\b\s*[(.]|->\s*reset\(/, "lifetime-free",
    "a release/free of an object — prove the pointer (and every alias/stored copy) is not read, written, or re-freed on ANY later path (including loop re-entry and error/cleanup branches), else use-after-free (CWE-416) / double-free (CWE-415)"]
];

// Extract obligations from one file. Returns [{ line, kind, obligation, text }].
// When more than `cap` sites exist, sample them EVENLY across the file (not the first
// N) so a dangerous primitive deep in a long file — e.g. a fixed-size buffer at line
// 3538 of a 4000-line file — is still represented. Keeps prep.json small enough for
// the agent's file-read limit while never biasing to the top of the file.
export function extractObligations(target, filePath, { cap = 32 } = {}) {
  const ext = filePath.slice(filePath.lastIndexOf(".")).toLowerCase();
  if (!NATIVE_EXT.has(ext)) return [];
  const path = resolve(target, filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return [];
  let lines;
  try { lines = readFileSync(path, "utf8").split(/\r?\n/); } catch { return []; }

  const all = [];
  for (let i = 0; i < lines.length; i += 1) {
    const text = lines[i];
    if (!text || text.length > 400) continue;
    const trimmed = text.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;
    for (const [re, kind, obligation] of RULES) {
      if (re.test(text)) {
        all.push({ line: i + 1, kind, obligation, text: trimmed.slice(0, 200) });
        break; // one obligation per line is enough to flag it
      }
    }
  }
  if (all.length <= cap) return all;
  // Even stride sample across the file so late-file sites survive the cap.
  const step = all.length / cap;
  const sampled = [];
  for (let k = 0; k < cap; k += 1) sampled.push(all[Math.floor(k * step)]);
  return sampled;
}
