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
  [/\b(free|zfree|kfree|xfree|release|destroy|close)\s*\(/, "free-site",
    "a free/release — prove the pointer is not used (or re-freed) afterward on any path (use-after-free / double-free)"],
  [/\b(luaS_new|lua_|incr_top|setsvalue|sethvalue|setobj|GC|gc_)/, "gc-rooting",
    "an allocation/stack op in a GC'd runtime — prove the object is rooted/anchored before any call that can allocate or trigger GC (else use-after-free)"]
];

// Extract obligations from one file. Returns [{ line, kind, obligation, text }], capped.
export function extractObligations(target, filePath, { cap = 80 } = {}) {
  const ext = filePath.slice(filePath.lastIndexOf(".")).toLowerCase();
  if (!NATIVE_EXT.has(ext)) return [];
  const path = resolve(target, filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return [];
  let lines;
  try { lines = readFileSync(path, "utf8").split(/\r?\n/); } catch { return []; }

  const out = [];
  for (let i = 0; i < lines.length && out.length < cap; i += 1) {
    const text = lines[i];
    if (!text || text.length > 400) continue;
    const trimmed = text.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;
    for (const [re, kind, obligation] of RULES) {
      if (re.test(text)) {
        out.push({ line: i + 1, kind, obligation, text: trimmed.slice(0, 200) });
        break; // one obligation per line is enough to flag it
      }
    }
  }
  return out;
}
