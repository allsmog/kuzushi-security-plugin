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

// Pure C/C++ — memory obligations only.
const NATIVE_EXT = new Set([".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".m", ".mm"]);
// Systems languages that ALSO run web/exec/SQL surfaces — get both rulesets.
const SYS_EXT = new Set([".rs", ".go"]);
// Managed/scripting web languages — injection/authz/logic obligations.
const WEB_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".php", ".java", ".cs", ".kt", ".scala", ".php5", ".phtml"]);

// (regex, kind, obligation) — kept deliberately broad. `kind` groups them; `obligation`
// is the exact thing the agent must prove.
const NATIVE_RULES = [
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
  // GC-rooting fires ONLY on calls that actually allocate or can step the collector — the
  // bare `lua_` prefix matched every accessor (`lua_gettop`, `lua_toboolean`, …) and buried the
  // real site under ~200 noise obligations (measured on lbaselib.c: 203/204 were noise). Keeping
  // it to the allocating / GC-triggering subset preserves the true sites (luaS_new, lua_newtable,
  // lua_pushstring, lua_call, …) while dropping the inert accessors.
  [/\b(luaS_new\w*|luaH_new\w*|luaC_\w+|luaM_\w*(?:new|malloc|realloc)\w*|incr_top|setsvalue|sethvalue|setobj|gc_\w+|lua_(?:newtable|createtable|newuserdata\w*|pushstring|pushlstring|pushfstring|pushvfstring|pushcclosure|concat|checkstack|call|pcall|getfield|setfield|gettable|settable|rawset|next|error)\b)/, "gc-rooting",
    "an allocation/stack op in a GC'd runtime — prove the object is rooted/anchored before any call that can allocate or trigger GC (else use-after-free)"],
  // Lifetime/release primitive — the shape of a use-after-free / double-free. Keyed on
  // UNIVERSAL release verbs (C free-family, C++ delete/reset, Python C-API DECREF, generic
  // release/destroy) — never on any project symbol or CVE line — so it fires on any native
  // codebase. Placed LAST so a `realloc(n*sz)` still tags alloc-arith first (first-match wins).
  [/\b(free|kfree|vfree|g_free|xfree|delete|Py_DECREF|Py_XDECREF|RefCount|release|destroy)\b\s*[(.]|->\s*reset\(/, "lifetime-free",
    "a release/free of an object — prove the pointer (and every alias/stored copy) is not read, written, or re-freed on ANY later path (including loop re-entry and error/cleanup branches), else use-after-free (CWE-416) / double-free (CWE-415)"]
];

// Web / managed-language obligations — the injection / authz / logic classes. Same
// contract as the native rules: each is a SITE the agent must DISCHARGE (prove the
// guard holds for all attacker inputs) or report. Generalizes the AIxCC obligation
// loop past memory bugs so the discovery agent isn't free-reading for these either.
// Order = most-dangerous first; one obligation per line (first match wins).
const WEB_RULES = [
  [/\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(|\b(os\.system|subprocess\.(run|call|Popen|check_output|check_call)|commands\.getoutput)\s*\(|\b(shell_exec|passthru|proc_open|popen|system)\s*\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(/, "command-exec",
    "a process/command execution — prove no attacker-influenced operand reaches a shell (pass an argv array, never build a shell string), else OS command injection (CWE-78)"],
  [/\b(pickle|cPickle)\.loads?\s*\(|\byaml\.(unsafe_)?load\s*\(|\bmarshal\.loads?\s*\(|\bMarshal\.load\s*\(|\bunserialize\s*\(|ObjectInputStream|\.readObject\s*\(|node-serialize|yaml\.load\s*\([^)]*$/, "deserialization",
    "deserialization of input — prove the bytes are trusted/typed/schema-validated (no untrusted source, no polymorphic gadget types reachable), else deserialization RCE / prototype pollution (CWE-502/1321)"],
  [/\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*["'`]|\bvm\.runIn\w+\s*\(|\bexec\s*\(\s*["'`]|\bcompile\s*\(.*['"]exec['"]/, "dynamic-eval",
    "dynamic code evaluation — prove the evaluated string contains no attacker-influenced data, else arbitrary code execution (CWE-94/95)"],
  [/\.(query|execute|executemany|exec|raw|prepare|annotate|extra)\s*\(|cursor\(\)\.execute|sequelize\.query|knex\.raw|\bdb\.run\s*\(|createQuery\s*\(|@Query\s*\(/, "sql-sink",
    "a SQL query/exec — prove every attacker-influenced operand is bound as a parameter (placeholder), not concatenated/interpolated into the SQL string, else SQL injection (CWE-89)"],
  [/\b(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|sendFile|send_file|fopen|file_get_contents|file_put_contents|readlink|unlink|fs\.open)\s*\(|new\s+File\s*\(|Paths\.get\s*\(/, "path-fs",
    "a filesystem path operation — prove the resolved path cannot escape its intended base (canonicalize + containment check) for attacker-influenced components, else path traversal (CWE-22)"],
  [/\b(requests\.(get|post|put|delete|head|request)|urllib\.(request\.)?urlopen|urlopen|http\.(get|request)|https\.(get|request)|fetch|axios\.(get|post|put|request)|got|superagent|HttpClient|openConnection|curl_exec)\s*\(/, "ssrf",
    "an outbound HTTP/URL request — prove the host/scheme is NOT attacker-controlled (allowlist host; block internal/link-local/metadata targets), else SSRF (CWE-918). Path-only control is out of scope (taxonomy rule 5)"],
  [/dangerouslySetInnerHTML|\.innerHTML\s*=|insertAdjacentHTML|\bv-html\b|\|\s*safe\b|html_safe|mark_safe|render_template_string|\.html\s*\(|document\.write\s*\(|@Html\.Raw|Markup\s*\(/, "template-xss",
    "raw HTML / unescaped template rendering with data — prove no attacker-influenced value reaches it unescaped (or the framework auto-escapes on THIS path with no raw escape hatch), else XSS / SSTI (CWE-79/1336). Auto-escaping frameworks with no raw sink are taxonomy rule 14"],
  [/\b(findById|find_by_id|getById|findByPk|findOne|get_object_or_404)\s*\(|objects\.get\s*\(|\.get\s*\(\s*(?:id|pk)\s*=|WHERE\s+id\s*=/, "object-authz",
    "an object fetched by a (possibly user-supplied) identifier — prove an ownership/tenant check gates access to the returned object on THIS path, else IDOR / broken object-level authz (CWE-639). Only matters if the id is reachable from untrusted input"],
  [/\b(user_id|userId|owner_id|ownerId|tenant_id|tenantId|account_id|accountId)\b\s*(===?|!==?)|\b(hasRole|hasPermission|isAuthorized|checkAccess|requireRole|ensureOwner|authorize|can)\s*\(|@(login_required|requires_auth|roles_required|PreAuthorize|RolesAllowed)/, "authz-decision",
    "an authorization/ownership decision — prove the mutation or sensitive read on this path cannot be reached with the check omitted or a forged identity (authorization-by-omission), else broken access control (CWE-285/862)"],
  [/\b(res\.redirect|response\.redirect|sendRedirect|HttpResponseRedirect|redirect)\s*\(|header\s*\(\s*["']Location/, "open-redirect",
    "a redirect whose target may be attacker-influenced — if unvalidated against an allowlist it is an open redirect (CWE-601). Low impact alone (taxonomy rule 12) — note it, weigh it as a phishing/chain primitive, do not over-promote"]
];

function rulesFor(ext) {
  if (NATIVE_EXT.has(ext)) return NATIVE_RULES;
  if (SYS_EXT.has(ext)) return [...NATIVE_RULES, ...WEB_RULES];
  if (WEB_EXT.has(ext)) return WEB_RULES;
  return [];
}

// Extract obligations from one file. Returns [{ line, kind, obligation, text }].
// When more than `cap` sites exist, sample them EVENLY across the file (not the first
// N) so a dangerous primitive deep in a long file — e.g. a fixed-size buffer at line
// 3538 of a 4000-line file — is still represented. Keeps prep.json small enough for
// the agent's file-read limit while never biasing to the top of the file.
export function extractObligations(target, filePath, { cap = 32 } = {}) {
  const ext = filePath.slice(filePath.lastIndexOf(".")).toLowerCase();
  const rules = rulesFor(ext);
  if (!rules.length) return [];
  const path = resolve(target, filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return [];
  let lines;
  try { lines = readFileSync(path, "utf8").split(/\r?\n/); } catch { return []; }

  const all = [];
  for (let i = 0; i < lines.length; i += 1) {
    const text = lines[i];
    if (!text || text.length > 400) continue;
    const trimmed = text.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*") || trimmed.startsWith("#")) continue;
    for (const [re, kind, obligation] of rules) {
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
