// Cheap cross-file reachability. The tree-sitter MCP `callers` tool is single-file,
// and a full CodeQL/Joern CPG is heavy and not always built — so a deep-scan or
// verify agent reasoning about "is this function reachable from an entry point?"
// has, by default, no way to follow a call across files. This is the lightweight
// bridge: a ripgrep-backed repo-wide call-site finder. It is a REACHABILITY HINT,
// not sound dataflow — it finds textual call sites of a symbol so the agent knows
// which files to open next. The agent still confirms the actual flow.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { runRg, parseJsonMatches, buildGlobs } from "./ripgrep.mjs";
import { enclosingExcerpt } from "./excerpt.mjs";

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const norm = (p) => String(p ?? "").replace(/^\.\//, "");

// Repo-wide call sites of `symbol` (textual `symbol(` occurrences), excluding the
// definition lines as best we can. scopeDir narrows to a subtree. Returns
// [{ filePath, line, text }] capped at `limit`. Empty array if rg unavailable.
export function crossFileCallers(target, symbol, { scopeDir = ".", limit = 50 } = {}) {
  if (!symbol || String(symbol).length < 2) return [];
  const pat = `(^|[^\\w.])${escapeRe(symbol)}\\s*\\(`;
  const result = runRg(target, ["--json", "-n", "--max-count", "20", "-e", pat, ...buildGlobs(), scopeDir === "." ? "." : scopeDir]);
  if (!result.ok) return [];
  const sym = escapeRe(symbol);
  // A definition site is the keyword *immediately* naming this symbol
  // (`function runQuery(`, `def runQuery(`) or an assigned-function form
  // (`runQuery = function`/`runQuery = (`/`const runQuery = (`). NOT just any line
  // that happens to contain a `function` keyword and a call to the symbol.
  const defRe = new RegExp(`\\b(function|func|def|fn|sub)\\s+${sym}\\b|\\b${sym}\\s*[:=]\\s*(async\\s*)?(function\\b|\\()`);
  return parseJsonMatches(result.stdout, 400)
    .filter((h) => h.text && !defRe.test(h.text)) // drop the definition site
    .map((h) => ({ filePath: String(h.filePath ?? "").replace(/^\.\//, ""), line: h.line, text: (h.text ?? "").trim() }))
    .slice(0, limit);
}

// Convenience: is the symbol called anywhere outside its own file? A quick
// "is this dead code or reachable" signal for ranking/triage.
export function isCalledElsewhere(target, symbol, defFile, opts = {}) {
  return crossFileCallers(target, symbol, opts).some((c) => c.filePath !== defFile);
}

// ---- forward direction (the keystone for interprocedural taint) -------------
//
// crossFileCallers answers "who calls X" (backward). To follow tainted data FROM
// a source you need the other half: "what does this function call, and where are
// those callees defined" (forward). That's crossFileCallees. Like its sibling it
// is a textual REACHABILITY HINT — it tells an agent which files to open next to
// keep tracing a flow; the agent reads each callee to confirm the data actually
// propagates. Together they let a deep-hunt / verify agent walk a source→sink
// path across files without a full CodeQL/Joern CPG.

// Identifiers that are immediately followed by "(" but are language keywords, not
// calls (`if (`, `for (`, `return (`, …). Filtered out of the callee set.
const CALL_STOPWORDS = new Set([
  "if", "for", "while", "switch", "catch", "return", "sizeof", "typeof", "new",
  "delete", "throw", "await", "do", "else", "function", "def", "fn", "func", "sub",
  "class", "struct", "interface", "trait", "impl", "enum", "case", "with", "in",
  "is", "and", "or", "not", "super", "self", "this", "match", "when", "unless",
  "go", "defer", "using", "lambda", "yield", "assert", "print"
]);

// Identifiers immediately followed by "(" — call expressions. Captures both plain
// `foo(` and method `obj.method(` (the captured name is the method). Best-effort
// textual scan, not a parser.
function callNamesIn(text) {
  const names = [];
  const re = /(?:\.|[^\w.$]|^)\s*([A-Za-z_]\w*)\s*\(/g;
  let m;
  while ((m = re.exec(text)) !== null) names.push(m[1]);
  return names;
}

// Best-effort function name from an enclosing-excerpt's header lines (used to drop
// self-recursion from the callee set; null is acceptable).
const NAME_PATTERNS = [
  /\b(?:function|func|fn|sub)\s+([A-Za-z_]\w*)/,
  /\bdef\s+([A-Za-z_]\w*)/,
  /\b(?:class|struct|interface|trait|enum)\s+([A-Za-z_]\w*)/,
  /\b([A-Za-z_]\w*)\s*[:=]\s*(?:async\s*)?(?:function\b|\()/,
  /^[\w:<>*&\s]*?\b([A-Za-z_]\w*)\s*\([^;]*$/
];
function functionNameOf(lines) {
  for (const { text } of lines.slice(0, 3)) {
    for (const re of NAME_PATTERNS) {
      const m = re.exec(text);
      if (m?.[1] && !CALL_STOPWORDS.has(m[1])) return m[1];
    }
  }
  return null;
}

// Resolve a symbol's definition site(s) repo-wide (textual hint). Covers keyword
// defs (function/def/func/fn/class), assigned-function / arrow forms, and C-family
// `return-type NAME(...)` headers — while excluding prototypes / calls (lines
// ending in ";") as best a regex can. Returns [{ filePath, line, text }].
export function resolveDefinition(target, name, { scopeDir = ".", limit = 5 } = {}) {
  if (!name || String(name).length < 2) return [];
  const n = escapeRe(name);
  const patterns = [
    `\\b(function|func|fn|sub)\\s+${n}\\b`,
    `\\bdef\\s+${n}\\b`,
    `\\b(class|struct|interface|trait|enum)\\s+${n}\\b`,
    `\\b${n}\\s*[:=]\\s*(async\\s+)?(function\\b|\\()`,
    `^[\\w:<>\\*&\\s]+\\b${n}\\s*\\([^;]*$`
  ];
  const args = ["--json", "-n", "--max-count", "10"];
  for (const p of patterns) args.push("-e", p);
  args.push(...buildGlobs(), scopeDir === "." ? "." : scopeDir);
  const r = runRg(target, args);
  if (!r.ok) return [];
  return parseJsonMatches(r.stdout, 200)
    .map((h) => ({ filePath: norm(h.filePath), line: h.line, text: (h.text ?? "").trim() }))
    // The C-family `return-type NAME(...)` pattern has no `;` to anchor on in
    // semicolon-less languages (Python/Ruby), so a call like `return store(data)`
    // can masquerade as a def header. A line whose FIRST token is a control
    // keyword never starts a definition — drop those (keeps `def`/`function`/
    // `int foo(` headers, which don't begin with a control keyword).
    .filter((d) => !CONTROL_FIRST.test(d.text))
    .slice(0, limit);
}

// Control-flow keywords that can lead a line that textually resembles a C def
// (`return foo(x)`) but never actually defines one.
const CONTROL_FIRST = /^(return|if|elif|else|for|while|do|switch|case|throw|raise|await|yield|except|with|assert|print|del|break|continue|goto|when|unless|and|or|not|in|is)\b/;

// The enclosing FUNCTION around file:line — distinct from enclosingExcerpt, which
// returns the nearest *block* (an `if`/`for` body is too narrow to capture every
// call the function makes). We walk up PAST control headers to the real function
// header, then brace-balance (C-family) / dedent-scan (Python/Ruby). Returns
// { filePath, startLine, endLine, name, text, lines } or null.
const BRACE_EXT = new Set([".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".m", ".mm", ".java", ".kt", ".kts", ".scala", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs", ".php", ".swift", ".cs"]);
const INDENT_EXT = new Set([".py", ".rb"]);
const MAX_FN_SPAN = 400;
// A function/method header: a def keyword, an arrow, or a `) {` close-params-then-brace.
const FUNC_HEADER = /\b(function|func|fn|sub)\b|\bdef\s+[A-Za-z_]|\)\s*=>\s*\{?\s*$|\)\s*\{\s*$/;
// A control-flow header (possibly after a `}`) that resembles `) {` but isn't a function.
const CONTROL_HEADER = /^\s*\}?\s*(else\s+if|if|for|while|switch|try|catch|else|do|case|when|unless|elif|except|with|finally|return)\b/;
const PY_DEF = /^\s*(async\s+)?(def|class)\s/;

function extOf(filePath) {
  const i = filePath.lastIndexOf(".");
  return i === -1 ? "" : filePath.slice(i).toLowerCase();
}

function funcBraceSpan(lines, anchor) {
  let headerIdx = -1;
  for (let i = anchor; i >= 0 && anchor - i <= MAX_FN_SPAN; i -= 1) {
    if (CONTROL_HEADER.test(lines[i])) continue;          // step over the inner if/for/catch
    if (FUNC_HEADER.test(lines[i]) && lines.slice(i, anchor + 1).join("\n").includes("{")) { headerIdx = i; break; }
  }
  if (headerIdx === -1) return null;
  let depth = 0, started = false, endIdx = -1;
  for (let i = headerIdx; i < lines.length && i - headerIdx <= MAX_FN_SPAN; i += 1) {
    for (const ch of lines[i]) { if (ch === "{") { depth += 1; started = true; } else if (ch === "}") depth -= 1; }
    if (started && depth <= 0) { endIdx = i; break; }
  }
  if (endIdx === -1 || endIdx < anchor) return null;
  return [headerIdx, endIdx];
}

function funcIndentSpan(lines, anchor) {
  const indentOf = (s) => (s.match(/^[ \t]*/)?.[0].length ?? 0);
  let headerIdx = -1;
  for (let i = anchor; i >= 0 && anchor - i <= MAX_FN_SPAN; i -= 1) {
    if (PY_DEF.test(lines[i])) { headerIdx = i; break; }
  }
  if (headerIdx === -1) return null;
  const hi = indentOf(lines[headerIdx]);
  let endIdx = headerIdx;
  for (let i = headerIdx + 1; i < lines.length && i - headerIdx <= MAX_FN_SPAN; i += 1) {
    if (lines[i].trim() === "") { endIdx = i; continue; }
    if (indentOf(lines[i]) <= hi) break;
    endIdx = i;
  }
  return [headerIdx, endIdx];
}

export function enclosingFunction(target, filePath, line) {
  const path = resolvePath(target, filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return null;
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchor0 = Math.max(0, Math.min(lines.length - 1, Number(line ?? 1) - 1));
  const ext = extOf(filePath);

  let span = null;
  if (BRACE_EXT.has(ext)) span = funcBraceSpan(lines, anchor0);
  else if (INDENT_EXT.has(ext)) span = funcIndentSpan(lines, anchor0);

  if (!span) {
    // Unsupported language or no function header found — degrade to the nearest
    // block (enclosingExcerpt) rather than fail, so the agent still gets context.
    const ex = enclosingExcerpt(target, filePath, line);
    if (!ex || !ex.length) return null;
    return { filePath: norm(filePath), startLine: ex[0].line, endLine: ex[ex.length - 1].line, name: functionNameOf(ex), text: ex.map((l) => l.text).join("\n"), lines: ex };
  }
  const [s0, e0] = span;
  const body = [];
  for (let i = s0; i <= e0; i += 1) body.push({ line: i + 1, text: lines[i] });
  return { filePath: norm(filePath), startLine: s0 + 1, endLine: e0 + 1, name: functionNameOf(body), text: body.map((l) => l.text).join("\n"), lines: body };
}

// Forward call-graph step: the callees of the function enclosing file:line, each
// with its resolved definition site(s). Returns { function, callees:[{ name,
// callLines, defs:[{filePath,line,text}] }] }. resolveDefs:false skips the
// (rg-backed) definition lookup when only the callee names are wanted.
export function crossFileCallees(target, { filePath, line, scopeDir = ".", limit = 40, resolveDefs = true } = {}) {
  const fn = enclosingFunction(target, filePath, line);
  if (!fn) return { function: null, callees: [] };
  const seen = new Map();
  for (const { line: ln, text } of fn.lines) {
    for (const name of callNamesIn(text)) {
      if (CALL_STOPWORDS.has(name) || name === fn.name) continue;
      if (!seen.has(name)) seen.set(name, { name, callLines: [] });
      const e = seen.get(name);
      if (!e.callLines.includes(ln)) e.callLines.push(ln);
    }
  }
  const callees = [...seen.values()].slice(0, limit);
  if (resolveDefs) for (const c of callees) c.defs = resolveDefinition(target, c.name, { scopeDir });
  // Strip the bulky `lines` from the returned function record (callers that want
  // the body call enclosingFunction directly).
  const { lines: _omit, ...fnSummary } = fn;
  return { function: fnSummary, callees };
}
