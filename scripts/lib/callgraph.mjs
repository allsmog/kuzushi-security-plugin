// Cheap cross-file reachability. The tree-sitter MCP `callers` tool is single-file,
// and a full CodeQL/Joern CPG is heavy and not always built — so a deep-scan or
// verify agent reasoning about "is this function reachable from an entry point?"
// has, by default, no way to follow a call across files. This is the lightweight
// bridge: a ripgrep-backed repo-wide call-site finder. It is a REACHABILITY HINT,
// not sound dataflow — it finds textual call sites of a symbol so the agent knows
// which files to open next. The agent still confirms the actual flow.

import { runRg, parseJsonMatches, buildGlobs } from "./ripgrep.mjs";

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

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
