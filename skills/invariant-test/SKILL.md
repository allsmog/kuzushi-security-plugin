---
name: invariant-test
description: Verify the CVE-derived invariants in .kuzushi/threat-intel.json against the code, using the tree-sitter taint MCP tools (and codeql/joern if available). Writes .kuzushi/invariant-results.json with hold / violated / needs-review verdicts. Requires /threat-intel to have run first.
context: fork
agent: invariant-tester
user-invocable: true
---

# Invariant test

Check this repo's CVE-derived invariants against the code.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/invariant-prepare.mjs" --target "<repo root>"`.
   If it reports no `threat-intel.json`, tell the user to run `/threat-intel` first and stop.
2. For each invariant in the worklist, open its candidate files and use the tree-sitter taint
   tools (`tree_sitter:taint_sources` / `taint_sinks` / `query` / `callers`; and
   `codeql:query` / `joern:query` only if a DB/CPG already exists) to decide
   `hold` / `violated` / `needs-review` with file:line evidence for the source, sink, and the
   guard (or its absence).
3. Write the results stage file and run the `assembleCommand` to persist
   `.kuzushi/invariant-results.json`.
4. Report the verdict counts and list the violated invariants (id, CWE, source→sink evidence).
