---
name: code-graph
description: Build a cached code-graph (.kuzushi/code-graph.json) — entry points + per-symbol caller counts (blast-radius / attack-surface signal) — so producers like /diff-review query it instead of re-deriving caller info live. Deterministic ripgrep heuristic; no heavy tooling required. Re-run after large code changes.
allowed-tools: Bash
---

# Code graph

Build (or refresh) the persistent code-graph for this repository.

Run, using the project working directory as `<repo>`:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/code-graph-build.mjs" --target "<repo>"
```

It writes `.kuzushi/code-graph.json` (`{ entryPoints[], symbols:[{name,file,line,callerCount}], … }`,
symbols ranked by `callerCount` — the blast-radius signal) and prints a summary (definition count,
top symbols, whether a Joern CPG is present for a higher-fidelity upgrade). Relay the summary.

Consumers read the artifact when present: `/diff-review` uses each changed symbol's `callerCount`
for a deterministic blast radius (instead of live caller counting), and the hunters may consult it
for reachability. It's a heuristic (ripgrep call-site tally), so re-run it after big changes; build a
Joern CPG via `/build-databases` if you want exact interprocedural edges later.

## When NOT to use

- As a vulnerability finder — it's a structural index, not a hunter; it makes no security judgments.
- On a repo you haven't changed since the last build — the cached artifact is still valid; only
  re-run after meaningful code changes.

## Rationalizations to Reject

- *"The caller count is exact."* → It's a ripgrep heuristic (call-site tally), not a true call graph;
  treat it as a blast-radius *signal*, and prefer a Joern-backed upgrade for precision.
- *"No graph, so skip blast radius."* → Without the cached graph, `/diff-review` still falls back to
  live caller counting — the graph just makes it cheaper and repo-wide.
