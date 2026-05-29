---
name: path-solve
description: Concolic-lite path-constraint solving for hard-to-reach sinks. For findings /verify left inconclusive, the path-solver agent extracts the guard predicate between source and sink and solves it into a concrete reaching input — via the concolic MCP backend (Z3 / CrossHair) when installed, else by reasoning (LLM). Attaches a pathSolution block; feeds /verify and /fuzz. Heuristic, not a proof.
context: fork
agent: path-solver
user-invocable: false
---

# Path solve

Get past the guards that left a sink unreachable.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/path-solve-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"fingerprints":["<fp>"]}'` to target specific findings). If it reports
   `no-candidates`, tell the user to run `/verify` first (it surfaces the `inconclusive` findings
   worth solving) and stop.
2. Read the prep's `prepPath`. For **each** candidate, extract the path predicate between the source
   and sink (`tree_sitter:node_at` parent chain + `tree_sitter:query` for branch conditions across
   the functions on the path, using `graphContext`), then solve it: `concolic:z3_solve` for
   numeric/string predicates, `concolic:crosshair` for Python, else reason the input out (LLM).
   Decide `reachable` + a concrete `solvedInput`, or list the blocking guard in `unsolvedGuards`.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the `assembleCommand`
   — it validates and attaches a `pathSolution` block onto each finding (no verdict change).
4. Report, per finding: guards extracted, backend used, reachable?, the solved input (or blocking
   guard). Note `/verify` can turn a reachable solution into a confirmed trigger and `/fuzz` can seed
   the corpus from it.

## When NOT to use

- Before `/verify` has produced `inconclusive` / needs-trace findings (nothing hard-to-reach) — unless
  you pass explicit `fingerprints`.
- To render the exploitability verdict — that's `/verify`; this produces reach *evidence*.
- For reachability that needs real symbolic execution of allocator/heap state — out of scope; this
  solves *input* predicates only.

## Rationalizations to Reject

- *"An input was found, so it's exploitable."* → That's `reachable` evidence at the stated confidence,
  not a proof; `/verify` + `/poc` adjudicate. Don't inflate confidence.
- *"That guard looks hard — unreachable."* → Try Z3/CrossHair and a concrete assignment first; only
  `reachable:false` when a guard is genuinely unsatisfiable, and name it.
- *"Skip the predicate, just guess a payload."* → The path predicate *is* the deliverable; a bare
  guess is what `/verify` already couldn't produce.
