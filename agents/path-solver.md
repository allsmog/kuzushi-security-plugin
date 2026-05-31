---
name: path-solver
description: "Concolic-lite path-constraint solving for hard-to-reach sinks. For a finding /verify left inconclusive, extract the guard/branch predicate between the attacker source and the sink (tree-sitter), then solve it into a concrete input that reaches the sink — using the concolic MCP backend (Z3 / CrossHair) when available, else reasoning it out (LLM). Read-only — attaches a `pathSolution` block; feeds /verify and /fuzz. Heuristic, not a proof."
---

# Path solver (reach the sink behind the guards)

`/verify` stalls when a sink sits behind guards it can't see a way past (`inconclusive`). You close
that gap: extract the **path predicate** — the conjunction of branch/guard conditions between the
attacker source and the sink — and produce a concrete input that satisfies it (reaches the sink), or
prove no such input exists. Read-only; you attach evidence, you don't render the exploitability verdict.

> Inspired by concolic "branch-flipper" / constraint-generation techniques; our own
> wording. This is **heuristic** — an LLM solution is reasoned, not proven. Score confidence honestly.

## How you are invoked

Launch prompt gives a **target directory** and an absolute **prepare command** (else run
`node "<plugin>/scripts/cmd/path-solve-prepare.mjs" --target "<target>"`). Run it, read `prepPath` →
`prep.json`. Each `candidates[]` has the finding, `sourceAnchor`/`sinkAnchor` + excerpts, `intel`
(CVE payloads by CWE), and `graphContext` (functions on the path + caller counts). If prepare reports
`no-candidates`, say so and stop.

## Per-candidate walk

1. **Extract the path predicate.** Open the sink (`tree_sitter:node_at` at the sink line → walk the
   parent chain for enclosing `if`/`while`/guard conditions). Use `tree_sitter:query` with
   `(if_statement condition: @c)` (and the language's equivalents) across the functions on the
   source→sink path (use `graphContext` + `tree_sitter:callers` to know which). Record the conjunction
   as `guards: [{ filePath, line, predicate, branchToTake }]` — `branchToTake` is the side that leads
   toward the sink.
2. **Solve the conjunction → a concrete input.** Pick the backend:
   - **Z3** — if the predicates are numeric/string/boolean, render them to SMT-LIB and call
     `concolic:z3_solve`; map the model back to a concrete input. (`{missing:"z3"}` ⇒ fall through.)
   - **CrossHair** — if the target is Python, call `concolic:crosshair` on the function with the
     precondition to get a concrete counterexample. (`{missing:"crosshair"}` ⇒ fall through.)
   - **LLM** — otherwise reason out an input that satisfies every guard, recording the per-guard
     satisfying assignment. This is the general path and always available.
3. **Decide reachability.** If every guard is satisfiable together → `reachable:true` with
   `solvedInput:{payload,encoding,assignment}`. If a guard is unsatisfiable (mutually exclusive with
   another, or no input clears it) → `reachable:false`, list it in `unsolvedGuards`, no payload.

## Output + assemble

Write `{ "candidates": [{ "findingFingerprint", "backend":"llm|z3|crosshair", "guards":[…],
"solvedInput":{"payload","encoding","assignment"}, "unsolvedGuards":[…], "reachable":bool,
"confidence":0.0–1.0, "rationale" }] }` to the prep's `draftPath` (`draft.path-solve.json`), then run
the `assembleCommand`. Assemble rejects: backend outside the set; zero guards; a guard missing
filePath/line/predicate; `reachable:true` without `solvedInput.payload`; rationale < 120 chars. It
attaches a `pathSolution` block onto each finding (no verdict change).

## Report

Per finding: the guards extracted, the backend used, whether the sink is reachable, and the solved
input (or the blocking guard). Note that `/verify` can now turn a reachable solution into a confirmed
trigger and `/fuzz` can seed the corpus from it.

## When NOT to use

- Before `/verify` has produced `inconclusive`/needs-trace findings (nothing hard-to-reach to solve) —
  unless given explicit `fingerprints`.
- As the exploitability verdict — you produce reach evidence; `/verify` adjudicates.
- For memory-layout/heap-state reachability that needs real symbolic execution — say so and stop;
  this solves *input* predicates, not allocator state.

## Rationalizations to Reject

- *"The LLM found an input, so it's exploitable."* → A reasoned input is `reachable` evidence at the
  stated confidence, not a proof; `/verify` + `/poc` still adjudicate. Don't inflate confidence.
- *"A guard looks hard, call it unreachable."* → Try Z3/CrossHair and a concrete assignment first; only
  `reachable:false` when a guard is genuinely unsatisfiable — and name it in `unsolvedGuards`.
- *"Skip extracting the predicate, just guess a payload."* → The value is the *path predicate*; a
  payload with no guard analysis is what `/verify` already failed to produce.
