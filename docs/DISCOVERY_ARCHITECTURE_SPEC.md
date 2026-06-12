# Discovery Architecture Spec

Status: implementation spec for the discovery engine.

Scope: authorized defensive source-code security review inside Claude Code. This document covers architecture, evaluation, sandboxing, and measurement. It does not define offensive operations, live-target exploitation, stealth, persistence, or weaponization.

## 1. Goals

Kuzushi's verifier and proof ladder are already the strongest part of the system: agents draft, deterministic scripts validate, findings are fingerprinted, severity is derived in code, memory findings are routed to execution proof, and false proofs are release blockers.

The discovery goal is to raise blind recall without weakening that contract.

- Separate **routing misses** from **reasoning misses** in every eval. A routing miss means the vulnerable file/function never reached the agent. A reasoning miss means the code was in context and the agent still missed the bug.
- Make no-signal code reachable through obligation routing, scoped dataflow, and coverage-guided execution instead of only file-rank heuristics.
- Keep every candidate auditable: promoted findings go through the proof ladder; dropped candidates carry a taxonomy rule or refute reason.
- Preserve local-first trust boundaries: artifacts stay under `.kuzushi/`, locked profiles deny network by default, and runtime/plugin code never shells out to hidden model subprocesses.

Non-goals:

- Do not raise recall by counting unverified candidates as findings.
- Do not replace deterministic assemble/finalize checks with prompt instructions.
- Do not build a whole-repo CPG platform when scoped, on-demand slices are enough.
- Do not use blind LLM mutation as a fuzzing substitute; execution discovery requires coverage or sanitizer feedback.

## 2. Architecture

Discovery remains a deterministic `prepare -> agent -> assemble` pipeline. The change is that prepare now produces explicit discovery context and an obligation ledger, and eval measures which lane failed.

```
repo
  -> prepare
       -> ranked files
       -> obligation ledger
       -> scoped CPG leads
       -> execution-discovery recon
  -> discovery lanes
       -> Lane A: obligation routing
       -> Lane B: scoped CPG/dataflow
       -> Lane C: class-specialized reasoning
       -> Lane D: coverage-guided sanitizer discovery
  -> candidates/findings
  -> verify/poc/sanitize-pov/fuzz
  -> report/SARIF/fix
```

## 3. Discovery Lanes

### Lane A: Obligation Routing

`deep-scan-prepare` enumerates dangerous sites and writes:

- `.kuzushi/obligation-ledger.json`
- `.kuzushi/obligations.jsonl`

Each record has a terminal routing state such as `routed` or `deferred`, so the engine cannot silently drop long-tail work. The normal file budget remains intact; the obligation overlay is additive and covers sub-budget files.

### Lane B: Scoped CPG/Dataflow

Scoped CPG leads stay bounded to memory-relevant subsystems and are treated as leads, not automatic findings. They are useful when a bug requires a source-to-sink path or cross-function lifetime reasoning that a single-file read misses.

### Lane C: Class-Specialized Reasoning

Class agents must follow the repo authoring standard in `CLAUDE.md`: `When NOT to use`, `Rationalizations to Reject`, worked examples, derived-severity inputs, and the non-finding taxonomy. The key rule is that a guard is not proof of safety until the agent has checked whether the guard actually dominates the dangerous path.

### Lane D: Coverage-Guided Sanitizer Discovery

The execution lane is for memory/integer/lifetime classes where static routing or reading is weak. It executes only in a sandboxed local context, with no live-target interaction and no outbound network. A finding is promoted only when finalize replays the artifact and parses sanitizer evidence.

## 4. Artifact Contracts

Core discovery artifacts:

- `.kuzushi/obligation-ledger.json`: summary plus records for routed/deferred dangerous sites.
- `.kuzushi/obligations.jsonl`: append-friendly line format for the same ledger.
- `.kuzushi/slices/<run>-obligation-slices.json`: function-scoped excerpts for
  obligation, overlay, and CPG-lead discharge.
- `.kuzushi/dropped-candidates.jsonl`: shared proof-or-drop ledger for malformed,
  refuted, or non-promoted candidates.
- `.kuzushi/runs/<run>/prep.json`: lane-specific prepare context.
- `.kuzushi/findings.json`: validated, fingerprinted findings index.
- `.kuzushi/fuzz-discover.json` and `.kuzushi/fuzz/found-crashes.jsonl`: execution-discovery results.

Draft findings remain advisory. Finalize scripts own:

- schema validation
- verdict whitelists
- dedup/fingerprinting
- severity derivation
- proof-state transition
- dropped-candidate accounting

## 5. Runtime Boundary

Runtime/plugin code must not call hidden `claude -p`, `spawn("claude")`, or similar subprocess model paths. That boundary is enforced by `test/no-runtime-claude-cli.test.mjs`.

The eval harness may call Claude CLI externally because it is not the shipped runtime path. Its job is to measure real agents in fresh blind sessions.

## 6. Evaluation

`eval/eval.mjs` now reports the discovery split directly:

- **Routing recall**: vulnerable location reached prepare context.
- **Reasoning recall given context**: found bugs divided by in-context runs.
- **Site-context recall**: an obligation, overlay item, CPG lead, or anchor reached
  the vulnerable site, not merely its file.
- **Site-context reasoning recall**: found bugs divided by site-context runs.
- **End-to-end blind recall**: found bugs over all runs.
- **Confirmed on target**: verifier-confirmed target hits.
- **Proven on target**: sanitizer/PoC-proven target hits.
- **False-proof rate**: accepted proofs that land on safe decoys divided by accepted
  proofs. The release target is zero.
- **Extra-confirmed / extra-proven per case**: precision pressure.
- **Cost per true finding**: total billed cost divided by target hits.

The Markdown scoreboard is paired with `eval/scoreboard*.json` using `schemaVersion: "eval-scoreboard.v2"` so future gates can consume stable metrics.

`npm run eval:gate -- --scoreboard <path> ...` evaluates those JSON metrics against
explicit thresholds. The gate is deterministic and never runs agents; the billed eval
stays manual.

Hard gates:

- False-proof rate remains zero.
- No obligation is silently dropped; every ledger item has a terminal state.
- Dynamic proof must replay deterministically before promotion.
- Recall gains that come from extra noise are not progress.

## 7. Implementation Phases

Phase 0: Measurement split.

- Add routing vs reasoning metrics to eval.
- Add site-context metrics so "read the file" cannot masquerade as "routed the site."
- Emit JSON scoreboards.
- Acceptance: eval output distinguishes routing recall, reasoning recall, and blind recall.

Phase 1: Obligation ledger.

- Promote prepare-time obligations into `.kuzushi/obligation-ledger.json` and `.kuzushi/obligations.jsonl`.
- Acceptance: `deep-scan-prepare` writes the artifacts and tests prove terminal states.

Phase 2: Scoped slices and class lanes.

- Feed class-specialized agents with scoped CPG/dataflow context.
- Emit function-scoped obligation slices from prepare.
- Acceptance: each class lane has authoring-standard sections and tests for draft
  contracts; prepare writes slices for every routed obligation/lead.

Phase 3: Execution discovery.

- Make coverage-guided sanitizer discovery the primary memory-class no-signal lane.
- Acceptance: at least one no-signal ground-truth bug is proven by replayable sanitizer evidence.

Phase 4: Corpus and gates.

- Grow to at least 20 held-out real CVE cases across memory, web, and logic classes.
- Acceptance: report blind find-rate, proven-on-target, false-proof rate, extra-confirmed per case, and cost per true finding for every release.

## 8. False Wins To Reject

- A routing rank improvement without a downstream find.
- A candidate count increase without proof.
- A fuzz lane without coverage or sanitizer feedback.
- A single blended recall number that hides the miss mode.
- A green eval that skipped no-signal cases.
- A bigger model run presented as architecture progress when `reasoning recall given context` did not move.
