---
name: sweep
description: Whole-repo orchestrator. Shards the repository and fans the discovery producers (taint, authz, logic-hunt, crypto, sharp-edges, systems-hunt, iac, supply-chain, threat-hunt, binary-recon) out across every shard in parallel, then pipelines each new finding through /verify. The systematic-coverage answer to "scan the whole codebase" — local, auditable, fingerprint-deduped.
context: fork
agent: sweep-coordinator
user-invocable: true
---

# Sweep

Run a whole-repo, parallel security sweep. This is kuzushi's answer to cloud
scanners that "spin up thousands of agents over your repo" — except it runs
locally, every verdict is evidence-anchored and deterministically validated, and
nothing leaves the machine.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/sweep-prepare.mjs" --target "<repo root>"`.
   For an air-gapped run that skips any producer that may touch the network, add
   `--input '{"offline":true}'`. To restrict the producer set, pass
   `--input '{"producers":["authz","logic-hunt","taint-analysis"]}'`.
2. Read the `planPath` (`.kuzushi/sweep-plan.json`). It contains `shards` (the repo
   split by top-level module, budget-sized) and `jobs` (one per shard×producer, or
   one per repo-wide producer). Each job carries its exact `prepareCommand`, the
   `agent` to run it, and a budget-scaled `maxCandidates`.
3. **Fan the jobs out in parallel batches** (respect a sane concurrency cap, e.g.
   8–12 at once). For each job: run its `prepareCommand`, then spawn the named
   producer `agent` pointed at the prep's `prepPath` to do that producer's normal
   reasoning and write its draft, then run the prep's `assembleCommand` (finalize).
   The finalizes promote into `.kuzushi/findings.json` — that index is guarded by a
   lock, so concurrent finalizes are safe and dedupe by fingerprint.
4. **Pipeline, don't barrier.** A job's finding should flow to `/verify` as soon as
   that producer finalizes — don't wait for the whole fan-out to finish before
   verifying. Each finding is independently verified before you present it. For
   `deep-scan` leads specifically — they were not gated by a deterministic pattern, so
   they carry more false-positive risk — run `/verify` in **panel mode**
   (`--input '{"panel":3}'`): three independent verifiers, majority vote, a concrete
   trigger required to confirm. A wrong deep-read hypothesis gets refuted here instead
   of reaching the user.
5. Optionally write a per-job run report to the run dir as `draft.sweep.json`
   (`{ jobs: [{ jobId, producer, status, candidateCount }] }`) so the summary
   records what actually ran.
6. Run the `finalizeCommand` (`sweep-finalize`). It writes `.kuzushi/sweep.json`
   and `.kuzushi/coverage-map.json` (which shards were covered, and the **uncovered
   set** — the recall backstop).
7. Report: coverage %, the uncovered shards (if any), the new `exploitable`/`open`
   findings by source, and which survived `/verify`.

## When NOT to use

- For a small, targeted change or a single known file — run the specific producer
  (`/authz`, `/logic-hunt`, `/diff-review`) directly; sweeping is wasteful.
- As a substitute for `/threat-model` reasoning — sweep is breadth-first coverage,
  not a system-understanding pass. Run `/deep-context` / `/threat-model` first for a
  model the threat-hunt job can consume; without one, the threat-hunt job is skipped.
- To re-confirm an already-open finding — that's `/verify` / `/poc`.

## Rationalizations to Reject

- *"The threat model already covers the risky parts, so a full sweep is redundant."*
  → Threat models miss surfaces nobody named. Sweep is the systematic backstop that
  visits **every** shard; the coverage map proves what was and wasn't reached.
- *"Most shards are boring; I'll just sweep the ones that look interesting."* →
  That reintroduces the sub-sampling gap sweep exists to close. If you must scope,
  pass an explicit `producers`/shard subset and say so — never silently drop shards.
- *"All jobs finished, so the repo is fully covered."* → Coverage = files a producer
  actually examined. Read `coverage-map.json`; if `uncoveredFileCount > 0`, say so
  and offer a follow-up sweep over the uncovered shards.
- *"Parallel finalizes might clobber findings.json, so run everything serially."* →
  The index is lock-guarded and fingerprint-deduped; fan out the reasoning, and the
  finalizes serialize themselves. Don't trade the whole speed win away on a fear the
  architecture already handles.
