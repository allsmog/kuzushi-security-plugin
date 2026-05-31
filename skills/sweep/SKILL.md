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
   `--input '{"offline":true}'`; for the whole-file deep reader add `'{"deep":true}'`;
   to restrict the set, `'{"producers":["authz","logic-hunt","taint-analysis"]}'`.
2. Read the `planPath` (`.kuzushi/sweep-plan.json`). The plan has **already decided
   applicability**: `producerSet`/`jobs` are the producers that apply to THIS repo, and
   `skipped[]` lists the rest with reasons (e.g. `systems-hunt: no native code`,
   `threat-hunt: no threat model`, `binary-recon: no binaries`, `supply-chain: offline`,
   `sast: semgrep not installed`). Each job carries its `prepareCommand`, `agent`, and a
   budget-scaled cap.
3. **Get the user's permission before fanning out — this is the gate, never skip it.**
   A sweep spawns many parallel agents and costs real tokens, so present the plan and
   ask: the **applicable** producers it will run (with the per-shard job count), the
   ones it's **skipping and why**, whether **deep** mode is on, and a rough sense of
   scale/cost. Let the user approve, narrow the set, or toggle deep. Only proceed on a
   clear yes. (Surface this as a native Yes/No / AskUserQuestion — don't just start.)
4. **On approval, fan the jobs out in parallel batches** (concurrency cap ~8–12). For
   each job: run its `prepareCommand`, spawn the named producer `agent` on the prep's
   `prepPath` to write its draft, then run the prep's `assembleCommand` (finalize).
   **Run every job in the approved plan — do not silently drop a producer**; the
   finalizes promote into the lock-guarded `.kuzushi/findings.json` (dedup by fingerprint).
5. **Pipeline, don't barrier.** A job's finding should flow to `/verify` as soon as
   that producer finalizes — don't wait for the whole fan-out to finish before
   verifying. Each finding is independently verified before you present it. For
   `deep-scan` leads specifically — they were not gated by a deterministic pattern, so
   they carry more false-positive risk — run `/verify` in **panel mode**
   (`--input '{"panel":3}'`): three independent verifiers, majority vote, a concrete
   trigger required to confirm. A wrong deep-read hypothesis gets refuted here instead
   of reaching the user.
6. Optionally write a per-job run report to the run dir as `draft.sweep.json`
   (`{ jobs: [{ jobId, producer, status, candidateCount }] }`) so the summary
   records what actually ran.
7. Run the `finalizeCommand` (`sweep-finalize`). It writes `.kuzushi/sweep.json`
   and `.kuzushi/coverage-map.json` (which shards were covered, and the **uncovered
   set** — the recall backstop).
8. Report: coverage %, the uncovered shards (if any), the new `exploitable`/`open`
   findings by source, and which survived `/verify`.

## Checkpointing (resume a large sweep)

A whole-repo sweep fans many jobs out and costs real tokens — don't restart it from zero after
an interruption. As each job finalizes, record it:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/lib/checkpoint.mjs" shard "<runDir>/sweep-state" <jobId> --root "<repo root>" --from <chunk.json>
```

On a resumed sweep, `checkpoint.mjs load "<runDir>/sweep-state"` returns `shards_done`; **re-spawn
only the jobs not in that list** (the finalizes are fingerprint-deduped, so a re-run is safe but
wasteful). Trust `shards_done`, not a glob of the run dir — stale drafts from a prior attempt may
linger. The writes are atomic and path-confined to the repo.

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
