---
name: partition
description: Split the attack surface into parallel-discovery partitions so fan-out hunters explore different subsystems instead of converging on the same shallow bug. Deterministic grouping of /x-ray entry points by component → .kuzushi/partitions.json, which a hunt coordinator hands to one subagent per partition. Run /x-ray first.
context: inline
user-invocable: true
---

# Partition

Discovery parallelizes well, but naive fan-out makes agents **converge on the same shallow
bugs**. The fix (from Anthropic's defending-code harness) is a first pass that *partitions the
search space* by subsystem, then gives each partition its own discovery agent. `/partition` does
that grouping deterministically so parallel hunters cover **different** components.

## Run it

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/partition.mjs" --target "<repo root>"` — reads the entry
points `/x-ray` mapped (`.kuzushi/x-ray/entry-points.json`), groups them by subsystem into
non-overlapping partitions (cap 6 by default; the long tail merges into `other`), and writes
`.kuzushi/partitions.json`. If it errors "run /x-ray first", do that — the partition is only as
good as the mapped attack surface.

## Fan out the hunt

Each partition has `{ id, label, focusHint, attackSurface: [entry points] }`. A coordinator
(`/threat-hunt`, `/taint-analysis`) spawns **one hunter subagent per partition in parallel**, each
scoped to its partition's `attackSurface` and told (via `focusHint`) to stay in that subsystem.
This both speeds discovery and **raises recall** — agents aren't racing to the same easy finding,
so the long tail of per-subsystem bugs gets attention. Promote findings into the shared index as
usual; the fingerprint dedupes anything two partitions both surface at a boundary.

## When NOT to use

- Before `/x-ray` — there's no mapped attack surface to split; partitioning an empty surface does
  nothing. Map first.
- On a tiny target (a handful of entry points in one component) — one partition is fine; fan-out
  overhead buys nothing.
- As a finder — `/partition` produces *no findings*; it only scopes where the hunters look.

## Rationalizations to Reject

- *"More parallel agents = more bugs, just scale it."* → Without partitioning they converge on the
  same shallow findings; the partition is what makes parallelism pay off. Scale *across* partitions,
  not redundantly within one.
- *"One giant component holds everything, so one partition is fine."* → If a component dominates,
  that's a signal to split it finer (by boundary kind or sub-path), not to hunt it as one blob —
  the long tail hides there. Re-run with a higher `maxPartitions` or sub-scope by hand.
- *"Partitions overlap, so I'll dedupe later."* → They're non-overlapping by construction (each
  entry point lands in one partition); if you hand a subagent more than its `attackSurface`, you've
  reintroduced the convergence the partition exists to prevent.
