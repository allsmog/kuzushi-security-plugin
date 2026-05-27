---
name: taint-analysis
description: IRIS-style source→sink taint hunt. Ranks a typed CWE catalog for the repo, then drives subagents to label dangerous sinks, label sources of user input, run Joern/CodeQL dataflow queries (or same-file linking) to connect them, and triage each flow as finding/candidate/rejected. Promotes verdicts into .kuzushi/findings.json. Benefits from a prebuilt CodeQL DB / Joern CPG but degrades gracefully.
user-invocable: true
---

# Taint analysis (coordinator)

Run a whole-repo source→sink taint hunt. You are the **coordinator**: you run the deterministic
prepare step, then spawn the phase subagents and thread their staged JSON drafts together. The
subagents do the LLM labeling and triage; you sequence them and report. Run these steps in order.

## 1. Prepare (deterministic)

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/taint-analysis-prepare.mjs" --target "<repo root>"
```

Parse the JSON envelope. Keep `prepPath`, `sinksDraftPath`, `sourcesDraftPath`, `flowsDraftPath`,
`findingsDraftPath`, `backends`, and `assembleCommand`. Relay any `warnings` to the user (e.g.
no context run, no CodeQL DB / Joern CPG → flow tracing will use tree-sitter + same-file linking).

## 2. Label sinks and sources — IN PARALLEL

In a **single message**, spawn two subagents (one Task call each, so they run concurrently):

- **`taint-sink-labeler`** — prompt: the target directory, the `prepPath`, and "write your sink
  specs to `<sinksDraftPath>`".
- **`taint-source-labeler`** — prompt: the target directory, the `prepPath`, and "write your
  source specs to `<sourcesDraftPath>`".

Wait for both to finish.

## 3. Trace flows

Spawn **`taint-flow-tracer`** with: the target directory, the `prepPath`, the `sinksDraftPath`,
the `sourcesDraftPath`, and "write your flows to `<flowsDraftPath>`". It uses
`backends` from prep to decide whether to run `joern:query` / `codeql:query` against prebuilt
databases or fall back to same-file structural linking.

## 4. Triage

Spawn **`taint-triager`** with: the target directory, the `prepPath`, the `sinksDraftPath`,
`sourcesDraftPath`, `flowsDraftPath`, "write your verdicts to `<findingsDraftPath>`", and the
`assembleCommand` to run when done. The triager assigns finding/candidate/rejected verdicts and
runs the assemble command, which validates them, enforces `minEvidenceLevel`, writes
`.kuzushi/taint-analysis.json`, and promotes verdicts into `.kuzushi/findings.json`.

If the triager did not run the assemble command, run it yourself:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/taint-analysis-assemble.mjs" --target "<repo root>" --run-dir "<runDir>"
```

## 5. Report

Summarize the run: ranked CWEs considered, sinks/sources labeled, flows by evidence level
(`path` / `linked` / `candidate`) and backend used, and the triage verdict counts. List the
`finding`s (CWE, source→sink, the guard gap) and note anything the evidence gate downgraded.
Point the user at `.kuzushi/taint-analysis.json` and the open findings in `.kuzushi/findings.json`.

## When NOT to use

- For native / memory-safety bugs (OOB, UAF, deserialization, JNI) — use `/systems-hunt`.
- When you already have a specific threat list to attack adversarially — `/threat-hunt` is more
  targeted; this is the broad source→sink sweep.
- To confirm a single known finding — that's `/verify`; to find its siblings, `/variant-hunt`.

## Rationalizations to Reject

- *"Source and sink share a CWE, so it's a flow."* → Co-occurrence is `candidate` evidence only;
  the triager must see a real (`linked`/`path`) data path before calling it a `finding`.
- *"A sanitizer is called nearby, so it's safe."* → Confirm the sanitizer is applied to the
  tainted value, in the right context, before the sink — not just present in the file.
- *"No CodeQL/Joern DB, so I can't trace."* → Fall back to same-file structural linking and report
  the lower evidence level; don't drop the flow.
