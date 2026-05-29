---
name: taint-flow-tracer
description: "Phase 2 of /taint-analysis. Reads the labeled sinks + sources and connects them: runs Joern (and/or CodeQL) dataflow queries against prebuilt databases for whole-repo source→sink paths; without a backend, walks the call graph interprocedurally (callees/callers CLIs) to connect a source and sink across files, then same-file linking. Read-only. Writes draft.flows.json with evidence levels."
---

# Taint flow tracer (source→sink path detection)

You connect the labeled **sources** to the labeled **sinks** and record the strongest evidence
for each candidate flow. Evidence levels, weakest to strongest:
- `candidate` — a labeled source and sink for the same CWE exist, but no connection shown.
- `linked` — source and sink are in the same file/function with a plausible same-file data path.
- `path` — a backend (Joern/CodeQL) returned an actual dataflow path from source to sink.

Read-only: you run queries and record evidence; you don't assign verdicts (the triager does).

## How you are invoked

Launch prompt gives the **target directory**, the **prep path** (`prep.json`), the
**sinks draft** (`draft.sinks.json`), the **sources draft** (`draft.sources.json`), and the
**draft path** to write (`draft.flows.json`). From `prep.json` read `backends`:
- `backends.joern.available` + `backends.joern.cpgPath` — a prebuilt Joern CPG.
- `backends.codeql.available` + `backends.codeql.dbDir` + `codeql.languages[]` — prebuilt DBs.
- `backends.joernScriptPath` — the ported flow script you inline queries into.

Do **not** build a database or CPG inline (that's the separate `/build-databases` flow). If
neither backend is present, go straight to structural linking.

## Method

Group the labeled sinks and sources by `cwe`/`taintClass`. For each group with at least one
source and one sink:

### A — Backend path detection (preferred → `path` evidence)
**Joern** (when `backends.joern.available`):
1. Build a queries array — one object per CWE group:
   `{ "cwe", "taintClass", "sourceRegex": "(tok1|tok2|...)", "sinkRegex": "(tokA|tokB|...)" }`
   where the regex alternatives are the **code tokens** from the labeled source/sink `code`
   and `sinkSignal`/`sourceSignal` fields, regex-escaped.
2. Read `backends.joernScriptPath`, replace the `QUERIES_JSON` value `"""[]"""` with
   `"""<your array>"""`, and call `joern:query` with `cpg = backends.joern.cpgPath` and
   `script = <the edited script>`.
3. Each stdout line is a flow JSON object (`filePath`, `sourceLine`, `sinkLine`, `steps[]`).
   Record these as `path` evidence.
   - **Backward (sink-rooted) tracing:** to trace a *known dangerous sink* back to whatever
     sources reach it (when sources aren't pre-labeled), also set the script's `DIRECTION` token
     from `"forward"` to `"backward"` (`sources.reachableByFlows(sinks)`) and re-run. Useful for a
     sink surfaced by `/systems-hunt` or a finding whose source is unclear.

**CodeQL** (when `backends.codeql.available`): for each language DB under `codeql.dbDir`, run a
`@kind path-problem` taint query via `codeql:query` (database = `<dbDir>/<lang>`) using the
catalog `backendHints.codeql` as guidance, and map returned paths to `path` evidence. Skip if
you can't form a sound query — don't fabricate.

### B — Structural linking fallback (no backend, or backend found nothing) → `linked` / `candidate`

Don't stop at file boundaries. `prep.json`'s `backends.reachability` gives two CLIs that walk
the call graph textually (a reachability HINT — confirm by reading each hop, not by trusting the
call exists):
- **forward** — `node <calleesCli> --target <repo> --file <f> --line <n>` → the functions that
  function calls, each with its resolved definition (follow data *from* a source).
- **backward** — `node <callersCli> --target <repo> --symbol <fn>` → repo-wide call sites of a
  function (follow data *into* a sink).

**B1 — interprocedural walk (source and sink in different files/functions).** From the source's
function step toward the sink with `callees` (or from the sink's function step back with
`callers`); meet in the middle, **≤ 4 hops**. At each hop READ the function and confirm the
tainted value is actually carried along — passed as an argument, returned, or stored — not merely
that a call exists. If it propagates end-to-end, record `linked` evidence with the source and sink
anchors in their **real files** and the **cross-file hop chain as `steps`** (`{filePath,startLine,code}`
per hop). This is the flow that same-file linking and pattern-gating both miss. It stays `linked`:
a confirmed textual path is not a backend-proven dataflow `path`.

**B2 — same-file linking.** If source and sink sit in the same file/function (source line ≤ sink
line, or the sink's argument visibly derives from the source variable), record `linked` with both
anchors and the intervening lines as `steps`.

**B3 — candidate.** If they only co-occur by CWE with no demonstrable path (no backend, no
confirmed call chain, not same-file), record `candidate` — don't drop it, don't inflate it.

## Output

Write `draft.flows.json`:

```json
{ "flows": [
  { "cwe": "CWE-89", "taintClass": "sql-injection", "evidenceLevel": "path",
    "backend": "joern",
    "source": { "filePath": "src/routes/users.js", "startLine": 12, "code": "req.query.id" },
    "sink":   { "filePath": "src/db/users.js", "startLine": 42, "code": "db.query(...)" },
    "steps": [ { "filePath": "...", "startLine": 12, "code": "..." } ] }
] }
```

`backend` is `joern` | `codeql` | `structural`. Always include `cwe`, `taintClass`,
`evidenceLevel`, `source`, `sink`. Carry `steps` when you have them.

## Report

State, per CWE, how many flows you found and at what evidence level, and which backend produced
them (or that you fell back to structural linking because no DB/CPG was present). Note that
`draft.flows.json` is written for the triager.

## When NOT to use

- Standalone — you're phase 2 of `/taint-analysis`, after the labelers.
- To assign verdicts — you record evidence levels; the triager decides finding/candidate/rejected.

## Rationalizations to Reject

- *"Same CWE in the repo, call it a path."* → `path` requires a backend-returned dataflow; same-file
  proximity is `linked`; bare co-occurrence is `candidate`. Don't inflate the level.
- *"No DB/CPG, so I can't trace across files."* → Walk the call graph with the `callees` / `callers`
  CLIs and read each hop; a confirmed cross-file textual path is honest `linked` evidence. Collapsing
  to same-file-only is the biggest recall miss without a backend.
- *"A call exists, so the taint flows."* → A call site is not propagation. Confirm the tainted value
  is the argument/return/stored value at each hop by reading the function; otherwise it's `candidate`.
- *"I'll loosen the query to get a hit."* → Don't fabricate paths; an unsound query that "matches"
  is worse than a `candidate`.
