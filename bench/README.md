# Kuzushi Bench

Two benchmarks live here:

- **`npm run bench:smoke`** — the temp-repo smoke fixture (asserts the proof ladder).
- **`npm run bench`** — the **recall benchmark** below, which measures how much more of
  a repo `/sweep` reaches than a single producer. This is what makes
  "better than a hotspot scanner" a number you can re-run.

Future fixtures should be self-contained, network-free, and assert the proof ladder
rather than only scanner output.

---

## Recall benchmark (`npm run bench`)

It turns "kuzushi finds more, with whole-repo coverage" into a number. It is
intentionally **engine- and LLM-free** so it runs in CI on a stock runner.

### What it measures: candidate recall

Every producer's `*-prepare.mjs` is a deterministic pattern scanner. A vulnerability
that no producer ever surfaces as a **candidate** can never be reported downstream —
so *candidate recall* (did some producer route itself to the known-vulnerable site?)
is a sound, reproducible **precursor** to end-to-end recall, and it isolates exactly
the gap `/sweep` was built to close: whole-repo coverage vs. hotspot sub-sampling.

For each case it computes recall in **three lanes** and reports the lift:

- **baseline** — a single producer (`taint-analysis`) run once over the whole repo
  with default caps ("what a typical one-tool pass sees").
- **pattern /sweep** — the full plan: every applicable *pattern* producer × every
  shard, budget-scaled.
- **deep /sweep** — the same plan with `{deep:true}`, which adds the whole-file
  reader `/deep-scan`. Its lift over `pattern` is the recall on bugs **no regex
  matches** (custom wrappers, plain-logic flaws) — the case `hidden-tenant` is the
  canonical one: a tokenless logic bug that pattern producers never route to and the
  deep reader does.

A site counts as recalled if any producer's `prep.json` surfaces its file (and, when
the candidate carries a line, within ±6 lines). Note this is **file-routing recall**:
it proves attention reached the right file. The deeper, reasoning-level recall (does
the agent actually call the bug) needs an LLM and is the manual / CVE path below.
`npm run bench` **fails** if overall deep recall drops below 80%, or if deep ever
scores worse than pattern on a case. Results land in `scoreboard.md`.

### Real-CVE lane (`npm run bench:cve`)

The credible "strong raw bug-finding" evidence runs the same three lanes against **real
projects cloned at a known-vulnerable commit**. Cases live in `bench/cves/<id>/` as a
`fetch.sh` (clones/downloads on demand — nothing third-party is committed) plus an
`expected.json`. With nothing fetched, `bench:cve` prints the fetch commands and
exits; fetch one and re-run. Shipped: `minimist-CVE-2020-7598` (prototype pollution).
Add more by dropping in a `fetch.sh` + `expected.json`.

> Honesty: until a real-CVE case is fetched and the deep lane surfaces + (manually)
> the panel verifies the bug, kuzushi's docs say it is *closing* the raw-power gap,
> not that it has closed it.

### What it does NOT measure (and why)

It does not run the producer **agents** (which need an LLM) or `/verify`/`/poc`, so it
doesn't measure precision or end-to-end true-positive rate. Those are the **manual**
path: run `/sweep` locally on a case repo, let the agents reason and verify, then diff
`.kuzushi/findings.json` against `expected.json`. Candidate recall is the CI-able floor
beneath that.

### Cases

Each `cases/<name>/` has a `repo/` (the source under test) and an `expected.json`:

```json
{ "expected": [ { "filePath": "api/orders.py", "line": 5, "cwe": "CWE-639", "note": "…" } ] }
```

Shipped cases (small, synthetic, MIT — extend freely):

| Case | Bug | Exercises |
|---|---|---|
| `idor-py` | object fetched by user-supplied id, no ownership check | authz / taint routing |
| `logic-idempotency` | replayable, non-atomic checkout | logic-hunt routing |
| `native-strcpy` | unbounded `strcpy` into a fixed buffer | systems-hunt routing (taint alone misses) |
| `novel-wrapper-sqli` | SQLi via a custom `dao.run()` helper | wrapper bug no standard sink names |
| `crossfile-taint` | XSS sink reached from another file | cross-file flow |
| `hidden-tenant` | broken tenant isolation in a plain helper | **deep-only** — no pattern routes here; the deep reader's headline win |

### Adding a case

1. `mkdir -p cases/<name>/repo` and drop in the vulnerable source (+ some clean files
   so recall isn't trivially 100%).
2. Write `cases/<name>/expected.json` with the true-positive anchors.
3. `npm run bench` — your case is picked up automatically.

For a stronger claim, add cases that clone real projects at a pinned vulnerable commit
(e.g. a CVE fix's parent) with `expected.json` pointing at the patched file:line — keep
them as fetch-on-demand scripts rather than committing large trees. The OWASP Benchmark
(Java) and CWE micro-suites slot in the same way: one `repo/` + one `expected.json`.
