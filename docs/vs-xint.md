# kuzushi vs. Xint Code (and cloud LLM-SAST in general)

[Xint Code](https://xint.io/products/xint-code) (Theori) is an LLM-native **cloud**
SAST: connect a repo, it spins up many parallel agents, analyzes millions of LOC +
config + binaries, verifies exploitability before reporting, and is strong on
business-logic flaws. It has a serious pedigree (ZeroDay Cloud wins, top-3 at DARPA
AIxCC, DEF CON CTF titles, named 0days in Redis/PostgreSQL/MariaDB).

This doc is an honest comparison — where kuzushi wins by construction, where Xint is
ahead, and what kuzushi added to close the gap.

## The structural difference

The defining property of Xint Code is that it is **a cloud service you upload your
source to**. kuzushi is **a local Claude Code plugin** — code never leaves the
machine, and every verdict is produced by a deterministic `prepare → agent →
finalize` pipeline whose validation (closed verdict sets, evidence anchors,
fingerprinting) lives in scripts that can't be reasoned around.

| Dimension | Xint Code | kuzushi |
|---|---|---|
| **Where your code goes** | Uploaded to the vendor cloud (`code.xint.io`) | Stays local; `/sweep --input '{"offline":true}'` skips every network producer |
| **Auditability** | Black-box report | Deterministic finalize scripts; closed verdict sets; file:line + fingerprints; provenance digests on every artifact |
| **Remediation** | Reports the bug | Closes the loop: `/verify` → `/poc` (sandboxed) → `/fix` (PoC⁺-revalidated patch behind explicit approval) |
| **Cost** | Enterprise pricing | One Claude Code session |
| **Dev workflow** | Portal / CI | In-editor; `/diff-review` per PR; SARIF 2.1.0 export |
| **Extensibility** | Closed | Open MIT; add a producer = one `prepare`/`finalize` pair + an agent |

## Where Xint was ahead — and what kuzushi added

1. **Scale / "thousands of parallel agents over the whole repo."**
   kuzushi ran producers one-at-a-time on threat-model hotspots. Added **`/sweep`**:
   shards the repo by module and fans **every** applicable producer across **every**
   shard in parallel, deduping into one fingerprinted, **lock-guarded** index so the
   parallel finalizes can't lose-update. It's honest about the number — Claude Code
   subagent fan-out is tens, not thousands — so the claim is *systematic coverage +
   verified findings*, not raw agent count.

2. **Whole-repo recall.** The old per-producer caps (threat-hunt 12, authz 30,
   taint 80 files) silently sub-sampled large repos. `/sweep` uses **budget-scaled
   caps per shard** and writes a **`coverage-map.json`** that records the *uncovered
   set* — so "we scanned everything" is a number you can check, not a claim.

3. **Business-logic depth.** Added **`/logic-hunt`**: idempotency / TOCTOU /
   transaction-atomicity / price-quantity / state-machine abuse — the class
   pattern-based taint analysis can't see.

4. **Binaries.** Added **`/binary-recon`**: read-only ELF/PE/Mach-O triage
   (dangerous imports, RWX segments) tied back to source. Assessment-grade and
   deliberately not an exploitation tool — see [HARDENING.md](HARDENING.md).

5. **Raw bug-finding power — the recall *ceiling*.** Coverage isn't recall: every
   producer was **pattern-gated** (it only ever looked at lines a regex matched), so a
   bug no pattern names was invisible regardless of model quality. Xint's edge is
   "reads every line in context." Four changes attack that ceiling:
   - **`/deep-scan`** — a whole-file reader that finds bugs by *reading* risk-ranked
     files, not grepping. On the benchmark's `hidden-tenant` case (a tokenless logic
     bug) the pattern lanes score **0%** and deep-scan **100%** — the exact gap.
   - **Full-function context** — producers now hand the agent the *enclosing function*
     (was ±10 lines), so a guard in a wrapper above the sink is visible.
   - **Cross-file reachability** — `scripts/cmd/callers.mjs` resolves a function's call
     sites repo-wide (tree-sitter callers is single-file); `/sweep --deep` also
     auto-builds CodeQL/Joern when present for true interprocedural flow.
   - **Adversarial verify panel** — `/verify --input '{"panel":3}'` runs N independent
     verifiers (distinct lenses, majority vote, trigger required to confirm), so the
     extra recall isn't buried in false positives.

## What the real LLM-in-the-loop eval actually showed (the honest scoreboard)

We built `eval/` — a harness that runs the **real agents** (`deep-scanner`, `verifier`)
in fresh `claude -p` sessions and scores them **blind** against fix-derived CVE ground
truth (`npm run eval:cve`). This is itself a differentiator: kuzushi *measures* its own
find-rate instead of asserting "low false positives." It is also brutally clarifying.

Blind, real agents, 3 real CVEs (minimist proto-pollution, Redis Lua-RCE, Redis XACKDEL):

| Lever tried | routed | found | confirmed |
|---|---|---|---|
| Sonnet, 30-file pass | 67% | **33%** | 33% |
| Opus, 30-file pass | 100% | **33%** | 33% |
| Sonnet, focused single file | 100% | XACKDEL **found 2/2**; Lua-UAF **0** | — |

What this taught us, and where it leaves the Xint comparison:
- **Routing is solved** (reachability + entry-point + input-processor ranking → 100%).
- **Model tier is not the lever** — Opus didn't beat Sonnet on find-rate.
- **Depth/focus is the lever** — one file read deeply finds a bug 30-files-shallow
  misses. But focus costs ~$2/file, so whole-repo depth = the AIxCC cost tradeoff.
- **The subtle class is still beyond us blind** — the Redis Lua **GC use-after-free**
  was missed even focused on the right file *with* a `gc-rooting` obligation pointing at
  it. That is exactly the bug class Xint/Theori catch — and the reason is instructive
  (next point).

## The empirical engine — now built (`/sanitize-pov`)

The eval's clearest lesson was that static LLM reading misses subtle memory bugs, and the
fix is the AIxCC core: **prove by execution under sanitizers, not by reading.** That is
now in kuzushi as **`/sanitize-pov`**: for a memory-class finding it compiles a harness
that drives the bug **with AddressSanitizer/UBSan** and runs it in the `--network none`
sandbox; a sanitizer abort is ground-truth proof and `scripts/lib/sanitizers.mjs` maps the
error class to the exact CWE (stack-buffer-overflow→CWE-121, heap-use-after-free→CWE-416,
…). The verdict is the sanitizer report, not an LLM — a clean run is `not-reproduced`, a
build failure is `harness-failed-build`, never a false proof. It's wired into the `/verify`
CONFIRM routing for native/memory findings (consented, since it executes).

This directly attacks the class that beat the reader: ASan catches a use-after-free or a
buffer overflow at *runtime* regardless of how subtle it looks in source.

**Why this is the right answer to the routing wall.** The eval showed (with numbers) that
blind *static* routing can't reliably reach a bug site that has no cheap signal — e.g.
`deps/lua/src/lbaselib.c` scores **0** in the risk ranker (no entry-defs, no code-graph
reach, no keyword), so it's never read. Execution doesn't care about ranking: you run the
trigger and the sanitizer reports the bug wherever it lives. That is the routing-independent
property a local tool needs to compensate for not having cloud read-everything throughput.

**Validated end-to-end on a real CVE.** Built real Redis at the vulnerable commit with its
own `make SANITIZER=address`, started the ASan server, and sent `XACKDEL … IDS 9 …` (>the
8-slot static buffer). AddressSanitizer aborted with `stack-buffer-overflow`, backtrace
`#1 xackdelCommand` — **CVE-2025-62507**. kuzushi's oracle parsed it (→ CWE-121) and
`/sanitize-pov` promoted the finding to `proven`, sharpening the CWE from a seeded vague
`CWE-119` to the sanitizer's exact `CWE-121`. The same bug the *static reader missed at
breadth* is **proven by execution** — build-to-proof in one consented run, ~10 min /
~½ GB transient. This is the gap-closer working on a real 0day-class memory bug, not a
fixture.

**Second real CVE, a harder class — and an oracle gap it exposed (now fixed).**
`bench/cves/redis-cve-2025-46817/repro.sh` builds Redis at the vulnerable SHA with UBSan and
fires the real trigger `EVAL "return {unpack({1,2,3}, -2, 2147483647)}"`. `luaB_unpack`
computes `n = e - i + 1` in signed `int`; the range overflows it, and at `-O2` the compiler
treats the signed overflow as UB and **elides the dependent `n <= 0` guard**, so the push
loop writes far past a corrupted-size Lua stack — a wild OOB write. Because the bad write
lands in unmapped memory *past every redzone*, the sanitizer can't print a tidy
`heap-buffer-overflow`; it traps the signal and prints `DEADLYSIGNAL` + `BUS on unknown
address` + `caused by a WRITE memory access`. kuzushi's oracle **used to parse that to
`null`** — i.e. `/sanitize-pov` would have silently missed a real CVE. Fixed: the oracle now
classifies a sanitizer-caught deadly signal, using the access-type hint to land
`oob-write → CWE-787` (the symptom of the `CWE-190` root cause), with the crash frame
(`lua_rawgeti`) recovered from the symbol when the optimized binary carries no source line
(`scripts/lib/sanitizers.mjs`; regression-tested against the captured report in
`test/sanitizers.test.mjs`). This is the empirical engine generalizing past the first case —
a *dependency*, an *integer-overflow* class, a *script-driven* trigger — and the harness
catching its own blind spot before it shipped.

## Where Xint is still ahead (no spin)

- **Empirical at scale.** `/sanitize-pov` proves *one finding* on consent; Xint/Theori run
  **coverage-guided fuzzing campaigns** (many inputs, corpus/frontier management) as the
  primary *discovery* engine. kuzushi's `/fuzz` is the seed of that but not a cluster
  campaign. The honest gap now: we can *prove* a memory finding by execution, but
  *discovering* the unknown ones still leans on the (weaker) static reader rather than a
  fuzzing fleet. (Discovery now also has a sanitizer path: `/fuzz` builds C/C++ targets with
  ASan and `fuzz-triage` classifies crashes by the same oracle — but it's laptop-scale, not
  a coverage-guided cluster campaign.) We tried to close the *coverage-guided* half with an
  engine **ladder** — local libFuzzer → libFuzzer in a `kuzushi-fuzz` Docker image →
  portable ASan dumb-fuzz — and report the result honestly: the bundled `ubuntu-clang-14`
  image **links and runs** libFuzzer but coverage feedback did not engage (`cov:1`, the gate
  unbeaten) on trivial harnesses in testing, so the ladder treats it as *experimental* and
  the dependable floor remains the dumb-fuzzer **seeded** from `/path-solve` and `/verify`
  payloads (proven in `test/fuzz-driver.test.mjs`: a gate-clearing seed finds a deep-gated
  overflow the unseeded run misses at the same budget). Real coverage-guidance needs a
  matched LLVM; that's wiring + a working image, not a solved capability.
- **Raw throughput** on millions of LOC — a cluster beats a laptop session on wall-clock,
  and depth-at-breadth (focus every file) costs real money locally.
- **Deep binary analysis** — Xint treats binaries as first-class; `/binary-recon` is
  triage and `/mem-exploitability` is assessment, not decompilation.

**Honest bottom line:** kuzushi's measured blind find-rate is ~33% on this small CVE set
(routing solved, reasoning the wall on subtle memory bugs). It is **not** at Xint parity
on raw discovery, and we can now say that with a reproducible number instead of a vibe.
The credible path to closing it is *not* "bigger model" — it's borrowing AIxCC's
empirical core: drive the bundled MCP/concolic/sanitizer/fuzz tooling to **prove bugs by
running them**, and reserve the LLM for triage and the human-readable writeup. Until that
lands, the docs say *closing*, not *closed*.

## When to pick which

- **Pick kuzushi** when the code can't leave your environment (regulated / IP-
  sensitive), when you need an auditable evidence trail and a closed
  verify→prove→fix loop, or when you want security review inside the editor at the
  cost of a Claude Code session.
- **Pick a cloud cluster** when you need one-shot throughput over a very large
  codebase and uploading the source is acceptable.

They're complementary: run `/sweep` locally for the auditable, fix-it-now loop;
reach for cloud throughput when scale is the binding constraint.
