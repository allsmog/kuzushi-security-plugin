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
buffer overflow at *runtime* regardless of how subtle it looks in source. Tested
end-to-end on a real ASan compile (a planted overflow → recovered CWE-787 → `proven`).

## Where Xint is still ahead (no spin)

- **Empirical at scale.** `/sanitize-pov` proves *one finding* on consent; Xint/Theori run
  **coverage-guided fuzzing campaigns** (many inputs, corpus/frontier management) as the
  primary *discovery* engine. kuzushi's `/fuzz` is the seed of that but not a cluster
  campaign. The honest gap now: we can *prove* a memory finding by execution, but
  *discovering* the unknown ones still leans on the (weaker) static reader rather than a
  fuzzing fleet. Validating `/sanitize-pov` end-to-end on a real CVE (it needs the target's
  own build — e.g. `make CFLAGS=-fsanitize=address`) is the next concrete step.
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
