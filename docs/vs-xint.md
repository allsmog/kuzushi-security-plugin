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

## Where Xint is still ahead (no spin)

- **Raw throughput** on millions of LOC in a single run — a cloud cluster beats a
  local session on wall-clock for very large targets.
- **Track record** — published 0days and competition wins. kuzushi's claim is
  measured by its own benchmark (see [`../bench/README.md`](../bench/README.md)), not
  by trophies.
- **Deep binary analysis** — Xint analyzes binaries as first-class targets;
  `/binary-recon` is triage, and `/mem-exploitability` is assessment, not full
  decompilation.

## When to pick which

- **Pick kuzushi** when the code can't leave your environment (regulated / IP-
  sensitive), when you need an auditable evidence trail and a closed
  verify→prove→fix loop, or when you want security review inside the editor at the
  cost of a Claude Code session.
- **Pick a cloud cluster** when you need one-shot throughput over a very large
  codebase and uploading the source is acceptable.

They're complementary: run `/sweep` locally for the auditable, fix-it-now loop;
reach for cloud throughput when scale is the binding constraint.
