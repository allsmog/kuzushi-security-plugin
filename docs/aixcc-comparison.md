# kuzushi vs. the AIxCC top-3 Cyber Reasoning Systems

A reference comparison between kuzushi and the three winning Cyber Reasoning Systems (CRSs) from
DARPA's **AI Cyber Challenge (AIxCC)** finals (DEF CON 33, Aug 2025). All three are open-sourced;
shallow clones live in `~/vibe-code/aixcc-winners/` (`atlantis`, `buttercup`, `theori`).

| Rank | Team | System | Repo | Clone size (shallow) |
|---|---|---|---|---|
| 🥇 1st ($4M) | Team Atlanta | **Atlantis** | `Team-Atlanta/aixcc-afc-atlantis` | ~4.5 GB |
| 🥈 2nd ($3M) | Trail of Bits | **Buttercup** | `trailofbits/buttercup` | ~15 MB |
| 🥉 3rd ($1.5M) | Theori | **Robo Duck** | `theori-io/aixcc-afc-archive` | ~87 MB |

> The point of comparison: these are **fully-autonomous, cluster-scale** find-*and*-patch systems
> built for a competition harness (OSS-Fuzz, C/Java). kuzushi is a **human-gated, laptop-scale,
> white-box static-first** Claude Code plugin. They sit at opposite ends of the same problem space,
> and the CRSs surface concrete ideas kuzushi can borrow.

---

## The three CRSs

### 🥇 Atlantis (Team Atlanta) — multi-engine ensemble
The largest and most sophisticated. An **ensemble of specialized sub-CRSs** orchestrated together
(`example-crs-webservice/`): `crs-multilang`, `crs-java`, `crs-p3`, `crs-patch`, `crs-sarif`,
`crs-userspace`. The `crs-multilang` engine alone combines **coverage-guided fuzzing + concolic
execution (SymCC) + Joern static analysis + LSP + a function tracer + grammar/dictionary/blob/
constraint generators + a "reverser."** It wins by throwing *many* complementary techniques at each
target and merging results, with a dedicated patcher and SARIF emitter. K8s-deployed.

### 🥈 Buttercup (Trail of Bits) — clean 5-service pipeline
Five components: **Orchestrator → Seed Generator → Fuzzer (OSS-Fuzz) → Program Model → Patcher**.
The fuzzer runs an AI/ML-assisted OSS-Fuzz campaign; the **multi-agent patcher** (has an explicit
state machine) repairs and validates fixes. Python, Docker/Kubernetes, SigNoz tracing, LiteLLM/
LangFuse across OpenAI+Anthropic+Google. Notably ships a **laptop-runnable** local mode and a web
UI — the most "productizable" of the three (≈8 cores / 16 GB / 100 GB to run locally). C + Java,
OSS-Fuzz-compatible targets.

### 🥉 Robo Duck (Theori) — agent pipeline with static + coverage
A dataflow pipeline (from `docs/crs-architecture.md`): **build → fuzz → LLM crash triage**, in
parallel with **static analysis via Meta's Infer + LLM repo analysis → VulnReport → score → agent
analysis → LLM dedup → produce PoV → generate patch → bundle (PoV+Patch+SARIF)**. Distinctive bits:
a **coverage DB + "fuzz frontier"** computation and an **agentic branch-flipper** (concolic-lite, an
LLM nudges the fuzzer past hard branches). Rust+Python, docker-compose. Tuned for a *huge* LLM budget
("can spend $1,000+ in under an hour").

### What all three share (the CRS archetype)
1. **Autonomous, end-to-end loop**: ingest task → build → fuzz → triage → dedup → prove (PoV) →
   patch → validate → submit. No human in the loop.
2. **Fuzzing is the primary discovery engine**, anchored on **OSS-Fuzz** harnesses (the competition
   gave each target a build + harnesses).
3. **Hybrid**: fuzzing + static analysis (Infer/Joern/CodeQL) + sometimes concolic/symbolic (SymCC),
   with **LLM agents for triage, dedup, and patching**.
4. **Cluster-scale + expensive**: Kubernetes, many workers, four-figure-per-hour LLM spend.
5. **C/Java focus** (the OSS-Fuzz ecosystem), patch generation as a first-class deliverable.

---

## Side-by-side vs. kuzushi

| Dimension | AIxCC CRSs (Atlantis / Buttercup / Robo Duck) | kuzushi |
|---|---|---|
| **Autonomy** | Fully autonomous; ingest→submit with no human | Human-gated; each skill is user-invoked, heavy/outbound steps ask first |
| **Form factor** | Cluster (K8s/Docker), 8+ cores, web UI/API | A Claude Code plugin; runs in the editor session, no server |
| **Discovery-first** | **Dynamic-first** (fuzzing campaign) | **Static-first** (threat-model → taint/hunt/sast → verify) |
| **Fuzzing** | Coverage-guided campaigns on OSS-Fuzz, corpus/frontier mgmt, concolic (Atlantis) | `/fuzz`: single sandboxed harness per finding (Docker `--network none`), no cluster/corpus-frontier |
| **Static analysis** | Infer (Theori), Joern (Atlantis), CodeQL | tree-sitter + CodeQL + Joern + semgrep, via self-gating MCP servers |
| **Targets** | OSS-Fuzz-compatible C/Java repos w/ existing harnesses | **Any source on disk**, multi-language; no harness prerequisite |
| **LLM orchestration** | Multi-agent micro-services (LiteLLM/LangFuse), big budgets | Claude Code skills + subagents, deterministic `prepare → agent → assemble` |
| **Patching** | First-class autonomous patcher (multi-agent, validated) | `/fix`: PoC⁺-validated patch, **applied only behind explicit approval** |
| **Output** | PoV + Patch + SARIF bundle submitted to a competition API | `findings.json` (accretes verification/poc/fix/exploitability) + `/export-sarif` |
| **Auditability** | Run logs, traces (SigNoz/LangFuse) | Deterministic assemble scripts, closed verdict sets, file:line evidence, fingerprints |
| **Cost** | $100s–$1000s/hr | One Claude Code session |
| **Provenance/trust** | Competition-scoped | Trust-plane (policy/provenance), guardrail hooks, untrusted-repo posture |

**The essential difference:** a CRS is a *robot* that autonomously finds and fixes bugs in a known
target shape at cluster scale; kuzushi is an *analyst's instrument* that an engineer drives over
arbitrary source, trading autonomy and fuzzing horsepower for breadth, interactivity, auditability,
and near-zero footprint. They're complementary, not competing — kuzushi is closest in spirit to
**Buttercup's laptop mode** (unsurprisingly: kuzushi already borrows from Trail of Bits' skills).

---

## What kuzushi can borrow (mapped to existing skills)

1. **OSS-Fuzz harness reuse → `/fuzz` / `fuzz-harness-author`.** All three lean on *existing*
   OSS-Fuzz harnesses instead of writing from scratch. `fuzz-harness-author` should **detect and
   reuse an in-repo OSS-Fuzz/`fuzz_targets`/`*_fuzzer` harness** when present, and only author one
   when absent — cheaper and higher-fidelity.

2. **Coverage frontier + branch-flipping (Theori) → smarter `/fuzz` seeding.** Theori computes a
   "fuzz frontier" and uses an agent to get past hard branches. `fuzz-harness-author`'s corpus
   seeding could target the specific guarded branch in the finding's excerpt (an LLM-derived seed
   that satisfies the precondition), rather than generic seeds.

3. **Buttercup's Program Model service → a persistent code-graph.** Buttercup keeps a standing
   semantic model of the program; Atlantis uses Joern + LSP + a function tracer. This is exactly the
   deferred **trailmark/code-graph** roadmap item — a cached call-graph/attack-surface artifact that
   `/threat-hunt`, `/taint-analysis`, and `/diff-review` (blast radius) all query instead of
   re-deriving.

4. **Multi-agent patcher state machine (Buttercup) → harden `/fix`.** Buttercup's patcher is a
   validated state machine (generate → build → test → re-fuzz the patched binary). `/fix` already
   does PoC⁺ validation; borrow the **"re-run the PoC/fuzzer against the patched code to confirm the
   crash is gone *and* nothing regressed"** loop more explicitly.

5. **Infer as another static backend (Theori) → an MCP wrapper.** Theori pairs Infer (interprocedural
   memory/null/leak analysis) with LLM analysis. kuzushi could add an `infer` MCP server alongside
   codeql/joern/semgrep for C/C++/Java memory bugs feeding `/systems-hunt`.

6. **Ensemble + dedup (Atlantis / Theori) → formalize the merge.** Atlantis merges many engines;
   Theori does **LLM-based vuln dedup** before patching. kuzushi already funnels many producers into
   one `findings.json`; adding an explicit **cross-producer dedup pass** (beyond fingerprinting —
   semantic "same root cause") would mirror this and feed `/chain`.

7. **Concolic/constraint generation (Atlantis SymCC) → a future depth upgrade.** The biggest gap:
   none of kuzushi's analysis solves path constraints. A long-horizon idea — a concolic-assisted
   trigger generator for `/verify`/`/fuzz` on hard-to-reach sinks (heavy; roadmap-tier).

### Where kuzushi already aligns
- Static analysis stack (CodeQL/Joern/semgrep) overlaps Atlantis/Theori.
- Sandboxed empirical proof (`/poc`, `/fuzz` with `--network none`) mirrors the CRS "produce a PoV"
  step, minus the cluster.
- SARIF output (`/export-sarif`) matches the CRSs' SARIF bundling.
- `/fix` ↔ the CRS patchers; `/chain` ↔ their vuln correlation/dedup.

---

## Takeaway

The CRSs validate kuzushi's direction — hybrid static+dynamic, LLM-driven, evidence-bundling — while
showing the two levers kuzushi deliberately trades away: **autonomy** and **fuzzing horsepower at
scale**. The highest-value, in-character borrows are the cheap ones: **reuse existing OSS-Fuzz
harnesses**, **seed `/fuzz` at the guarded branch**, a **persistent code-graph**, and a tighter
**patch-then-re-prove loop in `/fix`** — each an increment on a skill that already exists, not a pivot
to a cluster-scale robot.

*Sources: DARPA AIxCC results; the three repos' READMEs and architecture docs
(`buttercup/README.md`, `theori/docs/crs-architecture.md`, `atlantis/README.md` +
`example-crs-webservice/`).*
