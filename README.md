# kuzushi-security-plugin

[![test](https://github.com/allsmog/kuzushi-security-plugin/actions/workflows/test.yml/badge.svg)](https://github.com/allsmog/kuzushi-security-plugin/actions/workflows/test.yml)

**A local-first vulnerability confirmation and remediation pipeline that lives inside Claude Code.**

Point it at source you already have checked out and kuzushi turns security review into a
reproducible evidence pipeline: map the code, threat-model it, hunt source-to-sink paths, verify
exploitability, build sandboxed proof, synthesize variant rules, and validate patches before they
touch your working tree.

kuzushi is built for maintainers and product-security teams who need answers they can ship:

- **Is it real?** Findings advance through explicit proof states instead of staying as scanner hits.
- **Can I reproduce it?** Verification, PoC, fuzz, rule-pack, and patch artifacts stay under
  `.kuzushi/` with provenance and policy digests.
- **Can I fix it safely?** `/fix` validates exploit regression, functional behavior, and supported
  semantic oracles in a sandbox copy before apply.
- **Can I trust the workflow?** The plugin is local-first, policy-gated, network-denied by default
  for locked profiles, and designed for auditable CI/SARIF output.

It is self-contained Node (no daemon, no hosted service): plain stdio MCP servers, skills, agents,
schemas, and a SessionStart hook wire up Tree-sitter, Semgrep, CodeQL, Joern, fuzz harnesses, and
language tooling only when the repo needs them.

```
context ─► x-ray ─► threat-model ─► threat-intel ─► ┌ invariant-test ┐ ─► findings.json ─► verify ─► poc ─► fix ─► report
 (langs,    (entry    (PASTA DFD +    (CVEs for       └ threat-hunt   ┘     (open          (exploit-  (sandbox- (PoC⁺   (fix-first
  deps)      points)   threats)        stack + peers)  (adversarial)         findings)      ability)    proven)   patch)  report)
                                                                                  │
                                                                                  └─► mem-exploitability
                                                                                      (memory-corruption tier
                                                                                       + mitigation posture)
```

Each step writes an artifact under `.kuzushi/` that the next step consumes. You stay in
control: heavy or outbound steps **ask first**, and everything runs against your local repo.

---

## Scope & boundaries

This is a **local source-code** tool with static-first analysis and sandboxed dynamic proof
for harnessable targets. How complete that is depends on what you point it at.

**Always in scope** (any target with source on disk): PASTA threat model, version-checked CVE
intel, source→sink taint analysis, adversarial guard-bypass review, static exploitability
verdicts, memory-corruption exploitability assessment, and a sandboxed PoC harness.

**Web apps / HTTP services** — the plugin covers the *static* half of a grey-box review. Pair
it with a dynamic tool (Burp / DAST) for the rest: browsing the live app, mapping observed
traffic (endpoints, parameters, cookies, roles) to handlers, and triggering against a running
target. None of that lives here.

**Libraries, native / systems code, parsers, CLIs** — there's no HTTP layer to proxy, so most
of that dynamic half simply doesn't apply. Source→sink plus the sandboxed `/poc` harness is
much of the standard workflow. The dynamic complement *here* is fuzzing: `/fuzz` creates a
campaign plan from confirmed/proven findings, executes runnable harnesses in the same offline
sandbox model, triages/minimizes crashes, and only advances findings when empirical crash or
sanitizer evidence exists.

**Across the board:** it loads source, it does not *recover* it (no decompilation / bytecode);
`/poc` proves the code in an isolated sandbox (`--network none`), not a deployed app. Findings are
triaged independently; `/chain` then reasons over them to surface multi-bug **attack chains** as an
analysis overlay (it does not auto-build a combined exploit — the chain is a documented composition).

---

## Install

**Via the plugin marketplace (recommended):**

```
/plugin marketplace add allsmog/kuzushi-security-plugin
/plugin install kuzushi-security-plugin@kuzushi-security
```

Then `npm install` once in the plugin directory (bundles the MCP SDK, tree-sitter grammars,
and the TypeScript/Python language servers).

**For local development:**

```bash
git clone https://github.com/allsmog/kuzushi-security-plugin
cd kuzushi-security-plugin && npm install
claude --plugin-dir .
```

> Requires **Node ≥ 20**. Some analysis backends need a system toolchain (see [Tooling](#tooling)).

---

## Quickstart

Start Claude Code in any source repo. The SessionStart hook **auto-builds repository
context** (files, languages, components), prints a status report, and suggests one next
step. You don't need to learn 40 commands — kuzushi is **four phases**, and most reviews
are two commands: **`/sweep` then `/report`**.

```
                           (→ = typeable in the / menu ·  + = runs inside the phase or when you ask)
1  MAP        understand the code           (x-ray runs automatically on session start)
   → /threat-model           PASTA threat model + ASCII data-flow diagram
   + deep-context · code-graph · dfd · threat-intel · invariant-test

2  HUNT       find vulnerabilities
   → /sweep                  whole-repo: fans the hunters out by language, then verifies
   + taint · authz · logic-hunt · crypto · sharp-edges · systems · iac
     supply-chain · sast · threat-hunt · binary-recon · traffic-map

3  CONFIRM    prove it's real
   → /verify                 reconstruct trigger → verdict; routes each finding to its proof
   → /poc                    build + sandbox-run one harness (executes; explicit)
   + fuzz · path-solve · mem-exploitability   (verify picks these by language / finding-type)

4  FIX · SHIP  remediate + deliver
   → /fix                    minimal patch, PoC⁺-validated, applied behind approval
   → /report                 prioritized "fix first" report (Markdown / HTML)
   + chain · variant-hunt · export-sarif · semgrep-rule · rule-synth

   entry: /diff-review (review a PR)     setup: /doctor (+ install · build-databases)
```

**Happy path:** `/sweep` finds and verifies across the whole repo, then `/report` gives
you a prioritized, shareable writeup. Only the `→` commands are in the `/` menu; the `+`
tools aren't separate commands — they run inside their phase (e.g. `/sweep` selects the
hunters by language) or when you ask for them in plain language. The full reference is the
table below.

---

## Skills

This is the **full reference** — every capability the plugin ships. Only **8 are in the `/`
menu** (the phase drivers + a couple of entry points): `/sweep`, `/verify`, `/poc`, `/fix`,
`/report`, `/threat-model`, `/diff-review`, `/doctor`. The rest are **not separate commands you
type** — they run *inside their phase* (e.g. `/sweep` fans out the hunters by language; `/verify`
routes a finding to `/fuzz` / `/mem-exploitability` / `/path-solve`) or when you **ask in plain
language** ("do an authz review", "draw the data-flow diagram"). They stay fully available —
just demoted from the menu so it reads as the four phases. (Mechanism: `user-invocable: false`
in each skill's frontmatter — hidden from `/`, still model-invocable.)

| Command | What it does | Writes |
|---|---|---|
| `/sweep` | **Whole-repo orchestrator.** Shards the repo by module (budget-sized) and fans every applicable producer (taint, authz, logic-hunt, crypto, sharp-edges, systems-hunt, iac, supply-chain, threat-hunt, binary-recon) out across **every** shard in parallel, then pipelines each new finding through `/verify`. Records a **coverage map** (which shards were reached + the uncovered set — no silent sub-sampling) and writes findings to the shared lock-guarded index. `--input '{"offline":true}'` skips any network producer (zero-exfil); `'{"deep":true}'` adds the whole-file reader and an interprocedural-DB plan. The local, auditable answer to cloud "scan-everything" tools. | `.kuzushi/sweep.json`, `coverage-map.json`, `findings.json` |
| `/deep-scan` | **Whole-file deep reader** — the recall lever that beats pattern-gating. Risk-ranks files (entry points, trust boundaries, blast radius, churn, security-relevant paths), then the deep-scanner agent **reads each in full** and reasons from first principles, finding the long tail (project-specific wrappers, plain-logic flaws, cross-file flows) that regex-based producers structurally miss. Token-expensive, budget-bounded, honest about the unread remainder. Leads flow to `/verify` (panel). | `.kuzushi/deep-scan.json`, `findings.json` |
| `/deep-hunt` | **Interprocedural hypothesis hunt** — the cross-file recall lever. Risk-ranks **trace anchors** (entry points + dangerous sinks), then the deep-hunter agent **walks each flow source→sink across files** (forward/backward call-graph CLIs) over multiple rounds: hypothesize → follow the data hop by hop, reading each function → defeat every guard → self-falsify. Promotes only confirmed cross-file flows (≥2 hops, ≥2 files), storing the path as the finding's `evidenceGraph`. Finds the multi-file bugs same-file taint and pattern-gating both miss — **no CPG required**. Token-expensive; run via `/sweep --deep`. Leads flow to `/verify` (panel). | `.kuzushi/deep-hunt.json`, `findings.json` |
| `/deep-context` | **Deep system-understanding pass** (before threat modeling). The context-analyst agent reads the code line-by-line where it matters and builds a grounded model — modules, entry points, actors, trust boundaries, data stores, and **system invariants** — with file:line evidence and anti-hallucination rules. **Context only** (no vuln-finding/fixes/severity); `/threat-model` consumes it. | `.kuzushi/deep-context.json` |
| `/threat-model` | Agent builds a **PASTA** threat model in phases (objectives → scope → decomposition → threats) + an ASCII data-flow diagram. | `.kuzushi/threat-model.json`, `threat-model-dfd.txt` |
| `/threat-intel` | Researches recent **critical/high CVEs** for the detected stack (version-checked) and **similar apps**, distilled into machine-checkable invariants. *(uses web search)* | `.kuzushi/threat-intel.json` |
| `/invariant-test` | Verifies each CVE-derived invariant against the code with tree-sitter taint queries (CodeQL/Joern if built). | `.kuzushi/invariant-results.json` |
| `/threat-hunt` | **Adversarial per-threat review** (the Carlini doctrine): state attacker capabilities → trace source→sink → bypass *every* guard → verdict from a closed set. Promotes verdicts to the findings index. | `.kuzushi/threat-hunt.json`, `findings.json` |
| `/systems-hunt` | **Native / memory-safety review.** Scans for systems patterns (loadLibrary/JNI, `memcpy`/`Unsafe`/`gets`, archive parsers, deserialization, exec), then a subagent confirms reachability + memory-safety impact (OOB, UAF, integer overflow, RCE). Best on C/C++/Rust/native; promotes to findings. | `.kuzushi/systems-hunt.json`, `findings.json` |
| `/taint-analysis` | **IRIS-style source→sink taint hunt.** Ranks a typed CWE catalog for the repo, then runs subagents in sequence — label dangerous **sinks** → label **sources** of user input → trace source→sink with **Joern/CodeQL** queries (or same-file linking) → **triage** each flow `finding`/`candidate`/`rejected` with an evidence level (`path`/`linked`/`candidate`). Deeper with a prebuilt DB/CPG; degrades gracefully without. | `.kuzushi/taint-analysis.json`, `findings.json` |
| `/supply-chain` | **Dependency takeover/abandonment risk.** Parses manifests for direct deps, then the supply-chain-auditor agent rates each by maintainer count, popularity, CVE history, and release cadence (via `gh` + web), promoting high→finding / medium→candidate (`source: supply-chain`). Complements `/threat-intel` (CVEs). *Uses the network — asks first.* | `.kuzushi/supply-chain.json`, `findings.json` |
| `/diff-review` | **Change-focused security review.** Resolves a base ref, risk-scores changed files, then the diff-reviewer agent walks source→sink on the new code, uses `git blame` to catch **regressions**, and estimates **blast radius** by caller count. Threat-hunt verdict set. Needs git. | `.kuzushi/diff-review.json`, `findings.json` |
| `/sharp-edges` | **Misuse-resistance review.** Scans for footgun APIs / dangerous defaults, then the sharp-edges-analyzer agent reasons through three adversaries (scoundrel / lazy / confused dev) across six categories (e.g. JWT `alg:none`, TLS verify off, stringly-typed auth). Distinct from `/sast` (injection). | `.kuzushi/sharp-edges.json`, `findings.json` |
| `/sast` | **Semgrep SAST pass.** The sast-triager agent runs `semgrep:scan`, then reads the source behind each hit to classify it `finding`/`candidate`/`rejected` (scanner hits are leads, not findings). Promotes the kept ones into findings. Needs semgrep installed. | `.kuzushi/sast.json`, `findings.json` |
| `/crypto-review` | **Crypto-misuse review.** The crypto-reviewer agent confirms each candidate handles a secret, then flags timing side-channels (variable-time compare of a MAC/token, CWE-208), missing/elidable zeroization (CWE-226/14), and non-cryptographic RNG minting secrets (CWE-338). Distinct from `/sast` and `/sharp-edges`. | `.kuzushi/crypto-review.json`, `findings.json` |
| `/authz` | **Authorization-model review.** Scans endpoints + object-access-by-id sites; the authz-reviewer agent finds missing authz (CWE-862), IDOR / broken object-level authz (CWE-639), privilege escalation, and broken ownership. | `.kuzushi/authz.json`, `findings.json` |
| `/logic-hunt` | **Business-logic flaw review** — the class taint/SAST are structurally blind to. Scans for money/state mutations, checkout/redeem entrypoints, price math, and status transitions; the logic-hunter agent reconstructs the multi-step flow and tests it for **idempotency** gaps (replayable actions, CWE-837), **TOCTOU** races (CWE-367), non-atomic **transactions** (CWE-362), **price/quantity** manipulation (CWE-840), and **state-machine** re-entry (CWE-841) — naming the invariant that should protect each action. | `.kuzushi/logic-hunt.json`, `findings.json` |
| `/binary-recon` | **Read-only static binary triage.** Detects ELF/PE/Mach-O by magic bytes and surfaces dangerous imported symbols and writable+executable segments via on-PATH binutils (`nm`/`readelf`/`objdump`); the binary-recon agent judges which signals are real exposures in context and ties them to source. **Assessment only** — no execution, no exploit-oriented disassembly. | `.kuzushi/binary-recon.json`, `findings.json` |
| `/iac` | **Config & container security.** Scans Dockerfiles, Kubernetes/Compose, and Terraform/IaC for misconfigurations (privileged containers, root, unpinned images, hardcoded secrets, public network/storage, disabled TLS); the iac-reviewer agent confirms each in context. | `.kuzushi/iac.json`, `findings.json` |
| `/traffic-map` | **Offline Burp/HAR import.** Parses a HAR or Burp "Save items" XML export into observed endpoints, then the traffic-mapper agent correlates each to its source handler (x-ray + code-graph) and flags the gaps the traffic reveals (shadow surface, unauthenticated mutating endpoints, params reaching sinks). Offline — no proxy. | `.kuzushi/traffic-map.json`, `findings.json` |
| `/report` | **Prioritized security report — the human deliverable.** Deterministic transform of `findings.json` into a ranked, readable report (`.kuzushi/report.md`; `html` also writes `report.html`). Orders findings **fix-first** by severity × proof state × exploitability × blast radius (`scripts/lib/risk.mjs`), and folds in attack chains, `/sweep` coverage (the honest "what wasn't scanned" set), and provenance. Actionable findings by default; `all` includes reviewed/noise. Read-only rendering — makes no security decision; pair with `/export-sarif` for CI. | `.kuzushi/report.md`, `report.html` |
| `/export-sarif` | **SARIF export.** Deterministic transform of `findings.json` into SARIF 2.1.0 (`.kuzushi/findings.sarif`) for CI code-scanning, dashboards, and IDEs — one rule per CWE, severity→level, fingerprints carried. `all` includes reviewed/noise too. | `.kuzushi/findings.sarif` |
| `/variant-hunt` | **Variant analysis.** For each confirmed/proven finding (the *seed*), the variant-hunter agent sweeps the repo for other sites with the same bug class — exact-match → generalize one step at a time (ripgrep → Semgrep → CodeQL/Joern) → triage each. Promotes variants into findings with `refId` `variant-of:<seed>` so they trace back to origin. Requires a confirmed finding first. | `.kuzushi/variant-hunt.json`, `findings.json` |
| `/semgrep-rule` | **Test-driven detection from a confirmed bug.** For each seed finding, the semgrep-rule-author agent writes a positive/negative fixture and a Semgrep rule matching the bug shape under `.kuzushi/rules/`, validates it with `semgrep:scan`, and indexes it. The rules seed `/variant-hunt` and `/sast`. | `.kuzushi/rules/*.yaml`, `semgrep-rules.json` |
| `/rule-synth` | **Validated CodeQL/Joern rules from a confirmed bug** — the heavy semantic engines `/semgrep-rule` doesn't cover. The rule-synthesist agent writes a query per seed; a **native gate** (compile → fire-on-seed → repo-run → precision-cap) accepts only passing rules into a **digest-attested pack** (`.kuzushi/rules/{codeql,joern}/` + `pack.json`). The codeql/joern MCP servers refuse to run a pack query whose bytes don't match the manifest, so generated queries are validated before they execute. New matches promote as `candidate` leads. Needs a built CodeQL DB / Joern CPG. | `.kuzushi/rules/{codeql,joern}/`, `pack.json`, `rule-synth.json`, `findings.json` |
| `/verify` | **Exploitability verification** of the open findings: reconstruct source→sink, build a concrete trigger, defeat every guard → verdict (`confirmed-exploitable` / `not-exploitable` / `inconclusive`) + confidence + PoC sketch. Read-only; attaches a `verification` block onto each finding and tags the PoC-ready ones. | `.kuzushi/verify.json`, `findings.json` |
| `/path-solve` | **Concolic-lite path solving** for findings `/verify` left `inconclusive`. The path-solver agent extracts the guard predicate between source and sink (tree-sitter) and solves it into a concrete reaching input — via the optional concolic MCP backend (**Z3** for numeric/string, **CrossHair** for Python) when installed, else by reasoning (LLM). Attaches a `pathSolution` block that feeds `/verify` + `/fuzz`. Heuristic, not a proof. | `.kuzushi/path-solve.json`, `findings.json` |
| `/poc` | **Empirical proof**: for each verified finding, synthesize a minimal harness and run it in a sandbox (Docker `--network none`, else a gated local run) — a crash/expected exit is the proof. Attaches a `poc` block (`proofLevel`/`proofVerdict`) onto each finding. | `.kuzushi/poc.json`, `findings.json` |
| `/fuzz` | **Consolidated fuzz proof loop.** Plans a fuzz campaign from confirmed/proven findings, creates harness directories, runs declared harness commands offline, groups crashes, records minimization status, and promotes only `proofVerdict:"exploited"` evidence to `proven`. Lower-level `/fuzz-init`, `/fuzz-run`, `/fuzz-triage`, `/fuzz-minimize`, and `/fuzz-promote` remain replay/debug stages. | `.kuzushi/fuzz/*.json`, `findings.json` |
| `/mem-exploitability` | **Memory-corruption exploitability assessment.** For each memory-safety finding, an agent works the analysis phases — vuln shape, control/offset plausibility, input constraints, and **mitigation posture** (NX/PIE/canary/RELRO/FORTIFY/CFG from build flags + read-only binary inspection via checksec/readelf/otool) — and assigns an exploitability **tier** (`crash-only`/`dos`/`info-leak`/`control-flow-hijack-plausible`/`likely-code-exec`) + remediation. **Assessment only** — no shellcode, ROP chains, or mitigation bypasses; empirical crash proof stays in `/poc`. Attaches an `exploitability` block onto each finding. | `.kuzushi/mem-exploitability.json`, `findings.json` |
| `/fix` | **Patch generation + PoC⁺ validation.** For each confirmed/proven finding, an agent root-causes the bug and writes a minimal **defensive** unified-diff patch + functional and semantic checks. The host applies it to a **sandbox copy**, re-runs the existing PoC harness (must no longer fire), the functional check, and the semantic oracle check for supported CWEs — a patch is **`validated`** only if all required gates pass. The working tree is never modified until you **explicitly approve** the apply step (one finding at a time; native Allow/Deny + a rollback command). Status advances `patched` → `remediated` on apply. | `.kuzushi/fix.json`, `findings.json` |
| `/chain` | **Cross-finding attack chains.** The chain-finder agent reasons over the findings index for compositions (precondition → pivot → impact) — e.g. an auth bypass that turns a read-only SSRF into internal RCE, or a `/mem-exploitability` info-leak that defeats a canary for a control-flow hijack — and records each chain (ordered narrative + member fingerprints), attaching a `chains` ref onto each member (status unchanged). An analysis overlay, not a combined exploit. | `.kuzushi/chains.json`, `findings.json` |
| `/code-graph` | Builds a cached **code-graph** — entry points + per-symbol **caller counts** (blast-radius / attack-surface signal) — via a deterministic ripgrep heuristic (no heavy tooling). `/diff-review` reads it for deterministic blast radius; hunters consult it for reachability. | `.kuzushi/code-graph.json` |
| `/build-databases` | Builds the **CodeQL database** + **Joern CPG** (async, in the background) that power the deep-query backends. | `.kuzushi/codeql-db/`, `joern/cpg.bin.zip` |
| `/install` | Vendors / installs the tooling relevant to the repo's languages. | `vendor/` |
| `/doctor` | Preflight: Node deps, MCP server health, CLI/LSP install status + install hints. | — |

Skills are backed by purpose-built subagents (`context-analyst`, `threat-modeler`, `threat-intel-researcher`,
`threat-hunter`, `systems-hunter`, `invariant-tester`, `verifier`, `poc-builder`,
`mem-exploit-analyst`, `variant-hunter`, `sast-triager`, `semgrep-rule-author`, `supply-chain-auditor`,
`diff-reviewer`, `sharp-edges-analyzer`, `crypto-reviewer`, `fuzz-harness-author`, `path-solver`,
`iac-reviewer`, `authz-reviewer`, `logic-hunter`, `binary-recon`, `deep-scanner`, `traffic-mapper`,
`rule-synthesist`, `fixer`, `chain-finder`) that run in isolated context and
inherit the plugin's MCP tools. `/sweep` is a **coordinator** (`sweep-coordinator`) that fans the
producers out across repo shards in parallel and aggregates a coverage map. `/verify` supports a
**panel mode** (`--input '{"panel":3}'`) that runs N independent verifiers per finding and decides
by majority — precision for the un-pattern-gated leads `/deep-scan` produces. `/taint-analysis` is a **coordinator** that sequences four of
them — `taint-sink-labeler` and `taint-source-labeler` (in parallel), then `taint-flow-tracer`,
then `taint-triager` — passing data through staged JSON drafts.

### Companion skills

kuzushi stays focused on white-box source→sink work. For orthogonal angles — config/secrets
defaults, supply-chain risk, crypto side-channels, per-PR diffs — the
[Trail of Bits skills](https://github.com/trailofbits/skills) marketplace installs alongside
kuzushi and complements it. See **[docs/COMPANIONS.md](docs/COMPANIONS.md)** for which to add and
the gap each fills.

---

## Tooling — conditional & self-installing

The plugin only spins up what your repo needs, and installs what it can.

- **LSP** is gated by file extension automatically — Go tooling never starts in a Java repo.
  `typescript-language-server` and `pyright` ship bundled; `gopls`/`jdtls`/`rust-analyzer`/
  `clangd` resolve from a vendored copy or your PATH.
- **MCP servers** (always connected, self-reporting): a self-gating **tree-sitter** server
  (AST + taint source/sink queries, scoped to detected languages) plus wrappers for
  **semgrep, CodeQL, Joern, gtags, codegraph** — each returns a structured "missing" until its
  CLI is present.
- **Vendoring**: light tools (rust-analyzer, clangd, jdtls, codegraph) can auto-install in the
  background on first session in `developer-fast`; `review-safe` and `ci-locked` disable surprise
  downloads. Heavy ones (CodeQL ~1 GB, Joern ~2 GB) are opt-in via `/install codeql|joern`.
  Install state records source URLs and digests where available.
- **Databases**: `/build-databases` creates the CodeQL DB + Joern CPG **asynchronously** (logs
  to `.kuzushi/db-build.log`) so deep semantic queries work without blocking your session.

Run `/doctor` any time to see exactly what's available — including the effective
**tool-boundary policy**.

**System prerequisites** (only for the tools you use): Java 17+ (jdtls, Joern), Go (gopls),
Python (semgrep). The plugin tells you what's missing and how to get it.

### Trust plane

The analyzer query surface, working-tree writes, hook error posture, and tool downloads are governed by a policy
(`policy.default.json`, override per-repo with `.kuzushi/policy.json`). Always-on: CodeQL/Joern
query **path-confinement** (no escapes to `~/.ssh`, `/etc`, …) and an inline-script **size cap**.
Configurable profiles:

- `developer-fast`: raw queries allowed, hook errors fail open, light auto-install enabled.
- `review-safe`: raw queries require approval, hook errors block, auto-install disabled.
- `ci-locked`: raw queries denied, git apply denied, network installs denied, hook errors fail closed.

Every artifact carries a `provenance` block (toolchain/repo/scope/policy digests). See
[docs/HARDENING.md](docs/HARDENING.md).

---

## How it works

Everything persists under `.kuzushi/` in the target repo. Two artifacts are **forward
contracts** that later steps (and your own tooling) build on:

- **Invariants** (`threat-intel.json.invariants[]`) — `{ statement, cwe, severity, sourceCves,
  sourceSignals, sinkSignals, sanitizerSignals, taintClass, languages, checkHint }`. CVE
  intelligence turned into checkable assertions.
- **Findings** (`findings.json`) — versioned as `findings.v1` / `finding.v1` with
  `{ fingerprint, source, refId, title, severity, cwe, verdict, status, proofState,
  evidence:[{filePath,startLine}], rationale, nextChecks }`, deduped by fingerprint.
  The proof ladder is explicit: `lead/candidate → open → confirmed → proven → patched →
  remediated`, with reviewed/noise states kept separate. `/verify`, `/poc`, `/fuzz`,
  and `/fix` attach `verification`, `poc`, `fuzz`, and `fix` blocks instead of replacing the
  finding, so a finding accretes its full discovery → proof → remediation story in one place.

Schemas live under `schemas/`, and `npm run bench:smoke` verifies the core contracts plus SARIF
metadata and locked policy behavior. See [BENCHMARKS.md](BENCHMARKS.md).

It's a faithful Node port/adaptation of the [kuzushi](#acknowledgements) security toolkit —
no Rust build, no external binary, no daemon.

## Hardening

kuzushi opens **source you may not trust**, which changes the threat model for your own session.
The plugin ships `PreToolUse` guardrail hooks that block `rm -rf`, `git push` to `main`/`master`,
and reads of secret paths (`~/.ssh`, `~/.aws`, keychains, wallets, registry tokens). Hook errors
fail open only in `developer-fast`; `review-safe` and `ci-locked` block on hook errors. For the
user-level settings a plugin can't set itself — notably `enableAllProjectMcpServers: false` so a
target repo's own `.mcp.json` is never auto-loaded — see **[docs/HARDENING.md](docs/HARDENING.md)**.

## Privacy

All analysis runs **locally** against your repo. The only steps that reach the network are
`/threat-intel` (web search for CVEs), `/supply-chain` (registry/`gh` lookups), and optional tool
downloads in `/install` / `/build-databases`, and those are policy-gated. Nothing is uploaded.
`/sweep --input '{"offline":true}'` skips every network-touching producer for an air-gapped run —
the one guarantee a cloud SAST that uploads your source structurally cannot make.

## How it compares

For an honest head-to-head with cloud LLM-SAST (specifically **Xint Code**) — where kuzushi wins by
construction (local / auditable / closed-loop / free), where the cloud tools are still ahead (raw
throughput, track record), and what `/sweep`, `/logic-hunt`, and `/binary-recon` added to close the
gap — see **[docs/vs-xint.md](docs/vs-xint.md)**. Benchmark methodology lives in
**[bench/README.md](bench/README.md)**.

## Where it's headed — raw detection power

The active priority is finding **more, harder, and chained** vulnerabilities. The eval showed the
find-rate lever is *not* model strength — it's removing structural ceilings: interprocedural
dataflow is opt-in (degrades to same-file without a CPG), discovery is one-pass, and `/chain` only
composes findings that already exist rather than *searching* entry→asset attack paths. The
prioritized levers — interprocedural-by-default, a hypothesis-driven deep-hunt loop, a proactive
attack-path engine, framework-aware entry-point enumeration, ensemble discovery, and
class-specialized reasoning (gadget chains, TOCTOU) — are tracked in **[ROADMAP.md](ROADMAP.md#raising-detection-power-current-priority)**.

## Contributing

Issues and PRs welcome. The codebase is small, dependency-light Node; each capability is a
`prepare → agent → assemble` trio under `scripts/cmd/` with a matching skill + agent. Run
`/doctor` to validate your environment.

Run **`npm test`** before sending a change — `test/` covers the shared-lib contracts the whole
pipeline depends on (findings index + schema, verdict→status maps, the policy/attestation gate,
and the rule-synth / fix / chain / mem-exploitability validators) with Node's built-in runner (no
extra deps). Engine-backed tests (a real Joern `/rule-synth` run) self-skip when the CLI is absent,
so the suite is green offline and exercises the real path in CI where Joern/CodeQL exist.

## License

[MIT](LICENSE).

## Acknowledgements

Ports and adapts the **kuzushi** security toolkit (PASTA staging, the Carlini adversarial
threat-hunt doctrine, the analysis-engine conventions). Thanks to the CodeQL, Joern,
Semgrep, tree-sitter, and Eclipse JDT projects whose tools this orchestrates.
