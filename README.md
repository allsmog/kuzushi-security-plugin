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
context ─► x-ray ─► threat-model ─► threat-intel ─► ┌ invariant-test ┐ ─► findings.json ─► verify ─► poc ─► fix
 (langs,    (entry    (PASTA DFD +    (CVEs for       └ threat-hunt   ┘     (open          (exploit-  (sandbox- (PoC⁺
  deps)      points)   threats)        stack + peers)  (adversarial)         findings)      ability)    proven)   patch)
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

1. Start Claude Code in any source repo. The SessionStart hook **auto-builds repository
   context** (file inventory, languages, component hints) and prints a status report.
2. It then offers the next steps as you go — run x-ray, build a PASTA threat model, research
   CVEs, hunt threats. Or drive them yourself with the skills below.

```
/deep-context        # deep system-understanding pass (modules, trust boundaries, invariants)
/code-graph          # cache entry points + per-symbol caller counts (blast-radius signal)
/traffic-map         # offline Burp/HAR import → correlate observed endpoints to source handlers
/threat-model        # PASTA model → .kuzushi/threat-model.json (+ ASCII data-flow diagram)
/threat-intel        # research critical/high CVEs (this stack + similar apps) → invariants
/supply-chain        # dependency takeover/abandonment risk (maintainers, cadence) → findings
/threat-hunt         # adversarial per-threat review → .kuzushi/findings.json
/invariant-test      # check the CVE-derived invariants against the code
/taint-analysis      # IRIS-style source→sink taint hunt (label sinks/sources → trace → triage)
/sast                # semgrep scan → triage hits into findings.json
/sharp-edges         # footgun APIs / dangerous defaults (misuse-resistance review) → findings
/crypto-review       # timing side-channels, missing zeroization, weak crypto RNG → findings
/authz               # authorization-model review: missing authz, IDOR, privilege escalation → findings
/iac                 # config & container security: Dockerfile/k8s/Terraform misconfig → findings
/diff-review         # security review of a change (regressions + blast radius) → findings
/variant-hunt        # find siblings of a confirmed bug across the repo → findings.json
/semgrep-rule        # distill confirmed findings into test-driven Semgrep rules
/rule-synth          # distill confirmed findings into validated CodeQL/Joern rules (digest-attested pack)
/verify              # reconstruct each open finding's trigger → exploitability verdict + PoC sketch
/path-solve          # solve the guard predicate to reach a sink /verify left inconclusive (concolic-lite)
/poc                 # build a harness for each verified finding, run it in a sandbox → empirical proof
/fuzz                # plan/run/triage/minimize/promote local fuzz proof
/mem-exploitability  # memory-corruption findings → exploitability tier + mitigation posture (assessment only)
/fix                 # generate + PoC⁺-validate a patch per finding; apply behind explicit approval
/chain               # link related findings into higher-impact attack chains (analysis overlay)
/export-sarif        # export findings.json as SARIF 2.1.0 for CI / IDE code-scanning
/benchmark           # score recall / precision / false-proof against a ground-truth corpus
/doctor              # what's installed / missing, with install commands
```

---

## Skills

| Command | What it does | Writes |
|---|---|---|
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
| `/iac` | **Config & container security.** Scans Dockerfiles, Kubernetes/Compose, and Terraform/IaC for misconfigurations (privileged containers, root, unpinned images, hardcoded secrets, public network/storage, disabled TLS); the iac-reviewer agent confirms each in context. | `.kuzushi/iac.json`, `findings.json` |
| `/traffic-map` | **Offline Burp/HAR import.** Parses a HAR or Burp "Save items" XML export into observed endpoints, then the traffic-mapper agent correlates each to its source handler (x-ray + code-graph) and flags the gaps the traffic reveals (shadow surface, unauthenticated mutating endpoints, params reaching sinks). Offline — no proxy. | `.kuzushi/traffic-map.json`, `findings.json` |
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
| `/benchmark` | **Recall / precision / false-proof measurement.** Scores a run's `findings.json` against a ground-truth manifest (planted bugs + safe decoys that must *not* be flagged) and reports recall, precision, and false-proof rate. Runs the bundled `bench/cases/` corpus for regression, or a live target with `--ground-truth`. Deterministic, no agent. | — (report) |
| `/build-databases` | Builds the **CodeQL database** + **Joern CPG** (async, in the background) that power the deep-query backends. | `.kuzushi/codeql-db/`, `joern/cpg.bin.zip` |
| `/install` | Vendors / installs the tooling relevant to the repo's languages. | `vendor/` |
| `/doctor` | Preflight: Node deps, MCP server health, CLI/LSP install status + install hints. | — |

Skills are backed by purpose-built subagents (`context-analyst`, `threat-modeler`, `threat-intel-researcher`,
`threat-hunter`, `systems-hunter`, `invariant-tester`, `verifier`, `poc-builder`,
`mem-exploit-analyst`, `variant-hunter`, `sast-triager`, `semgrep-rule-author`, `supply-chain-auditor`,
`diff-reviewer`, `sharp-edges-analyzer`, `crypto-reviewer`, `fuzz-harness-author`, `path-solver`,
`iac-reviewer`, `authz-reviewer`, `traffic-mapper`, `rule-synthesist`,
`fixer`, `chain-finder`) that run in isolated context and
inherit the plugin's MCP tools. `/taint-analysis` is a **coordinator** that sequences four of
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
`/threat-intel` (web search for CVEs) and optional tool downloads in `/install` /
`/build-databases`, and those are policy-gated. Nothing is uploaded.

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
