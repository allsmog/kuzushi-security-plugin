# kuzushi-security-plugin

**An autonomous, language-aware white-box (static source) security review pipeline that lives inside Claude Code.**

Point it at source you already have checked out and the plugin statically maps it (entry
points by pattern, not observed traffic), threat-models it, researches the CVEs that actually
apply, and adversarially hunts the threats it found — wiring up the right LSP and analysis
tooling for the languages it detects. Self-contained Node (no external engine, no server to
run): everything is plain stdio MCP servers, skills, and a SessionStart hook.

```
context ─► x-ray ─► threat-model ─► threat-intel ─► ┌ invariant-test ┐ ─► findings.json ─► verify ─► poc
 (langs,    (entry    (PASTA DFD +    (CVEs for       └ threat-hunt   ┘     (open          (exploit-  (sandbox-
  deps)      points)   threats)        stack + peers)  (adversarial)         findings)      ability)    proven)
                                                                                  │
                                                                                  └─► mem-exploitability
                                                                                      (memory-corruption tier
                                                                                       + mitigation posture)
```

Each step writes an artifact under `.kuzushi/` that the next step consumes. You stay in
control: heavy or outbound steps **ask first**, and everything runs against your local repo.

---

## Scope & boundaries

This is a **white-box, static source-code** tool. How complete that is depends on what you
point it at.

**Always in scope** (any target with source on disk): PASTA threat model, version-checked CVE
intel, source→sink taint analysis, adversarial guard-bypass review, static exploitability
verdicts, memory-corruption exploitability assessment, and a sandboxed PoC harness.

**Web apps / HTTP services** — the plugin covers the *static* half of a grey-box review. Pair
it with a dynamic tool (Burp / DAST) for the rest: browsing the live app, mapping observed
traffic (endpoints, parameters, cookies, roles) to handlers, and triggering against a running
target. None of that lives here.

**Libraries, native / systems code, parsers, CLIs** — there's no HTTP layer to proxy, so most
of that dynamic half simply doesn't apply. Source→sink plus the sandboxed `/poc` harness is
much of the standard workflow. The dynamic complement *here* is fuzzing (libFuzzer / AFL,
sanitizers at scale); `/poc` builds a single ASAN/crash harness, not a fuzzing campaign.

**Across the board:** it loads source, it does not *recover* it (no decompilation / bytecode);
`/poc` proves the code in an isolated sandbox (`--network none`), not a deployed app; and there
is no multi-bug exploit chaining — findings are assessed independently.

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
/threat-model        # PASTA model → .kuzushi/threat-model.json (+ ASCII data-flow diagram)
/threat-intel        # research critical/high CVEs (this stack + similar apps) → invariants
/threat-hunt         # adversarial per-threat review → .kuzushi/findings.json
/invariant-test      # check the CVE-derived invariants against the code
/taint-analysis      # IRIS-style source→sink taint hunt (label sinks/sources → trace → triage)
/verify              # reconstruct each open finding's trigger → exploitability verdict + PoC sketch
/poc                 # build a harness for each verified finding, run it in a sandbox → empirical proof
/mem-exploitability  # memory-corruption findings → exploitability tier + mitigation posture (assessment only)
/doctor              # what's installed / missing, with install commands
```

---

## Skills

| Command | What it does | Writes |
|---|---|---|
| `/threat-model` | Agent builds a **PASTA** threat model in phases (objectives → scope → decomposition → threats) + an ASCII data-flow diagram. | `.kuzushi/threat-model.json`, `threat-model-dfd.txt` |
| `/threat-intel` | Researches recent **critical/high CVEs** for the detected stack (version-checked) and **similar apps**, distilled into machine-checkable invariants. *(uses web search)* | `.kuzushi/threat-intel.json` |
| `/invariant-test` | Verifies each CVE-derived invariant against the code with tree-sitter taint queries (CodeQL/Joern if built). | `.kuzushi/invariant-results.json` |
| `/threat-hunt` | **Adversarial per-threat review** (the Carlini doctrine): state attacker capabilities → trace source→sink → bypass *every* guard → verdict from a closed set. Promotes verdicts to the findings index. | `.kuzushi/threat-hunt.json`, `findings.json` |
| `/systems-hunt` | **Native / memory-safety review.** Scans for systems patterns (loadLibrary/JNI, `memcpy`/`Unsafe`/`gets`, archive parsers, deserialization, exec), then a subagent confirms reachability + memory-safety impact (OOB, UAF, integer overflow, RCE). Best on C/C++/Rust/native; promotes to findings. | `.kuzushi/systems-hunt.json`, `findings.json` |
| `/taint-analysis` | **IRIS-style source→sink taint hunt.** Ranks a typed CWE catalog for the repo, then runs subagents in sequence — label dangerous **sinks** → label **sources** of user input → trace source→sink with **Joern/CodeQL** queries (or same-file linking) → **triage** each flow `finding`/`candidate`/`rejected` with an evidence level (`path`/`linked`/`candidate`). Deeper with a prebuilt DB/CPG; degrades gracefully without. | `.kuzushi/taint-analysis.json`, `findings.json` |
| `/verify` | **Exploitability verification** of the open findings: reconstruct source→sink, build a concrete trigger, defeat every guard → verdict (`confirmed-exploitable` / `not-exploitable` / `inconclusive`) + confidence + PoC sketch. Read-only; attaches a `verification` block onto each finding and tags the PoC-ready ones. | `.kuzushi/verify.json`, `findings.json` |
| `/poc` | **Empirical proof**: for each verified finding, synthesize a minimal harness and run it in a sandbox (Docker `--network none`, else a gated local run) — a crash/expected exit is the proof. Attaches a `poc` block (`proofLevel`/`proofVerdict`) onto each finding. | `.kuzushi/poc.json`, `findings.json` |
| `/mem-exploitability` | **Memory-corruption exploitability assessment.** For each memory-safety finding, an agent works the analysis phases — vuln shape, control/offset plausibility, input constraints, and **mitigation posture** (NX/PIE/canary/RELRO/FORTIFY/CFG from build flags + read-only binary inspection via checksec/readelf/otool) — and assigns an exploitability **tier** (`crash-only`/`dos`/`info-leak`/`control-flow-hijack-plausible`/`likely-code-exec`) + remediation. **Assessment only** — no shellcode, ROP chains, or mitigation bypasses; empirical crash proof stays in `/poc`. Attaches an `exploitability` block onto each finding. | `.kuzushi/mem-exploitability.json`, `findings.json` |
| `/build-databases` | Builds the **CodeQL database** + **Joern CPG** (async, in the background) that power the deep-query backends. | `.kuzushi/codeql-db/`, `joern/cpg.bin.zip` |
| `/install` | Vendors / installs the tooling relevant to the repo's languages. | `vendor/` |
| `/doctor` | Preflight: Node deps, MCP server health, CLI/LSP install status + install hints. | — |

Skills are backed by purpose-built subagents (`threat-modeler`, `threat-intel-researcher`,
`threat-hunter`, `systems-hunter`, `invariant-tester`, `verifier`, `poc-builder`,
`mem-exploit-analyst`) that run in isolated context and
inherit the plugin's MCP tools. `/taint-analysis` is a **coordinator** that sequences four of
them — `taint-sink-labeler` and `taint-source-labeler` (in parallel), then `taint-flow-tracer`,
then `taint-triager` — passing data through staged JSON drafts.

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
- **Vendoring**: light tools (rust-analyzer, clangd, jdtls, codegraph) auto-install in the
  background on first session, language-gated; the heavy ones (CodeQL ~1 GB, Joern ~2 GB) are
  opt-in via `/install codeql|joern`. Cross-platform (macOS + Linux).
- **Databases**: `/build-databases` creates the CodeQL DB + Joern CPG **asynchronously** (logs
  to `.kuzushi/db-build.log`) so deep semantic queries work without blocking your session.

Run `/doctor` any time to see exactly what's available.

**System prerequisites** (only for the tools you use): Java 17+ (jdtls, Joern), Go (gopls),
Python (semgrep). The plugin tells you what's missing and how to get it.

---

## How it works

Everything persists under `.kuzushi/` in the target repo. Two artifacts are **forward
contracts** that later steps (and your own tooling) build on:

- **Invariants** (`threat-intel.json.invariants[]`) — `{ statement, cwe, severity, sourceCves,
  sourceSignals, sinkSignals, sanitizerSignals, taintClass, languages, checkHint }`. CVE
  intelligence turned into checkable assertions.
- **Findings** (`findings.json`) — `{ fingerprint, source, refId, title, severity, cwe,
  verdict, status, evidence:[{filePath,startLine}], rationale, nextChecks }`, deduped by
  fingerprint. The canonical index every producer (`threat-hunt`, `taint-analysis`, …) writes
  to and every consumer reads. `/verify` and `/poc` don't replace findings — they **attach** a
  `verification` then a `poc` block onto the matching finding and advance its `status`
  (`open → confirmed → proven`), so a finding accretes its full exploit story in one place.

It's a faithful Node port/adaptation of the [kuzushi](#acknowledgements) security toolkit —
no Rust build, no external binary, no daemon.

## Hardening

kuzushi opens **source you may not trust**, which changes the threat model for your own session.
The plugin ships `PreToolUse` guardrail hooks that block `rm -rf`, `git push` to `main`/`master`,
and reads of secret paths (`~/.ssh`, `~/.aws`, keychains, wallets, registry tokens). For the
user-level settings a plugin can't set itself — notably `enableAllProjectMcpServers: false` so a
target repo's own `.mcp.json` is never auto-loaded — see **[docs/HARDENING.md](docs/HARDENING.md)**.

## Privacy

All analysis runs **locally** against your repo. The only step that reaches the network is
`/threat-intel` (web search for CVEs) and the optional tool downloads in `/install` /
`/build-databases`. Nothing is uploaded.

## Contributing

Issues and PRs welcome. The codebase is small, dependency-light Node; each capability is a
`prepare → agent → assemble` trio under `scripts/cmd/` with a matching skill + agent. Run
`/doctor` to validate your environment.

## License

[MIT](LICENSE).

## Acknowledgements

Ports and adapts the **kuzushi** security toolkit (PASTA staging, the Carlini adversarial
threat-hunt doctrine, the analysis-engine conventions). Thanks to the CodeQL, Joern,
Semgrep, tree-sitter, and Eclipse JDT projects whose tools this orchestrates.
