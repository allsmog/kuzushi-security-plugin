---
name: rule-synth
description: Synthesize CodeQL queries / Joern scripts from confirmed findings — the heavy semantic engines /semgrep-rule (Semgrep-only) doesn't cover. The rule-synthesist agent writes a tight rule per seed; the host runs a native compile → fire-on-seed → repo-run → precision gate and persists only validated rules into a digest-attested pack under .kuzushi/rules/{codeql,joern}/, promoting new matches as candidate leads. Needs a confirmed finding + a built CodeQL DB / Joern CPG.
context: fork
agent: rule-synthesist
user-invocable: true
---

# Rule synthesis (CodeQL / Joern)

Lift a confirmed finding into a **validated, reusable semantic detection rule** for CodeQL/Joern
— complementary to `/semgrep-rule` (which covers Semgrep). Accepted rules land in a digest-attested
pack (`.kuzushi/rules/{codeql,joern}/` + `pack.json`); the codeql/joern MCP servers refuse to run a
pack query whose bytes don't match the manifest, so generated queries are validated before they execute.

Requires: a confirmed/proven/exploitable finding in `findings.json`, **and** a built CodeQL DB or
Joern CPG (`/build-databases`). For Semgrep, use `/semgrep-rule` instead.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/rule-synth-prepare.mjs" --target "<repo root>"`.
   If `status` is `no-seeds` (run `/verify` or `/threat-hunt` first) or `no-engine` (run
   `/build-databases`, or `/semgrep-rule` for Semgrep), report that and stop. Read `prepPath`.
2. For **each** seed, write a tight CodeQL `.ql` / Joern `.sc` for the `recommendedEngine` into the
   run dir, using the seed's `seedFingerprint` as `seedRef`. Joern scripts must print matches as
   `KUZUSHI_MATCH\t<file>\t<line>`. Write the `{ rules: [...] }` bundle to the prep's `draftPath`.
3. Run the `assembleCommand` (finalize). It compiles each rule, checks it fires on the seed line,
   runs it across the repo, and caps it for precision — accepting only those that pass into the
   pack and promoting new matches as `candidate` findings. Report accepted/rejected per seed.
