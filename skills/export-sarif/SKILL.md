---
name: export-sarif
user-invocable: false
description: Export .kuzushi/findings.json as a SARIF 2.1.0 file (.kuzushi/findings.sarif) so findings are consumable by CI code-scanning, dashboards, and IDEs. Deterministic transform — no analysis. Pass "all" to include reviewed/noise findings too.
argument-hint: "[all]"
allowed-tools: Bash
---

# Export findings as SARIF

Convert the shared findings index into SARIF 2.1.0 for interop with CI / IDE tooling.

Run, using the project working directory as `<cwd>` (add `--all` only if `$ARGUMENTS` is `all`):

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/export-sarif.mjs" --target "<cwd>"
```

It writes `.kuzushi/findings.sarif` and prints `{ sarifPath, resultCount, ruleCount }`. By
default only **actionable** findings are exported (status open/confirmed/proven, or verdict
exploitable/finding); pass `all` to include reviewed/noise too. Relay the result and the path.
Severity maps to SARIF level (critical/high → error, medium → warning, else → note); each
distinct CWE becomes a SARIF rule; the kuzushi fingerprint is carried as a partial fingerprint.

## When NOT to use

- Before any findings exist — run a producer (`/threat-hunt`, `/taint-analysis`, `/systems-hunt`)
  first.
- To analyze or triage — this only reformats existing findings; it makes no security decisions.
