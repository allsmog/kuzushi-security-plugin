# Starter query pack

Curated, maintainer-authored CodeQL/Joern queries so the **first** interprocedural taint query
runs without the agent hand-writing one. `install-starter-pack` copies these into a target's
`.kuzushi/rules/` and registers them in the digest-attested pack manifest, so the codeql/joern MCP
servers will execute them (the execution gate, `assertPackRunnable`, checks the on-disk bytes
against the recorded digest). The SessionStart auto-build installs the pack when it builds the DB.

## Coverage

| CWE | Class | CodeQL | Joern (any language) |
|-----|-------|--------|----------------------|
| CWE-22 | Path traversal | JS, Python | — |
| CWE-78 | Command injection | JS, Python | ✓ |
| CWE-79 | Reflected XSS | JS, Python | — |
| CWE-89 | SQL injection | JS, Python | ✓ |
| CWE-90 | LDAP injection | — | ✓ |
| CWE-94 | Code injection | JS, Python | ✓ |
| CWE-502 | Unsafe deserialization | JS | ✓ |
| CWE-601 | Open redirect | — | ✓ |
| CWE-611 | XXE | — | ✓ |
| CWE-918 | SSRF | JS, Python | ✓ |
| CWE-943 | NoSQL injection | — | ✓ |
| CWE-1336 | Server-side template injection | — | ✓ |

CodeQL queries use the standard-library security **flow modules** (`<Name>Flow::PathGraph`); Joern
queries are language-agnostic CPG dataflow (`reachableByFlows`) following the `KUZUSHI_CPG`
convention (see `scripts/joern/taint-flows.sc`) — so they cover Java/Go/C# targets too, not just
the languages with a dedicated CodeQL query here.

## Trust & verification

Shipped entries are marked `validated.compile: true` (curated authorship) with
`validated.compileVerified: false` — the bytes are **not** machine-compiled at install time, since
no specific CodeQL/Joern version is assumed. Two safety nets back this:

- `test/starter-pack-structure.test.mjs` validates structure offline (imports, flow modules, the
  `KUZUSHI_CPG` convention, manifest↔file consistency) — runs in every CI job.
- `test/starter-pack-compile.test.mjs` + the **`codeql-verify` CI job** install the CodeQL bundle
  and actually compile every CodeQL query against the standard library, so a wrong `*Flow` module
  name fails CI instead of erroring at query time.
- `test/starter-pack-joern.test.mjs` + the **`joern-verify` CI job** (Joern is the primary backend)
  go further: they build a real CPG from a fixture and *run* every Joern query against it, so a
  broken script (bad import, the `@main`/`importCpg` pitfall, a wrong CPG-API call) fails CI too.

Both engine jobs self-skip in the normal suite (no engine on stock runners) and run for real in
their dedicated cached CI jobs.

## Adding a query

1. Drop the `.ql`/`.sc` under `codeql/<lang>/` or `joern/`.
2. Add an entry to `manifest.json` (`ruleId`, `engine`, `language`, `cwe`, `file`, `title`).
3. `npm test` — the structure test enforces the conventions and rejects orphan files.
