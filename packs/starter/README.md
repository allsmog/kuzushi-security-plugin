# Starter query pack

Curated, maintainer-authored CodeQL/Joern queries so the **first** interprocedural taint query
runs without the agent hand-writing one. `install-starter-pack` copies these into a target's
`.kuzushi/rules/` and registers them in the digest-attested pack manifest, so the codeql/joern MCP
servers will execute them (the execution gate, `assertPackRunnable`, checks the on-disk bytes
against the recorded digest). The SessionStart auto-build installs the pack when it builds the DB.

## Coverage

| CWE | Class | CodeQL | Joern |
|-----|-------|--------|-------|
| CWE-22 | Path traversal | JS, Python | — |
| CWE-78 | Command injection | JS, Python | any |
| CWE-89 | SQL injection | JS, Python | any |
| CWE-94 | Code injection | JS, Python | any |
| CWE-502 | Unsafe deserialization | JS | any |
| CWE-611 | XXE | — | any |
| CWE-918 | SSRF | — | any |

CodeQL queries use the standard-library security **flow modules** (`<Name>Flow::PathGraph`); Joern
queries are language-agnostic CPG dataflow (`reachableByFlows`) following the `KUZUSHI_CPG`
convention (see `scripts/joern/taint-flows.sc`).

## Trust & verification

Shipped entries are marked `validated.compile: true` (curated authorship) with
`validated.compileVerified: false` — the bytes are **not** machine-compiled at install time, since
no specific CodeQL/Joern version is assumed. `test/starter-pack-structure.test.mjs` validates the
queries' structure offline (imports, flow modules, the `KUZUSHI_CPG` convention, manifest↔file
consistency). To verify against a concrete engine build, run a CodeQL `query compile` / Joern
script load where the CLI is present.

## Adding a query

1. Drop the `.ql`/`.sc` under `codeql/<lang>/` or `joern/`.
2. Add an entry to `manifest.json` (`ruleId`, `engine`, `language`, `cwe`, `file`, `title`).
3. `npm test` — the structure test enforces the conventions and rejects orphan files.
