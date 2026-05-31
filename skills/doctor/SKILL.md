---
name: doctor
user-invocable: true
description: Run kuzushi preflight diagnostics — Node dependencies, plugin MCP server health, and which analysis CLIs and LSP servers are installed, with exact install commands for anything missing. Use when tooling shows as missing or MCP servers won't connect.
allowed-tools: Bash
---

# kuzushi doctor

Run the plugin's diagnostics and report the result to the user.

Execute:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/doctor.mjs"
```

Then relay its output verbatim (it's already a readable table). If anything is marked
`✗`, surface the exact `install:` command the report prints for it. Note the distinction it
draws for MCP servers: **server ✓** means the plugin's Node server connects; **CLI ✓** means
the external tool it drives (codeql, joern, semgrep, …) is installed. A server can be ready
while its CLI is missing — those tools return a structured "missing" response until the CLI
is installed.

## When NOT to use

- To *install* anything — doctor only reports status; use `/install` to fix what's `✗`.
- To build the semantic indexes — that's `/build-databases`.
