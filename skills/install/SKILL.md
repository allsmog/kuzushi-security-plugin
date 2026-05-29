---
name: install
user-invocable: false
description: Install/vendor the analysis tooling for this repo's detected languages — LSP servers (rust-analyzer, clangd, jdtls) and MCP backend CLIs. Pass a tool name to install a specific one, including the heavy ones (e.g. /install codeql, /install joern). Use when /doctor shows tools missing.
argument-hint: "[tool|all]"
allowed-tools: Bash
---

# Install kuzushi tooling

Install the language-relevant tooling for the current repository (vendors prebuilt binaries
into the plugin where possible, runs native installers otherwise). Choose the command based
on the argument the user passed (`$ARGUMENTS`); use the project working directory as `<cwd>`:

- **A specific tool** (e.g. `codeql`, `joern`, `clangd`) — installs just that one, including
  heavy ones:
  `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/install-tooling.mjs" --target "<cwd>" --only $ARGUMENTS --approved`
- **`all`** — everything relevant including the heavy codeql/joern (~1–3 GB):
  `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/install-tooling.mjs" --target "<cwd>" --include-heavy --approved`
- **No argument** — the light, language-relevant tools only (no GB-scale downloads):
  `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/install-tooling.mjs" --target "<cwd>" --approved`

Then relay the JSON result: what was `installed`, what `failed` (show the reason / install
hint), and what `needsConfirm` (heavy tools you can install by name). Warn that heavy
downloads (codeql ~1 GB, joern ~2 GB) take a while, and that jdtls/joern need system Java,
gopls needs Go, and semgrep needs Python. Suggest `/doctor` to confirm the final status.

## When NOT to use

- To build the CodeQL DB / Joern CPG — installing the CLI is `/install`; building the indexes is
  `/build-databases`.
- To check what's already present — that's `/doctor` (don't reinstall blindly).
