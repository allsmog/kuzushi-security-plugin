# Hardening Claude Code for security work

kuzushi opens **source you may not trust** — that's the whole point of a security
review. That changes the threat model for *your own* Claude Code session: an
attacker-supplied repo can try to steer the agent into reading your credentials,
or ship its own MCP server config. This page lists the guardrails kuzushi can
enforce on its own, plus the user-level settings you should add yourself.

## What kuzushi enforces (no setup needed)

The plugin ships `PreToolUse` hooks (`hooks/hooks.json`) that block:

- **`rm -rf`** — irreversible deletes (suggests `trash` instead).
- **`git push` to `main`/`master`** — pushes should go through a branch + PR.
- **Reads of secret paths** — `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`,
  `~/.kube`, gcloud, Docker config, `.npmrc`/`.pypirc`/`.netrc`,
  `~/.git-credentials`, the macOS Keychain, and crypto wallets — via `Read`,
  `Edit`, `Write`, or `Bash` (e.g. `cat ~/.ssh/id_rsa`).

These are guardrails against the common dangerous shapes, not a sandbox. They
**fail open**: if a hook errors, the tool call is allowed, so the guardrail can
never wedge your session.

## Tool-boundary policy (analyzer queries & working-tree writes)

The analyzer MCP servers (`codeql:query`, `joern:query`) execute queries with the
host's privileges, and `/fix` can write to your tree. A **policy plane** governs
those surfaces. The shipped default (`policy.default.json` at the plugin root) is
**non-breaking** and always-on for two controls:

- **Path confinement** — a CodeQL `.ql` file or Joern CPG path must resolve under
  the target repo, the plugin dir, or the OS temp dir. A query pointing at
  `/etc/...` or `~/.ssh/...` is refused before anything runs.
- **Inline-script size cap** — Joern scripts over `mcp.maxQueryBytes` (200 KB) are
  refused.

One control is **configurable** and defaults to permissive so existing analysis
keeps working:

- **`mcp.rawQuery`** — `"allow"` (default) · `"require-approval"` · `"deny"`. A
  *raw* query is one not drawn from the validated rule pack (`.kuzushi/rules/`,
  produced by `/rule-synth` and digest-attested). Under `require-approval`, a raw
  query is refused unless a `.kuzushi/.approvals/raw-query` marker exists; under
  `deny`, only pack queries run.

Override per-repo by dropping a partial `<repo>/.kuzushi/policy.json` (shallow-
merged over the default), e.g. to lock a CI run down:

```json
{ "mcp": { "rawQuery": "require-approval" }, "git": { "apply": "deny" } }
```

Run `/doctor` to see the effective policy (and its digest). Every run artifact is
also stamped with a `provenance` block (`toolchainDigest`, `repoDigest`,
`scopeDigest`, `policyDigest`) so a result is reproducible and auditable.

## What you should set yourself

A plugin **cannot** set Claude Code permissions — those live in *your*
`~/.claude/settings.json`. Merge this in for defense in depth:

```jsonc
{
  // Do NOT auto-load MCP servers a target repo ships in its own .mcp.json.
  // Critical when you open untrusted code: a malicious repo could otherwise
  // register an MCP server that runs on your machine. Approve project servers
  // explicitly with `/mcp` instead.
  "enableAllProjectMcpServers": false,

  "permissions": {
    "deny": [
      "Read(~/.ssh/**)",
      "Read(~/.gnupg/**)",
      "Read(~/.aws/**)",
      "Read(~/.azure/**)",
      "Read(~/.kube/**)",
      "Read(~/.config/gcloud/**)",
      "Read(~/.npmrc)",
      "Read(~/.pypirc)",
      "Read(~/.netrc)",
      "Read(~/.git-credentials)",
      "Read(~/Library/Keychains/**)"
    ]
  },

  // Optional: opt out of telemetry / error reporting / surveys.
  "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_BUG_COMMAND": "1"
  }
}
```

The `permissions.deny` block overlaps the secret-read hook on purpose: the hook
is plugin-scoped and travels with kuzushi; the settings rule is enforced by
Claude Code itself and applies everywhere. Use both.

> Inspired by Trail of Bits' [`claude-code-config`](https://github.com/trailofbits/claude-code-config),
> adapted to the fact that kuzushi's job is to read untrusted repositories.
