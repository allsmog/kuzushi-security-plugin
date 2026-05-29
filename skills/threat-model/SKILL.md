---
name: threat-model
description: Build or regenerate the PASTA threat model for the current repository. Runs the threat-modeler subagent through the PASTA phases (S1 Objectives → S2 Scope → S3 Decomposition → S4 Threats) and writes .kuzushi/threat-model.json plus an ASCII data-flow diagram.
context: fork
agent: threat-modeler
user-invocable: true
---

# Regenerate the PASTA threat model

Build (or regenerate, overwriting any existing one) the PASTA threat model for this
repository.

1. Run the prepare step to open a run and get the stage-file paths + scope inputs:
   `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/threat-model-prepare.mjs" --target "<repo root>"`
   (use the project's working directory as the target).
2. Work the PASTA phases in order — S1 Objectives → S2 Scope → S3 Decomposition → S4
   Threats — writing each `pasta-s*.json` in the schema your agent definition specifies.
   Gather evidence with `tree_sitter:*` (AST, taint sources/sinks, callers) and ambient LSP
   while reading files. If `.kuzushi/deep-context.json` or `code-graph.json` exist (the deeper
   MAP passes), read them for grounded modules / trust boundaries / blast radius instead of
   re-deriving. Use `codeql:query` / `joern:query` only if a database/CPG already exists.
   **Do NOT run semgrep** — SAST scanning is out of scope for threat modeling.
3. Run the assemble step it prints to persist `.kuzushi/threat-model.json` and render the
   ASCII data-flow diagram.
4. Report a brief summary (threat counts by category + top threats), then paste the ASCII
   data-flow diagram from `.kuzushi/threat-model-dfd.txt` verbatim **inside a triple-backtick
   fenced code block** (```). Mandatory — it's column-aligned ASCII and breaks if pasted as
   prose. Paste the file contents as-is; do not re-draw or summarize the diagram.

> **MAP depth.** The deeper map passes — `deep-context` (line-by-line system model),
> `code-graph` (caller counts / blast radius), `threat-intel` (CVEs → invariants), `dfd`, and
> `invariant-test` — are part of this phase, not separate commands. They're pulled in here when
> they add signal; on a large or unfamiliar codebase, a `deep-context` pass first yields a richer
> model (ask for it and it runs). `/threat-intel` + `/invariant-test` follow the model when you
> want version-checked CVE coverage.

## When NOT to use

- To find or confirm concrete vulnerabilities — the model names *threats* to investigate;
  `/threat-hunt`, `/taint-analysis`, and `/systems-hunt` do the finding.
- To run SAST — semgrep is explicitly out of scope here (step 2).

## Rationalizations to Reject

- *"This is a small app, the data-flow diagram can be rough."* → Trust boundaries and data flows
  are what every downstream stage keys off; a vague S3 weakens the whole pipeline.
- *"I'll list the obvious threats and move on."* → Cover each STRIDE category against each trust
  boundary; the threat you skip naming is the one nobody hunts.
- *"I can infer the architecture without reading the code."* → Anchor decomposition in actual
  files (tree-sitter / LSP), not assumptions about how the framework "usually" works.
