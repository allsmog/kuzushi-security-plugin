---
name: report
user-invocable: true
description: Render .kuzushi/findings.json into a prioritized, human-facing security report (.kuzushi/report.md, plus report.html with "html"). Deterministic transform — ranks findings "fix first" by severity × proof state × exploitability × blast radius and folds in attack chains, coverage, and provenance. No analysis. Use when asked for "a report", "a summary", "what should I fix first", or a shareable deliverable. Pass "all" to include reviewed/noise; "html" for an HTML copy.
argument-hint: "[all] [html]"
allowed-tools: Bash, Read
---

# Security report

Turn the shared findings index into the deliverable a maintainer actually reads: a
prioritized, evidence-anchored report — not raw JSON. This is the **last mile**, run
after the producers (`/sweep`, `/threat-hunt`, …) and ideally after `/verify`/`/poc`
so the proof states are populated.

Run, using the project working directory as `<cwd>` (add `--all` if `$ARGUMENTS`
contains `all`, `--html` if it contains `html`):

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/report-build.mjs" --target "<cwd>"
```

It writes `.kuzushi/report.md` (and `.kuzushi/report.html` with `--html`) and prints
`{ reportPath, findingCount, actionableCount, fixFirstCount, chainCount }`. **Read
`report.md` and paste it into the chat verbatim inside a fenced code block**, then add
at most a 2–3 line note pointing at the top item(s) to fix first. If `--html` was
requested, surface the file path (don't paste HTML).

## What it does

- **Ranks** every actionable finding with one transparent risk score (`scripts/lib/risk.mjs`):
  severity × proof state (proven > confirmed > open > lead) × memory-exploitability tier ×
  blast radius (caller count from `/code-graph`, when built) × chain membership. The
  ordering — not just the list — is the product; a proven critical with 30 callers must
  beat an open low.
- **Sections:** an executive summary (counts by severity + proof state), a **Fix first**
  list (top N by risk, with file:line evidence, remediation, and PoC/patch pointers), the
  full ranked table, **attack chains** (from `/chain`, with `C-1…` cross-refs), **coverage**
  (from `/sweep`'s coverage map — the honest "what wasn't scanned" set), and a scope/
  provenance footer (policy profile, toolchain digest, producers run).
- By default shows only **actionable** findings (not reviewed/noise/remediated); `all`
  includes them. Resolved counts always appear in the footer so nothing is silently dropped.

It makes **no security decision** — it only orders and renders existing verdicts. The
`findings.json` record stays the source of truth.

## When NOT to use

- **Before any findings exist** — there is nothing to report. Run a producer first
  (`/sweep`, `/threat-hunt`, `/taint-analysis`, …). The command tells you so and exits.
- **To find, confirm, or triage bugs** — `/report` is read-only rendering. Use the
  producers to find, `/verify` + `/poc` to confirm. A finding only reaches "Fix first"
  with the proof state those steps assign.
- **For machine/CI consumption** — use `/export-sarif` (SARIF 2.1.0). `/report` is for humans.
- **To change a verdict or severity** — edit the finding via its producer/verifier;
  the report reflects `findings.json`, it does not override it.

## Rationalizations to Reject

- "It's just formatting, so order doesn't matter." → **Wrong — the ranking IS the
  value.** A flat list re-creates the overwhelm the report exists to remove. Trust the
  risk score; if it ranks something wrong, fix the *finding's* proof state/severity
  upstream, don't hand-reorder the report.
- "High severity → list it first." → Severity alone is not risk. An *unproven* critical
  can sit below a *proven* high; a bug reachable from 200 callers outranks a dead-code
  one. Severity is one factor, weighted by how established and how reachable the bug is.
- "No coverage map, so I'll imply we scanned everything." → Never. If `/sweep` didn't run,
  there's no coverage section — say coverage is unknown, don't imply completeness. The
  report's credibility is that it never over-claims.
- "I'll write a nicer remediation than the finding has." → Don't invent fixes. Render the
  remediation the finding/`/fix`/`/mem-exploitability` actually carries; if there is none,
  show the next check. A fabricated fix is worse than an honest gap.
- "Reviewed/noise are gone, so they're handled." → They're *hidden by default*, still
  counted in the footer. If a reader needs to audit dismissals, run `/report all` — don't
  pretend dismissed findings don't exist.
