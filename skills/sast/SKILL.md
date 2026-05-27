---
name: sast
description: Semgrep-driven SAST pass — scan the repo with semgrep, then triage each hit against the source as finding / candidate / rejected (scanner hits are leads, not findings). Promotes the kept ones into .kuzushi/findings.json (source "sast"). Needs semgrep installed.
context: fork
agent: sast-triager
user-invocable: true
---

# SAST (semgrep scan → triage)

Run a semgrep pass and triage the hits into the findings index.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/sast-prepare.mjs" --target "<repo root>"`. Read
   the prep's `prepPath`.
2. Call the `semgrep:scan` MCP tool (`config` from prep, default `"auto"`). If semgrep is missing,
   tell the user to `/install` it (or `pip install semgrep`) and stop.
3. For each hit worth considering, **read the source** and decide `finding` / `candidate` /
   `rejected` with file:line evidence — don't promote a hit you didn't read.
4. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates verdicts and promotes them into `.kuzushi/findings.json`
   (`source:"sast"`).
5. Report the scan + triage counts and list the `finding`s (ruleId, CWE, file:line).

## When NOT to use

- Without semgrep installed — there's nothing to scan.
- As your only pass — semgrep is pattern breadth; it misses logic/authz/memory bugs. Pair with
  `/threat-hunt`, `/taint-analysis`, and `/systems-hunt`.

## Rationalizations to Reject

- *"Semgrep flagged it ⇒ finding."* → Hits are leads; confirm attacker reach + missing guard in
  the source before promoting.
- *"Mark everything candidate to be safe."* → Triage each; an undifferentiated pile helps no one.
- *"Test/vendored hit, drop it silently."* → `rejected` with a reason, so it's auditable.
