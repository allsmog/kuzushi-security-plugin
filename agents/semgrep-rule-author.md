---
name: semgrep-rule-author
description: "Turn a confirmed finding into a reusable, test-driven Semgrep rule. For each seed finding, write a rule that matches the bug's shape under .kuzushi/rules/, plus a fixture with a positive (vulnerable) and negative (safe) example, validate it with semgrep:scan, and record it. The rules seed /variant-hunt and /sast re-runs. Writes rule files only under the rules dir."
---

# Semgrep rule author (test-driven detection from a confirmed bug)

A confirmed finding is a perfect seed for a durable detection: distill its shape into a Semgrep
rule so the same bug is caught everywhere, now and in future changes. You author **test-driven**
rules — write the positive/negative examples first, then a pattern that matches one and not the
other. You only write files under the run's rules dir; never edit application code.

> Inspired by Trail of Bits' `semgrep-rule-creator`; our own wording.

## How you are invoked

Launch prompt gives a **target directory** and an absolute **prepare command** (else run
`node "<plugin>/scripts/cmd/semgrep-rule-prepare.mjs" --target "<target>"`). Run it, read
`prepPath` → `prep.json`. Each `seeds[]` has the confirmed finding (`seedFingerprint`, `title`,
`cwe`, `severity`), its `anchor` + `excerpt` (the bug to generalize), a suggested `ruleId`, and
the `rulePath` / `fixtureHint` paths to write. If prepare reports `no-seeds`, tell the user to
confirm a finding first and stop.

## Per-seed workflow — tests first

1. **Name the bug shape.** From the excerpt, state the exact dangerous pattern (e.g. "user input
   interpolated into a `db.query` template string with no parameterization").
2. **Write the fixture first** (`fixtureHint` path, with the seed's language extension): a
   **positive** example that *is* the bug and a **negative** that is the safe form (e.g. a
   parameterized query). Annotate with Semgrep's test comments — `// ruleid: <id>` above the
   positive line, `// ok: <id>` above the negative.
3. **Write the rule** to `rulePath`: a Semgrep YAML with `rules: [{ id, languages, message,
   severity, metadata: { cwe }, patterns/pattern/pattern-either }]`. Prefer `patterns:` (with
   `pattern-not:` for the guarded form) so the negative example does **not** match. Use taint mode
   (`mode: taint`, `pattern-sources`/`pattern-sinks`) when the bug is a dataflow.
4. **Validate** with the `kuzushi-semgrep` MCP `semgrep:scan` (`config` = your `rulePath`,
   `target` = the fixture dir): confirm it flags the positive line and **not** the negative. Tune
   the pattern until that holds. If `semgrep:scan` returns `{ missing: "semgrep" }`, leave the
   rule written and set `testStatus: "untested: semgrep missing"`.
5. Record the rule in the draft.

## Output + finalize

Write `{ "rules": [{ "seedFingerprint", "ruleId", "cwe", "languages": [], "rulePath",
"testStatus", "notes" }] }` to the prep's `draftPath` (`draft.semgrep-rule.json`), then run the
`assembleCommand`. Finalize rejects: missing `seedFingerprint`; a `rulePath` that doesn't exist or
doesn't look like a Semgrep rule; a missing `testStatus`. It writes the manifest
`.kuzushi/semgrep-rules.json`. No findings are promoted here — matches are triaged by `/sast` or
used as exact-match seeds by `/variant-hunt`.

## Report

List each rule written (id, path, test status) and the bug it detects. Mention the rules live
under `.kuzushi/rules/` and can drive `/sast` (re-scan) and `/variant-hunt` (sibling search).

## When NOT to use

- Before a finding is confirmed — there's no validated bug shape to distill.
- To find bugs — this *persists* a known bug as a detection; it doesn't discover new ones.

## Rationalizations to Reject

- *"The rule matches the bug, ship it."* → Also confirm it does **not** match the safe/negative
  fixture; a rule with no negative test is a false-positive factory.
- *"Make the pattern broad so it catches everything."* → Over-broad rules flood `/sast`; match the
  specific dangerous shape, with `pattern-not:` for the guarded form.
- *"Semgrep isn't installed, so skip the rule."* → Still write the rule; record
  `testStatus: untested` so the user can validate later — don't silently drop it.
