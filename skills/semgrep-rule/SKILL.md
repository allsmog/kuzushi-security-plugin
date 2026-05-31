---
name: semgrep-rule
description: Turn confirmed findings into reusable, test-driven Semgrep rules under .kuzushi/rules/. For each seed, the semgrep-rule-author agent writes a positive/negative fixture and a rule that matches the bug shape, validates it with semgrep, and indexes it. The rules seed /variant-hunt and /sast re-runs. Requires a confirmed finding first.
context: fork
agent: semgrep-rule-author
user-invocable: false
---

# Semgrep rule generation

Distill the repo's confirmed bugs into durable Semgrep detections.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/semgrep-rule-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxSeeds":6}'`). If it reports `no-seeds`, tell the user to confirm a
   finding first (`/threat-hunt` → `/verify`, or `/taint-analysis` / `/systems-hunt`) and stop.
2. Read the prep's `prepPath`. For **each** seed, write the fixture first (positive + negative),
   then a rule to its `rulePath`, then validate with `semgrep:scan` (config = the rule, target =
   the fixture) so it flags the positive and not the negative. If semgrep is missing, leave the
   rule written and mark `testStatus: untested`.
3. Write the `{ rules: [...] }` bundle to the prep's `draftPath`, then run the `assembleCommand` —
   it validates the rule files exist + look like Semgrep rules and writes
   `.kuzushi/semgrep-rules.json`.
4. Report each rule (id, path, test status) and note the rules can drive `/sast` and `/variant-hunt`.

## When NOT to use

- Before a finding is confirmed — there's no validated bug shape to turn into a rule.
- To discover bugs — this persists a *known* bug as a reusable detection.

## Rationalizations to Reject

- *"It matches the bug, done."* → Confirm it does **not** match the safe/negative fixture too; no
  negative test ⇒ a false-positive factory.
- *"Broad pattern catches more."* → Match the specific dangerous shape with `pattern-not:` for the
  guarded form; over-broad rules drown `/sast`.
- *"No semgrep, skip it."* → Write the rule and mark `untested`; don't silently drop it.
