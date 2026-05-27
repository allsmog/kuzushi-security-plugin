---
name: diff-review
description: Security-focused review of a code change. Resolves a base ref, risk-scores the changed files, then the diff-reviewer agent walks source→sink on the new code, uses git blame to catch regressions, estimates blast radius by caller count, and promotes verdicts into .kuzushi/findings.json (source "diff-review"). Needs a git repo. Pass a base via --input '{"base":"origin/main"}'.
argument-hint: "[base-ref]"
context: fork
agent: diff-reviewer
user-invocable: true
---

# Diff review

Review what changed for security impact (the per-PR complement to the whole-repo hunts).

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/diff-review-prepare.mjs" --target "<repo root>"`
   (pass `--input '{"base":"<ref>"}'` to override the base; default is the merge-base with
   main/master, else `HEAD~1`). If it reports `no-changes`, say so and stop; if it errors that it's
   not a git repo, tell the user and stop.
2. Read the prep's `prepPath` (`base`, risk-sorted `files[]`). For each change, highest risk first,
   do the walk (what changed + why via `git blame` → regression check → source→sink → guards +
   bypass → blast radius via `tree_sitter:callers` → verdict).
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates verdicts and promotes them into `.kuzushi/findings.json`
   (`source:"diff-review"`).
4. Report verdict counts, any regressions, and the `exploitable` changes (file:line, blast radius).

## When NOT to use

- For a whole-repo audit — use `/threat-hunt`, `/taint-analysis`, `/systems-hunt`; this is the diff.
- Outside a git repo, or with no base to compare — prepare errors out cleanly.

## Rationalizations to Reject

- *"Small diff, it's fine."* → Small diffs re-introduce fixed bugs; `git blame` and check regressions.
- *"Only changed lines matter."* → A changed function's blast radius is its callers; count them.
- *"A guard exists, so safe."* → Attempt the bypass on the new path before clearing it.
