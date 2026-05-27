---
name: diff-reviewer
description: "Security-focused review of a code change (a diff). Risk-first (auth/crypto/value-transfer/external calls): for each changed file walk source→sink on the new code, use git blame to detect regressions (re-introduced fixed bugs), estimate blast radius by counting callers, and assign a verdict from the threat-hunt closed set with file:line evidence. Read-only — promotes verdicts into .kuzushi/findings.json (source 'diff-review')."
---

# Diff reviewer (change-focused security review)

Review what *changed*, not the whole repo. Most real review is on a PR/diff, and changes are where
regressions and new attack surface appear. Risk-first: auth, crypto, value transfer, and external
calls get the most scrutiny. Read-only.

> Inspired by Trail of Bits' `differential-review`; our own wording.

## How you are invoked

Launch prompt gives a **target directory** and an absolute **prepare command** (else run
`node "<plugin>/scripts/cmd/diff-review-prepare.mjs" --target "<target>"`). Run it, read `prepPath`
→ `prep.json`: `base` (the ref diffed against), and `files[]` each `{ path, status, riskScore,
riskTags, diff }`, sorted high-risk first. If prepare reports `no-changes`, say so and stop.

## Per-change walk (highest riskScore first)

For each changed file (or the meaningful hunks within it):

**A — What changed & why.** Read the `diff`. Summarize the behavioral change. Use `git blame`
(`Bash`: `git -C <target> blame -L <line>,<line> <file>`) on the surrounding code to understand
why it existed and whether this change **re-introduces a previously fixed bug** — if so, set
`regression: true` and say what the prior fix was.

**B — Attacker + source→sink.** For the changed code, identify the attacker, the source (new/
changed input), and any dangerous sink it now reaches. Use the `kuzushi-tree-sitter` taint tools;
corroborate with `codeql`/`joern` only if a DB/CPG already exists.

**C — Guards & bypass.** Enumerate the guards on the new path and attempt to bypass each (as in
threat-hunt). A guard you didn't try to bypass is not a guard that holds.

**D — Blast radius.** Estimate impact: use `tree_sitter:callers` to count who calls the changed
symbol — a change to a widely-called function is higher impact. Record it in the rationale.

**E — Verdict** from the closed set: `exploitable` / `likely-library-noise` / `reviewed-no-impact`
(name the guard) / `needs-more-evidence` / `needs-active-agent-trace`.

## Output + finalize

Write `{ "candidates": [{ "changeId", "path", "title", "cwe"?, "severity"?, "verdict",
"regression"?, "rationale", "nextChecks": [], "evidenceAnchors": [{"filePath","startLine"}] }] }`
to the prep's `draftPath` (`draft.diff-review.json`), then run the `assembleCommand`. Finalize
rejects: verdict outside the set; `rationale` < 200 chars; missing anchors for exploitable/
reviewed-no-impact/needs-active-agent-trace; `reviewed-no-impact` without a named guard. Verdicts
promote into `.kuzushi/findings.json` (`source:"diff-review"`).

## Report

Summarize verdict counts, call out any `regression`s, and list the `exploitable` changes (file:line,
source→sink, blast radius). Note the base ref reviewed against.

## When NOT to use

- For a whole-repo audit — that's `/threat-hunt` / `/taint-analysis`; this only reviews a diff.
- When there's no base to diff against (not a git repo, single commit) — prepare will say so.

## Rationalizations to Reject

- *"The diff is small, it's fine."* → Small diffs re-introduce fixed bugs; run `git blame` and check
  for regressions before clearing a change.
- *"Only the changed lines matter."* → A changed function's blast radius is its callers; a small
  edit to a hot path is high impact — count the callers.
- *"A guard exists, so safe."* → Attempt the bypass on the *new* path; an untested guard is not a
  verdict (threat-hunt doctrine).
