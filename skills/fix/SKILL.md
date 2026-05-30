---
name: fix
description: Generate and PoC⁺-validate a patch for each confirmed/proven finding. The fixer agent writes a minimal defensive unified diff plus functional and semantic checks; the host applies it to a SANDBOX COPY, re-runs the existing PoC harness, the functional check, and the semantic oracle check for supported CWEs. A patch is "validated" only if all required gates pass. The working tree is never touched until you explicitly approve the apply step. Requires confirmed/proven findings (run /verify and /poc first).
context: fork
agent: fixer
user-invocable: true
---

# Patch generation + PoC⁺ validation

Turn the repo's confirmed/proven findings into **validated** fixes. Requires findings at
`confirmed`/`proven` in `.kuzushi/findings.json` — run `/verify` (and `/poc` for empirical
harnesses) first.

**PoC⁺ moat:** a patch is `validated` only when it stops the existing PoC harness, passes a
functional/regression check, and passes the semantic oracle check for supported CWEs. Validation
runs against a **sandbox copy** — your working tree is never modified until you explicitly approve
the apply step.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fix-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxCandidates":8}'`). If there are no fixable findings, tell the user
   to run `/verify` and `/poc` first, and stop. Read the prep's `prepPath`.
2. For **each** candidate, root-cause the bug and write a **minimal defensive unified diff** +
   a `functionalCheck`, using each candidate's `findingFingerprint` verbatim. If the candidate has
   `semanticOracle`, also write a runnable `semanticCheck` that exercises its positive/negative
   controls; supported CWE fixes are not `validated` without that semantic check. Set
   `harnessLinkage` honestly. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`.
   Write only under the run dir — never edit application code here.
3. Run the `assembleCommand` (finalize). It applies each diff to a sandbox copy, re-runs the PoC
   (expecting NO crash), **re-attacks the patch** (re-runs the fuzz harness with the variant corpus
   you seeded, and replays every other finding's PoC that lives in the same function — any
   reproduced crash ⇒ `exploit-still-fires`, no status advance), runs the functional check, runs the
   semantic check for supported CWEs, and assigns the patch verdict. The re-attack **executes code in
   the sandbox**; add `--trust-local` only if the user consents to a local (non-Docker) run. Report
   the verdict per finding.
4. **Apply step (explicit approval, one finding at a time).** For each `validated` finding, ask
   the user with AskUserQuestion whether to apply it to the working tree ("Apply patch" / "Skip").
   On approval, run exactly
   `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fix-apply.mjs" --target "<root>" --fingerprint "<fp>"`
   — the user will see a permission prompt; that is the consent gate. On success, report the
   applied files and the rollback command (`git apply -R …`). **Never** apply a verdict other than
   `validated` (the script refuses anyway).

## When NOT to use

- Before findings are confirmed/proven — run `/verify` and `/poc` first.
- When you can't accept code execution — validation builds/runs harnesses in a sandbox.
- To auto-fix en masse — each apply is individually approved.

## Rationalizations to Reject

- *"The original PoC stops, so the patch is good."* → That is one shape through one caller. Seed the
  variant corpus and let the re-attack (variants + same-function sibling replay) try to break it
  before you trust the `validated` verdict.
- *"A non-`validated` verdict is close enough to apply."* → Only `validated` advances to `patched`,
  and `fix-apply` refuses anything else. Re-root-cause instead of forcing the apply.
- *"Skip the sandbox, the diff obviously holds."* → The sanitizer/exit-signal in the sandbox is the
  verdict, not your reading of the diff. No run ⇒ no `validated`.
