---
name: fix
description: Generate and PoC⁺-validate a patch for each confirmed/proven finding. The fixer agent writes a minimal defensive unified diff + a functional check; the host applies it to a SANDBOX COPY, re-runs the existing PoC harness (must no longer fire) and the functional check (must still pass) — a patch is "validated" only if it stops the exploit AND preserves behavior. The working tree is never touched until you explicitly approve the apply step. Requires confirmed/proven findings (run /verify and /poc first).
context: fork
agent: fixer
user-invocable: true
---

# Patch generation + PoC⁺ validation

Turn the repo's confirmed/proven findings into **validated** fixes. Requires findings at
`confirmed`/`proven`/`open+exploitable` in `.kuzushi/findings.json` — run `/verify` (and `/poc`
for empirical harnesses) first.

**PoC⁺ moat:** a patch is `validated` only when it BOTH stops the existing PoC harness AND passes
a functional/regression check. Validation runs against a **sandbox copy** — your working tree is
never modified until you explicitly approve the apply step.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fix-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxCandidates":8}'`). If there are no fixable findings, tell the user
   to run `/verify` and `/poc` first, and stop. Read the prep's `prepPath`.
2. For **each** candidate, root-cause the bug and write a **minimal defensive unified diff** +
   a `functionalCheck`, using each candidate's `findingFingerprint` verbatim. Set `harnessLinkage`
   honestly. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`. Write only under
   the run dir — never edit application code here.
3. Run the `assembleCommand` (finalize). It applies each diff to a sandbox copy, re-runs the PoC
   (expecting NO crash), runs the functional check, and assigns the patch verdict. Add
   `--trust-local` only if the user consents to a local (non-Docker) run. Report the verdict per
   finding.
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
