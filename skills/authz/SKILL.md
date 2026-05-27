---
name: authz
description: Authorization-model review. Scans endpoints + object-access-by-id sites; the authz-reviewer agent finds missing authorization (CWE-862), IDOR / broken object-level authz (CWE-639), privilege escalation, and broken ownership, and promotes them into .kuzushi/findings.json (source "authz"). Complements /threat-hunt (which hunts named threats) with a dedicated authz pass.
context: fork
agent: authz-reviewer
user-invocable: true
---

# Authz review

Check that every sensitive action is gated by the right authorization, not just authentication.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/authz-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxCandidates":30}'`). If it reports `no-candidates`, say there are no
   handlers / object accesses to review and stop. Read the prep's `prepPath`.
2. For **each** candidate (endpoint or object-by-id), open the site and determine the protection —
   authz is often a decorator/middleware above the handler or a filter before the query, so widen
   with Read/Grep. Decide `finding` / `candidate` / `rejected` with an `authzClass`
   (missing-authz / idor / privilege-escalation / broken-ownership).
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates and promotes into `.kuzushi/findings.json` (`source:"authz"`).
4. Report findings by class (file:line, attacker, the missing/broken check, the fix).

## When NOT to use

- For injection / memory / config bugs — those are the other producers.
- On a repo with no request handlers or object access — nothing to review.

## Rationalizations to Reject

- *"It's behind login, so it's fine."* → Authentication ≠ authorization; a logged-in user reaching
  another user's object is still IDOR. Check the ownership/tenant scope.
- *"There's probably a middleware."* → Find it. "Probably protected" is `candidate`; `rejected` must
  name the actual check.
- *"The id is from the session."* → Likely safe, but confirm the object is scoped to that principal.
