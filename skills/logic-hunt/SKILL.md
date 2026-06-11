---
name: logic-hunt
description: Adversarial business-logic and invariant-violation hunt. For each intended-behavior invariant (from /deep-context) and logic-bug code shape, the logic-hunter agent tries to construct an operation sequence that violates the property — broken atomicity, out-of-order state transitions, authorization-by-omission, replay, business-rule abuse — then assigns a verdict from a closed set with file:line evidence. Promotes violations into findings.json. Strongest after /deep-context.
context: fork
agent: logic-hunter
user-invocable: true
---

# Logic Hunt

Find the bugs taint and SAST structurally cannot: **logic flaws**. There's no injection
token to grep for — the code is syntactically fine and does the wrong *thing*. This track
hunts broken atomicity, skippable state transitions, authorization-by-omission, replay, and
business-rule abuse (negative amounts, rounding theft, quantity underflow) by taking a
property the system should uphold and adversarially trying to break it.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/logic-hunt-prepare.mjs" --target "<repo root>"`.
   It seeds candidates from the **system invariants** `/deep-context` extracted (the strongest
   seed) plus ripgrep probes for logic-bug-prone shapes (money, state assignment, transactions,
   ownership checks, check-then-act, idempotency). If it warns there are no deep-context
   invariants, run `/deep-context` first for materially better coverage.
2. For each candidate the logic-hunter agent states the intended property, finds the operations
   that touch it, and **attempts a concrete violation** — then assigns `violation` / `holds` /
   `not-an-invariant` / `needs-more-evidence`.
3. Write the draft to `draftPath` and run the `assembleCommand`. The host validates the closed
   verdict set (a `holds` must name the enforcement; a `violation` must carry the ordered break
   scenario + evidence) and promotes `violation` verdicts into `findings.json` (status `open`).
4. Report the violations: the property, the operation sequence that breaks it, and who can drive it.

## When NOT to use

- For injection / memory-safety bugs — use `/threat-hunt`, `/taint-analysis`, `/systems-hunt`.
  Logic-hunt is for behavioral properties, not tainted source→sink flows.
- On a stateless library with no business rules or state machine — there's little to violate;
  the taint and fuzz tracks fit better.
- To prove exploitability — a `violation` is a static argument; `/verify` and `/poc` carry it to
  empirical proof.

## Rationalizations to Reject

- *"There's an authorization check, so it's fine."* → Logic bugs hide in the path that *lacks* the
  check, or where it's applied to the wrong object. Find the absent guard, don't admire the present one.
- *"The amount is a validated number, so the math is safe."* → Try negative, zero, overflow, and
  precision/rounding. "Is a number" is not "is in range".
- *"It's in a transaction, so it can't half-apply."* → Check the isolation level and for effects
  (emails, external calls, cache writes) that escape the transaction boundary.
- *"No invariants were extracted, so there's nothing to hunt."* → The probes still seed real leads;
  but run `/deep-context` first — an explicit intended-behavior invariant is the highest-yield seed.
