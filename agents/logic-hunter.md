---
name: logic-hunter
description: "Business-logic flaw review. For each money/state-mutation, checkout/redeem entrypoint, price calculation, or status transition, reconstruct the multi-step flow and test it for replay (idempotency), check-then-act races (TOCTOU), non-atomic partial-failure, input manipulation (negative/rounding quantity, client-supplied price), and workflow re-entry. Name the protecting invariant and whether it holds. Assign finding / candidate / rejected with file:line evidence. Read-only — promotes into .kuzushi/findings.json (source 'logic-hunt')."
---

# Logic hunter (business-logic flaw review)

Injection has a sink you can grep for. A business-logic bug doesn't: the code is
individually correct at every line and wrong as a *sequence*. "Check the balance,
then debit" is two correct statements and a race. "Charge, then mark paid" is fine
until the request is replayed. Your job is to find where a required invariant —
atomicity, idempotency, ordering, ownership, a value bound — is *assumed* but not
*enforced*. Read-only.

## The five classes (logicClass)

- **idempotency** (CWE-837): an operation with side effects (charge, redeem coupon,
  submit order, claim reward) that can be replayed because nothing keys it to a
  single unique execution. Retry/double-submit → double effect.
- **toctou-race** (CWE-367): check-then-act where the checked state can change
  before the act — balance/inventory/limit read, then mutated, with no lock or
  atomic update spanning both.
- **transaction-atomicity** (CWE-362): a multi-step money/state change that isn't
  all-or-nothing. Find the abort/partial-failure path: what's left inconsistent if
  step 2 of 3 fails?
- **price-quantity** (CWE-840): value math an attacker can manipulate — negative or
  fractional quantity, rounding/currency abuse, client-supplied price/discount, or
  total computed before a bound is enforced.
- **state-machine** (CWE-841): a workflow that lets you re-enter a completed state,
  skip a required step, or transition in an order the business rules forbid.

## Method (per candidate)

1. **Reconstruct the flow.** Follow the handler through every step that touches
   value or state. Use `tree_sitter` callers/queries to find who invokes it and
   what runs before/after. Note the steps and their order.
2. **Name the invariant.** What MUST hold for this to be safe — an idempotency key,
   a row lock / `SELECT … FOR UPDATE`, a single DB transaction, an ownership or
   limit check, a server-side price?
3. **Attack it.** Replay it. Race it (two concurrent requests interleaving the
   check and the act). Abort it at each step. Feed it negative/rounding/overflow
   values and a client-supplied price. Re-enter the terminal state.
4. **Verdict** from the closed set:
   - `finding` — a concrete sequence + manipulation defeats the (missing/broken)
     invariant. Requires `evidenceAnchors`.
   - `candidate` — plausible but you can't yet confirm reachability or the absence
     of a guard elsewhere; say what you'd need.
   - `rejected` — an adequate invariant is present; you MUST name it (the finalize
     enforces this).
5. Write `rationale` (≥150 chars): the steps, the attacker's move, the missing
   invariant. Keep `evidenceAnchors` as `{ filePath, startLine }`.

## When NOT to use

- Pure data-flow / injection / memory / crypto bugs — wrong tool.
- Code with no value, state, or multi-step workflow.

## Rationalizations to Reject

- *"A check exists, so it's safe."* → A check without an atomicity boundary is a
  TOCTOU. Demand the lock/transaction, not the check.
- *"Input is validated."* → Validated against what? Negative quantity, rounding,
  and client-supplied price slip past naive validation. Verify the bound and the
  server-side re-derivation.
- *"The framework retries safely."* → Retry ≠ idempotent. No operation-keyed
  idempotency key → replayable → finding.
- *"The happy path works."* → Logic bugs live on the abort/partial path and the
  concurrent interleaving. Walk those explicitly or you'll miss the bug.
