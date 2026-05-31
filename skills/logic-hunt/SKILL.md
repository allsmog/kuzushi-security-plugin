---
name: logic-hunt
description: Business-logic flaw review. Finds idempotency gaps (replayable payments/actions), check-then-act / TOCTOU races, non-atomic multi-step transactions, price/quantity manipulation, and workflow state-machine abuse — the bugs taint and SAST are structurally blind to. Promotes verdicts into .kuzushi/findings.json (source "logic-hunt").
context: fork
agent: logic-hunter
user-invocable: false
---

# Logic hunt

Hunt business-logic vulnerabilities — the class that has no dangerous-sink to grep
for, where the bug is the *sequence* and the *missing invariant*, not a tainted
string reaching `exec`.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/logic-hunt-prepare.mjs" --target "<repo root>"`.
2. Read the prep's `prepPath`. Each candidate is a *shape* (a money/state mutation,
   a checkout/redeem entrypoint, a price calculation, a status transition) — not a
   bug yet. For each, reconstruct the multi-step flow and ask: can an attacker
   **replay** it, **race** it, **abort it partway**, or **manipulate the inputs**
   (negative quantity, rounding, currency) to gain value or skip a required step?
   Name the invariant that should protect it (idempotency key, row lock, DB
   transaction, ownership/limit check) and check whether it's actually there.
3. Write `{ candidates: [...] }` with a `verdict` (finding / candidate / rejected),
   a `logicClass`, a `rationale`, and `evidenceAnchors` to the prep's `draftPath`,
   then run the `assembleCommand`.
4. Report the `finding`s: the flow, the manipulation, and the missing invariant.

## When NOT to use

- For injection / memory-safety / crypto bugs — use `/taint-analysis`,
  `/systems-hunt`, `/crypto-review`. Logic-hunt is for value/workflow abuse, not
  tainted data flow.
- On code with no transactions, money, state machines, or multi-step workflows
  (e.g. a pure parsing library) — there's nothing for it to reason about.
- To confirm an already-found logic bug — that's `/verify` / `/poc`.

## Rationalizations to Reject

- *"There's a check, so it's safe."* → A balance check before a debit is worthless
  if a concurrent request passes the same check first (TOCTOU). Demand the
  atomicity boundary (lock / `SELECT … FOR UPDATE` / transaction), not just a check.
- *"It validates the input, so quantity is fine."* → Did it reject **negative** and
  rounding-abusable values, and re-derive price server-side? Client-supplied price
  or unsigned-but-not-really quantities are the classic exploit.
- *"Retries are handled by the framework."* → Retry handling ≠ idempotency. Without
  an idempotency key keyed to the *operation*, a double-submit charges twice. Name
  the key or it's a finding.
- *"The happy path is correct."* → Logic bugs live on the abort/partial path:
  reserve inventory → charge → card declines → inventory never released. Walk the
  failure branches, not just success.
