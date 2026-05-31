---
name: crypto-review
description: Crypto-misuse review — non-constant-time comparison of secrets (timing side-channels), missing/compiler-elidable zeroization of secrets, and non-cryptographic RNG used to mint secrets. The crypto-reviewer agent confirms each candidate handles a secret and promotes real issues into .kuzushi/findings.json (source "crypto-review"). Distinct from /sast (injection) and /sharp-edges (API design).
context: fork
agent: crypto-reviewer
user-invocable: false
---

# Crypto review

Find the crypto-implementation footguns that look fine but leak or weaken secrets.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/crypto-review-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxCandidates":30}'`). If it reports `no-candidates`, say so and stop.
   Read the prep's `prepPath`.
2. For **each** candidate, open the site and **first confirm the value is secret-derived**, then
   assess by category: timing-side-channel (variable-time compare of a secret), missing-zeroization
   (secret not securely wiped / elidable `memset`), or weak-crypto-rng (non-CSPRNG minting a
   token/key/nonce). Decide `finding` / `candidate` / `rejected`.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates verdicts/categories and promotes them into
   `.kuzushi/findings.json` (`source:"crypto-review"`).
4. Report findings by category (file:line, the leak/weakness, and the constant-time / secure-zero /
   CSPRNG fix to use).

## When NOT to use

- On code with no cryptographic / secret handling — nothing to review.
- For injection or API-design misuse — that's `/sast`, `/taint-analysis`, and `/sharp-edges`.

## Rationalizations to Reject

- *"Just a string compare."* → If a side is a secret (MAC/token/hash), a variable-time compare leaks
  it; confirm secret-derivation before clearing.
- *"memset wipes it."* → A plain `memset` on a dying buffer is often optimized away; only a secure-zero
  primitive counts.
- *"The RNG is random enough."* → `Math.random`/`rand()` are predictable; for secrets that's a finding.
