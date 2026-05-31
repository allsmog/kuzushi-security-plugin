# Authoring skills & agents for kuzushi

This file is the standard for writing the markdown that drives this plugin — the
`skills/*/SKILL.md` files and the `agents/*.md` files. It is for contributors (and
for Claude when asked to add or edit a skill). It is **not** a runtime instruction.

The architecture itself (deterministic `prepare → agent → assemble`, the shared
fingerprinted `findings.json`, self-gating MCP) is documented in the README. This
file is only about how the *prose* should be written.

## Principles

1. **Explain WHY, not just WHAT.** A skill earns its place by teaching judgment the
   model doesn't already have — trade-offs, decision criteria, the failure mode it
   prevents. Don't restate tool docs; teach *when* to reach for a tool and *how to
   read the result*.
2. **Prescriptiveness proportional to risk.** Security verdicts, exploitability
   calls, and anything that promotes a finding need rigid, step-by-step enforcement
   with a closed verdict set (see `agents/threat-hunter.md`). Low-stakes helpers can
   be loose.
3. **Behavioral guidance over reference dumps.** Don't paste whole specs or CWE
   catalogs into a skill. Point at where to look it up and what to do with it.
4. **Names:** kebab-case; prefer a verb/role that says what it does. Match the
   existing pattern (`threat-hunt`, `systems-hunt`, `variant-hunt`).
5. **Keep SKILL.md scannable** (aim < 200 lines). Long methodology belongs in the
   agent file, which runs in a forked context.

## Required sections

Every `skills/*/SKILL.md` and every security `agents/*.md` must include both:

### "When NOT to use"
State the cases where this skill is the wrong tool, so it isn't fired pointlessly or
on the wrong target. Be concrete — e.g. `/systems-hunt` is not for pure web apps;
`/verify` is not for discovering new bugs; `/variant-hunt` is useless before any
finding is confirmed.

### "Rationalizations to Reject"
List the shortcuts a reviewer (human or model) tells themselves that cause **missed
findings or false confidence** — and reject each explicitly. This is the generalized
form of the Carlini doctrine already in `agents/threat-hunter.md` ("a guard exists →
marked safe, *without an attempted bypass*, is the single largest source of missed
bugs"). Each producer/verifier has its own version; write the ones specific to that
skill's job. Format as a short bulleted list of `"<the rationalization>" → <why it's
wrong / what to do instead>`.

## Additional sections for finder / verifier agents

An agent that **promotes or adjudicates a finding** (the discovery hunters and
`verifier`) must, beyond the two required sections above, also include:

### "Worked example"
The single biggest lever for turning *read the right file* into *found the bug*. Teach
by a compact, concrete walk-through — NOT a narrative essay. Mirror the three moves a
strong find-prompt uses: (a) **reasoned classification** (name the shape and *why* it is
or isn't the bug), (b) a **filled-in draft-JSON exemplar** showing the exact object to
emit (this is the highest-value part — the model copies the shape), (c) **named tactics**.
Anchor it to a real case (the `bench/cases/*` fixtures are ideal — ground-truth-aligned,
won't drift). Aim for +20–40 lines, ending in the exact `draft.*.json` shape.

### Derived-severity inputs
Do not assert a severity and expect it to stick — the finalize **derives** it
(`scripts/lib/severity.mjs`). Emit `preconditions: []` (every condition that must hold to
exploit) and `accessLevel` (minimum attacker access: `unauthenticated-remote` /
`authenticated` / `local-only` / …). The claimed `severity` becomes advisory only.

### Reference the non-findings taxonomy
Before promoting, check the candidate against the taxonomy below and **drop** matches,
recording the rule number in `exclusionRule` and a `refuteReason`. List the 2–4 rules
most relevant to the agent's domain inline; the full set is the verifier's gate.

## The false-positive taxonomy (the non-finding rules)

The numbered rules a reviewer cites when a candidate is *not* a finding. Recording the
matched rule (not just "false") makes drops auditable and tells us *why* noise appears.
The canonical set (our own wording — adapt the inline subset per agent domain):

1. **Volumetric DoS** — "send a lot" with no logic bug. Out of scope unless it's an
   algorithmic-complexity blowup or an amplification primitive.
2. **Test / fixture / dead code** — not on any production execution path.
3. **Intended design** — documented behavior, a deliberate admin escape hatch, a flag.
4. **Memory-safety in a memory-safe language** outside `unsafe`/FFI boundaries.
5. **SSRF, path-only** — only the URL path is attacker-controlled, not host/scheme.
6. **LLM-prompt input** — untrusted text that only reaches a model prompt (a separate
   threat class, not a code vuln here).
7. **Object-storage traversal** — "../" into S3/GCS keys with no hierarchical FS to escape.
8. **Trusted-operator input** — values only a trusted operator supplies (CLI, env, root config).
9. **Client-class on the server** (or vice-versa) — a server-side vuln class flagged in
   code the same user already fully controls.
10. **Outdated dependency** with no demonstrated reachable call into the vulnerable code.
11. **Weak randomness, non-security** — `Math.random()` for jitter/cache keys, not tokens.
12. **Low-impact nuisance** — log-spoofing, open redirect with no auth context, regex-inject
    on operator-only input.
13. **Missing-hardening-only** — a defense-in-depth control absent (no CSP, no SameSite) with
    no concrete exploit. Note it; don't promote it.
14. **XSS in an auto-escaping framework** with no raw-HTML escape hatch (`html_safe` /
    `dangerouslySetInnerHTML`) on the path.
15. **Unguessable token flagged predictable** — UUID/token called "IDOR/predictable" without
    showing it's actually guessable or leaked.
16. **Theoretical race / TOCTOU** — no realistic window, or process-local single-threaded state.

`refuteReason` enum (separate axis — *why* refuted): `doesnt_exist | already_handled |
implausible_trigger | intentional_behavior | misread_code | duplicate | not_actionable | n/a`.

## Determinism boundary

The agent reasons and writes a **draft** JSON; a deterministic `*-finalize.mjs` /
`*-assemble.mjs` script validates and persists it. Never put validation that must be
trustworthy in the prose — put it in the assemble script, where it can't be reasoned
around. Things that live in code, not prompts:
- verdict whitelist, min-evidence length, fingerprinting/dedup;
- **severity derivation** (`scripts/lib/severity.mjs`: precondition × access table, take
  the LOWER column, threat-model boost capped at one step) — the agent supplies inputs,
  the finalize computes the stored severity;
- **panel consensus** (`verify-panel-assemble.mjs`: majority + trigger-gate, agreeing-side
  confidence, split-vote noise-tolerance tie-break);
- **resumable checkpoints** (`scripts/lib/checkpoint.mjs`: atomic, path-confined,
  payload-from-file) for the long orchestrators.

## Licensing note

Methodology in this repo is **MIT** and must be **our own wording**. Several skills
are *inspired by* [Trail of Bits' skills](https://github.com/trailofbits/skills)
(CC-BY-SA 4.0) — ideas are fine to learn from, but do **not** paste their text into
this repo. Credit the inspiration in a one-line note where relevant.
