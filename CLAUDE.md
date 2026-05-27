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

## Determinism boundary

The agent reasons and writes a **draft** JSON; a deterministic `*-finalize.mjs` /
`*-assemble.mjs` script validates and persists it. Never put validation that must be
trustworthy (verdict whitelist, min-evidence, fingerprinting) in the prose — put it
in the assemble script, where it can't be reasoned around.

## Licensing note

Methodology in this repo is **MIT** and must be **our own wording**. Several skills
are *inspired by* [Trail of Bits' skills](https://github.com/trailofbits/skills)
(CC-BY-SA 4.0) — ideas are fine to learn from, but do **not** paste their text into
this repo. Credit the inspiration in a one-line note where relevant.
