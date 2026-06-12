# Contributing to kuzushi

Thanks for helping — kuzushi gets better mostly by **growing its coverage and its corpus**, and a
lot of that is approachable first-PR work. This guide gets you productive fast.

## The one rule that matters: no false wins

kuzushi's brand is that it doesn't lie — findings must be *proven*, and the tool measures its own
recall so it can report what it missed. So every change is held to: **does a deterministic test or a
measurement back this up?** A change that *looks* like an improvement but isn't measured is the one
thing we reject. When in doubt, add the test that would catch a regression.

## Setup

```bash
git clone https://github.com/allsmog/kuzushi-security-plugin
cd kuzushi-security-plugin && npm install   # Node ≥ 20
npm test                                    # the deterministic gate — must stay green
```

- `npm test` — unit + integration tests of the deterministic scripts. **This is the CI gate; keep it green.**
- `npm run bench` — candidate-recall on the planted-bug corpus (no LLM; reproducible).
- `npm run eval` / `eval:cve` — the LLM-in-the-loop eval. **Billed, nondeterministic, never a CI gate** — don't run it in CI; a low number is a valid result, not a failure.

Some backends (Joern, CodeQL, semgrep) are optional — tests that need them self-skip when the CLI
isn't on PATH, so you can contribute most things without installing heavy tooling.

## How the architecture constrains a PR

Each capability is a **deterministic `prepare` → `agent` (LLM prose) → `assemble`/`finalize`
(deterministic)** pipeline. The split is load-bearing:

- **Trustworthy validation lives in the `*-finalize.mjs` / `*-assemble.mjs` script**, never in the
  agent prose — the prose can be reasoned around; the script can't. Verdict whitelists, severity
  derivation, dedup, consensus all live in code (see [`CLAUDE.md`](CLAUDE.md) → *Determinism boundary*).
- **Agent/skill prose** (`agents/*.md`, `skills/*/SKILL.md`) teaches *judgment* — when to reach for
  a tool, how to read its result. [`CLAUDE.md`](CLAUDE.md) is the authoring standard; finder/verifier
  agents must include the required sections (*When NOT to use*, *Rationalizations to Reject*, and for
  promoters a *Worked example*). `test/agent-compliance.test.mjs` enforces this.
- **No new slash commands** without discussion — the menu is deliberately the four phases; new
  capability usually rides an existing skill or an internal helper (like `scripts/cmd/callers.mjs`).

## Good first contributions (each is small + tested)

- **Add a bench case** — a `bench/cases/<name>/` with a `repo/` (a real bug *and* a guarded "safe"
  decoy) + `expected.json`. Exerts both recall and precision; picked up automatically by `npm run bench`.
- **Add a starter query** — a Joern `.sc` (`packs/starter/joern/`) or CodeQL `.ql` for a CWE the pack
  doesn't cover, registered in `packs/starter/manifest.json`. `test/starter-pack-structure.test.mjs`
  checks the shape; the joern/codeql verify jobs run it for real.
- **Extend an obligation rule** — a new dangerous-primitive pattern in `scripts/lib/sink-obligations.mjs`,
  with a fixture in `test/sink-obligations.test.mjs`. *Measure the noise*: it must land on a real bug
  line without flooding ordinary files (we reject noisy rules — see the gc-rooting de-noise history).
- **Add a CWE → remediation mapping** in `scripts/lib/remediation.mjs` (+ its test).
- **Docs** — a first-run walkthrough, a case study, or improving any skill's `SKILL.md` per `CLAUDE.md`.

## PR checklist

- [ ] `npm test` is green (add/adjust a test for your change).
- [ ] New validation that must be trusted is in the finalize/assemble script, not the prose.
- [ ] If you touched a ranking/obligation/query, you can point at the measurement showing it helps
      and doesn't regress (a bench number, a new fixture, or the live-recall gate).
- [ ] Prose changes follow `CLAUDE.md` (required sections; explain *why*, not just *what*).
- [ ] No overclaiming in docs — keep capability statements honest and measured.

Open an issue first for anything large or that adds a command. Small, focused PRs merge fastest.
