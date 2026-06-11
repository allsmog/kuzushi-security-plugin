---
name: deep-scan
description: Whole-file deep reader — finds bugs by READING risk-ranked files in full and reasoning from first principles, not by grepping for known patterns. Catches the long tail (project-specific wrappers, business logic, cross-function flaws) that pattern-gated producers structurally miss. Token-expensive; budget-bounded and risk-ranked. Promotes leads into .kuzushi/findings.json (source "deep-scan").
context: command
runner: scripts/cmd/deep-scan-run.mjs
user-invocable: false
---

# Deep scan

Find the bugs the pattern scanners can't see. Every other producer starts from a
ripgrep hit; this one starts from the *files*. It reads the highest-risk files in
full and reasons about what could actually go wrong — the way a human auditor finds
the bug that doesn't look like any CVE.

1. Prefer the provider-neutral command:
   `KUZUSHI_MODEL="${KUZUSHI_MODEL:-openai-codex:gpt-5.5}" node "<plugin root>/scripts/cmd/deep-scan-run.mjs" --target "<repo root>"`.
   It performs prepare -> configured LLM bridge -> finalize without depending on a
   Claude subagent runtime. To go wider, pass `--input '{"maxFiles":50}'`; to scope a
   subtree, `'{"scopeDir":"src/api"}'`.
2. Manual fallback only when the runner is unavailable: run
   `node "<plugin root>/scripts/cmd/deep-scan-prepare.mjs" --target "<repo root>"`,
   read each listed file in full, write `{ candidates: [...] }` to `draftPath`, then
   run the returned `assembleCommand`.
3. For each file, emit hypotheses: `verdict` (finding / candidate / rejected), a
   `rationale` (the trusted assumption that breaks + the attacker path), `cwe`, and
   `evidenceAnchors`.
4. **Pipeline to verification — use the panel by default.** Deep-read `finding`s are
   strong leads but were *not* gated by a deterministic rule, so they carry the highest
   false-positive risk. Run `/verify --input '{"panel":3}'` on them: the multi-lens
   majority (reachability / guard-bypass / impact) is what keeps the extra recall from
   arriving as noise. Single-pass `/verify` is fine for pattern-gated findings; for
   deep-scan leads the panel is the default, not the exception.
5. Report the findings, and explicitly state the `unreadCount` so coverage stays
   honest — offer a follow-up `/deep-scan` over the remainder if it's non-zero.

## When NOT to use

- For a fast, cheap pass over known bug-classes — use the pattern producers
  (`/taint-analysis`, `/authz`, `/logic-hunt`, `/crypto-review`, `/systems-hunt`).
  Deep-scan is for depth and the long tail, and it costs real tokens.
- On a tiny diff — use `/diff-review`. On a single known file — read it directly.
- To confirm an existing finding — that's `/verify` / `/poc`.

## Rationalizations to Reject

- *"The pattern scanners already ran, so the repo's covered."* → They only saw lines
  a regex matched. The whole point of deep-scan is the bugs no pattern names; running
  it is how you find them, not a duplicate pass.
- *"maxFiles covered the important stuff, ignore unreadCount."* → `unreadCount > 0`
  means the repo is not fully read. Report it and offer the follow-up pass; never
  imply full coverage you didn't achieve.
- *"Reading every file is too expensive."* → That's why it's risk-ranked and
  budgeted. The trade is tokens-for-recall, made explicitly — not skipped silently.
- *"It looks like normal framework code."* → Framework-shaped code with a custom
  wrapper is exactly where the pattern tools fail and deep reading wins. Judge the
  behavior.
