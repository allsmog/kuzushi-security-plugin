---
name: verify
description: Exploitability verification of the findings index. For each open / trace-needed finding in .kuzushi/findings.json, reconstruct source→sink, build a concrete trigger, and assign a proof verdict (confirmed-exploitable / not-exploitable / inconclusive) with a PoC sketch. Read-only — attaches a verification block onto each finding and tags the PoC-ready ones for /poc. Requires /threat-hunt (or /taint-analysis) first.
context: fork
agent: verifier
user-invocable: true
---

# Verify

Verify the exploitability of the open findings for the current repository.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/verify-prepare.mjs" --target "<repo root>"`.
   If it reports no findings index, tell the user to run `/threat-hunt` (or `/taint-analysis`)
   first and stop.
2. Read the prep's `prepPath`. For **each** candidate finding, do the full verify walk
   (reconstruct source→sink → concrete trigger/payload **+ a negative PoC** → attempt every guard
   → **devil's-advocate** the opposite verdict → TRUE/FALSE-positive verdict + confidence + PoC
   sketch), using the `kuzushi-tree-sitter` taint tools
   (`tree_sitter:taint_sources` / `taint_sinks` / `callers` / `query`; codeql/joern only if a
   prebuilt DB/CPG already exists) and each candidate's matched threat-intel (`intel`).
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates the verdicts, persists `.kuzushi/verify.json`, and attaches
   a `verification` block onto each finding (tagging the PoC-ready ones).
4. Report the verdict counts, the `confirmed-exploitable` findings (fingerprint, CWE, the
   trigger), and which findings are now PoC-ready. Then **route each finding to its proof
   path by language / finding-type** — see *Proof routing* below.

## Panel mode (recommended for un-pattern-gated leads, e.g. `/deep-scan`)

Run `verify-prepare … --input '{"panel":3}'`. The prep then carries `panel`, the
`lenses` (reachability, guard-bypass, impact), and `draftPaths` (one per lens). A
single verifier can be confidently wrong; the panel makes the call by majority.

- For **each lens**, spawn an independent `verifier` sub-agent (one Task call each,
  in a single message so they run concurrently). Give each the prep, the **lens
  focus** to specialize on, and "write your `{ lens, candidates:[…] }` to
  `draft.verify.<k>.json`". The verifiers do **not** see each other's drafts — the
  independence is the point.
- When all lenses are done, run the `assembleCommand` (`verify-panel-assemble`). It
  computes per-finding consensus (majority confirms; a `confirmed-exploitable`
  consensus still requires at least one lens to supply a concrete trigger, else it
  downgrades to `inconclusive`) and patches the index with a `verification.panel`
  block (votes, agreement, and — when the panel leaned non-finding — the modal
  exclusion rule + refute reasons). Use this from `/sweep` on high-severity findings.
- **Split-vote policy.** Add `"noiseTolerance"` to the input to decide a no-majority
  tie: `precision` drops it (`not-exploitable`), `recall` (default) keeps it
  `inconclusive` for manual review, `ask` surfaces it so you decide. The assemble
  reports `needsUserDecision` fingerprints under `ask` — present those via
  AskUserQuestion rather than silently keeping or dropping them.

## Proof routing (CONFIRM picks the next step by language / finding-type)

The proof tools are no longer separate menu commands — `/verify` is the CONFIRM driver that
reaches them. After verdicts, select the right one **per finding**:

- **Inconclusive / needs-trace** (a guard you couldn't bypass) → `/path-solve`: extracts the
  guard predicate and solves for a reaching input (Z3 / CrossHair if installed, else reasoning),
  then re-verify. Read-only — run it as part of CONFIRM.
- **Memory-corruption finding** (CWE-119/120/121/122/124/125/126/127/131/190/191/415/416/476/787/824,
  or `source: systems-hunt` / `binary-recon`) → two complementary steps:
  - `/mem-exploitability`: tier + mitigation posture (assessment, no payloads). Read-only.
  - **`/sanitize-pov` (the empirical proof — borrow from AIxCC):** compile a harness that drives
    the bug **with AddressSanitizer/UBSan** and run it; a sanitizer abort is ground-truth proof and
    names the exact error class + CWE. This is what catches the subtle memory bugs static reading
    misses (use-after-free, buried overflow). It **executes code** — propose it, run on consent.
    A sanitizer-proven finding goes straight to `proven`; prefer this over a hand-reasoned verdict
    whenever a C/C++/Rust toolchain is available.
- **Native / parser / library target** (C/C++/Rust, archive/format parsers) → `/sanitize-pov` for a
  targeted proof, or a `/fuzz` campaign to *discover* via the same sanitizer oracle over many
  inputs. Both **execute code** — propose, run only on the user's say-so.
- **Otherwise** (web / general; one reconstructed trigger) → `/poc`: builds and sandbox-runs one
  harness. It **executes code** — only on explicit user request.

Run the read-only selectors (`/path-solve`, `/mem-exploitability`) as part of CONFIRM; anything
that **executes** (`/sanitize-pov`, `/poc`, `/fuzz`) stays a consented user action — never auto-run it.

## When NOT to use

- To *find* new bugs — verify only confirms findings a producer already wrote.
- Before any findings exist — run `/threat-hunt`, `/taint-analysis`, or `/systems-hunt` first.
- To empirically execute a PoC — that's `/poc`; verify is read-only and never runs code.

## Rationalizations to Reject

- *"The sink looks reachable, that's enough."* → `confirmed-exploitable` requires a **concrete
  trigger** (an actual payload + how it reaches the sink), not a plausibility argument.
- *"A guard is in the way, so not-exploitable."* → Name the guard **and** show every bypass you
  tried failed; an unbypassed-but-untested guard is `inconclusive`, not `not-exploitable`.
- *"I'm fairly sure, call it confirmed."* → Confidence is recorded explicitly; if you can't settle
  it from on-disk artifacts, the honest verdict is `inconclusive` with what runtime evidence is needed.
