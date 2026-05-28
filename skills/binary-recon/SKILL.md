---
name: binary-recon
description: Read-only static triage of compiled binaries (ELF / PE / Mach-O). Detects them by magic bytes, then surfaces dangerous imported symbols, writable+executable segments, and hardening gaps via on-PATH binutils (nm / readelf / objdump). Assessment only — no execution, no exploit-oriented disassembly. Promotes verdicts into .kuzushi/findings.json (source "binary-recon").
context: fork
agent: binary-recon
user-invocable: true
---

# Binary recon

Triage the compiled artifacts a source-only review skips. This is deliberately
modest: it tells you *what's exposed and how hardened* a binary is, and ties that
back to the source — it does not write exploits.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/binary-recon-prepare.mjs" --target "<repo root>"`.
   If it reports `no-candidates`, there are no binaries to triage — stop.
2. Read the prep's `prepPath`. Each candidate is a detected binary with read-only
   `signals` (dangerous imports, RWX segments) gathered from whatever binutils were
   available (`toolsUsed`). For each signal, decide whether it's a real exposure in
   context: is the dangerous import reachable with attacker-influenced input? Is the
   RWX segment a genuine mitigation gap or an expected JIT region? Tie it to the
   source that produces or invokes the binary where you can.
3. Write `{ candidates: [...] }` with `verdict` (finding / candidate / rejected), a
   `binaryClass`, a `rationale`, and `evidenceAnchors` ({ filePath } = the binary)
   to the prep's `draftPath`, then run the `assembleCommand`.
4. Report the `finding`s and note these are assessment-grade (hardening/exposure),
   not proven exploits — escalate real candidates to source-level review.

## When NOT to use

- On a repo with no compiled binaries (pure source / scripting project).
- As an exploitation tool — it never disassembles for gadget hunting or runs the
  binary. For memory-corruption exploitability use `/mem-exploitability`.
- As a substitute for source review — a signal here is a pointer back to source,
  not a verdict on its own.

## Rationalizations to Reject

- *"It's just a vendored binary, not our code."* → Vendored binaries ship in your
  artifact and run with your privileges; a backdoored or unhardened dependency is
  your exposure. Triage it or record why you skipped it.
- *"nm/readelf weren't installed, so there's nothing to find."* → Missing tools
  means *reduced* signal, not *no* risk. Say the triage was magic-only and flag the
  binary for follow-up rather than implying it's clean.
- *"A dangerous import exists, so it's a bug"* (or the reverse, *"…so it's fine"*).
  → An import is a lead, not a verdict. Decide reachability with attacker input
  before calling it a finding; absence of the symbol doesn't prove safety either.
