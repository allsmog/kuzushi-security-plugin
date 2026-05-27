---
name: poc
description: Empirical proof-of-concept for the PoC-ready findings. For each finding /verify marked confirmed-exploitable or inconclusive, synthesize a minimal harness that triggers the bug; a host script then runs it in a sandbox (Docker --network none when present, else a gated local run) and classifies the crash into a proof verdict. Attaches a poc block onto each finding. Requires /verify first.
context: fork
agent: poc-builder
user-invocable: true
---

# PoC

Build and empirically run proof-of-concepts for the PoC-ready findings.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/poc-prepare.mjs" --target "<repo root>"`.
   If it reports no PoC-ready findings, tell the user to run `/verify` first and stop.
2. Read the prep's `prepPath`. Note its `sandbox` field (`docker` / `local` / `none`) — it tells
   you whether the harness will actually run. For **each** candidate, write the **smallest
   harness that triggers the bug** described in its `verification.pocSketch` into the candidate's
   `harnessDir` (write files only there — never edit application code), and record it in the
   draft.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand`. The host script (not you) runs each harness in the sandbox, classifies the
   result, persists `.kuzushi/poc.json` with run logs, and attaches a `poc` block onto each
   finding.
4. Report the proof verdict + level per finding (and which were `exploited`). If `sandbox` was
   `none`, note the harnesses were written but not executed — the user can run them manually, or
   re-run with Docker available.

## When NOT to use

- On findings that aren't PoC-ready — run `/verify` first; it tags what's worth proving.
- As a way to *find* or *triage* bugs — `/poc` only empirically confirms an already-reconstructed
  trigger.
- When you can't accept code execution — `/poc` builds and **runs** harnesses; if no sandbox is
  available it writes them but won't execute, and you should not run them by hand on untrusted code.

## Rationalizations to Reject

- *"The harness is easier if it just imports the whole app."* → Build the **smallest** harness that
  triggers the bug; a giant harness that crashes proves nothing specific.
- *"It didn't crash, so the finding is wrong."* → `not-reproduced` is about *this harness*, not the
  finding; a weak harness or wrong payload fails to reproduce a real bug. Re-read the pocSketch.
- *"I'll just add a network call to make it work."* → The sandbox is offline by design; a PoC that
  needs the network is testing the wrong thing.
