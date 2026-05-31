---
name: binary-recon
description: "Read-only static triage of compiled binaries (ELF / PE / Mach-O). For each detected binary and its read-only signals (dangerous imported symbols, writable+executable segments, hardening gaps from nm/readelf/objdump), judge whether the signal is a real exposure in context and tie it to source. Assign finding / candidate / rejected with the binary path as evidence. Assessment only — no execution, no exploit-oriented disassembly. Promotes into .kuzushi/findings.json (source 'binary-recon')."
---

# Binary recon (read-only static binary triage)

A source review that never opens the shipped binary is trusting the build. You
triage the artifacts: classify each binary, read the read-only signals the prepare
step gathered, and decide which are real exposures — without ever running or
exploiting them. Your output is assessment-grade: a hardening/exposure verdict and
a pointer back to source, not a proof of exploitation.

## What you work from

The prepare step already detected binaries by magic bytes and ran whatever binutils
were on PATH (`toolsUsed`), producing `signals`:
- **dangerous-import** — a risky imported symbol (`system`, `popen`, `strcpy`,
  `gets`, `mprotect`, `dlopen`, …).
- **rwx-segment** — a LOAD segment that is both writable and executable (a
  mitigation gap unless it's a known JIT region).

You may also reason about **hardening-gap** (missing NX/PIE/canary/RELRO — overlaps
with `/mem-exploitability`, defer the exploitability tiering to it), **embedded-secret**
(hard-coded credential strings), and **suspicious-string** signals if the tooling
surfaced them.

## Method (per binary / signal)

1. **Classify** the binary (format, role: app, shared lib, vendored dependency,
   test fixture).
2. **Context the signal.** A `system()` import matters if the binary takes
   attacker-influenced input that reaches it; an RWX segment matters unless it's an
   expected JIT/codegen region. Where possible, find the **source** that builds or
   invokes this binary and link the two.
3. **Verdict** from the closed set:
   - `finding` — a real exposure (e.g. a vendored binary importing `system` and fed
     external input, or an unexpected RWX segment). Requires `evidenceAnchors` with
     the binary's `filePath`.
   - `candidate` — a signal worth follow-up but unconfirmed reachability; say what
     source/inputs you'd need.
   - `rejected` — benign in context (expected JIT region, unreachable symbol, test
     fixture). Say why.
4. Write `rationale` (≥120 chars): the signal, the binary, and why it does or
   doesn't matter. Set `binaryClass` and keep `evidenceAnchors` as `{ filePath }`.

## Worked example (a vendored binary importing `system`)

Signal `{ kind: "dangerous-import", symbol: "system", filePath: "vendor/bin/updater" }` (ELF).

- **Classify:** `vendor/bin/updater` — a vendored helper. Find the caller in source:
  `subprocess.run(["vendor/bin/updater", user_channel])`, where `user_channel` is a request field.
- **Context the signal:** `system` is imported AND the binary is fed attacker-controlled argv, so
  if `updater` forwards that to `system()` it's command injection. The import is reachable from
  attacker input → real exposure, not a benign libc reference.
- **Verdict `finding`** (`binaryClass: "vendored-dependency"`); evidence is the binary path. Defer
  any hardening/exploitability tiering to `/mem-exploitability`. Assessment only — no execution.

```json
{ "candidates": [{
  "binaryId": "<prep id for vendor/bin/updater>",
  "binaryClass": "vendored-dependency",
  "title": "Vendored updater imports system() and is fed request-controlled argv",
  "cwe": "CWE-78",
  "severity": "high",
  "verdict": "finding",
  "rationale": "vendor/bin/updater (ELF) imports system(); the app invokes it as subprocess.run(['vendor/bin/updater', user_channel]) where user_channel is a request field. The dangerous import is reachable from attacker-controlled argv, so if updater forwards it to system() it is OS command injection — a real exposure in context, not a benign libc reference. Assessment only; no execution or disassembly.",
  "nextChecks": ["confirm updater forwards argv to system(); validate/allowlist user_channel"],
  "evidenceAnchors": [{ "filePath": "vendor/bin/updater" }]
}] }
```

## When NOT to use

- No binaries present, or as an exploitation/gadget tool (it isn't one).
- For memory-corruption exploitability tiering — that's `/mem-exploitability`.

## Rationalizations to Reject

- *"Vendored, so not our problem."* → It ships in your artifact and runs with your
  privileges. Triage it or record the skip.
- *"Tools missing → nothing to find."* → That's reduced signal, not safety. Mark
  the binary magic-only and flag for follow-up.
- *"Symbol present → bug"* / *"symbol absent → safe."* → An import is a lead, not a
  verdict; decide reachability first, and absence never proves safety.
