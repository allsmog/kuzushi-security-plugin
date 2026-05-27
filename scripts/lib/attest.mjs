// Capability attestation: content digests + a runnable-gate for generated
// analyzer rules.
//
// Generated CodeQL/Joern queries (from /rule-synth) are EXECUTED code. Before
// any execution path runs one, `assertRunnable` checks that the on-disk bytes
// still match the digest recorded in the rule-pack manifest AND that the rule
// passed validation at synthesis time. A tampered or unvalidated rule throws
// loudly instead of executing — this is the hook the rule-synth pack records a
// digest for, and the policy plane (policy.mjs) pairs with it.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export function digestBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function digestFile(path) {
  return digestBytes(readFileSync(path));
}

// Throw unless the rule is safe to execute. `entry` is a rule-pack manifest
// entry { digest, validated:{compile} }; `onDiskBytes` are the current file
// contents (Buffer or string). Callers (finalize, future CI replay) recompile
// before running too — this is the integrity/attestation layer on top.
export function assertRunnable(entry, onDiskBytes) {
  if (!entry || typeof entry !== "object") {
    throw new Error("assertRunnable: missing manifest entry");
  }
  if (!entry.validated?.compile) {
    throw new Error(`assertRunnable: rule ${entry.ruleId ?? "?"} is not marked validated.compile — refusing to execute`);
  }
  const actual = digestBytes(onDiskBytes);
  if (actual !== entry.digest) {
    throw new Error(`assertRunnable: digest mismatch for ${entry.ruleId ?? "?"} (manifest ${entry.digest}, on-disk ${actual}) — refusing to execute a tampered rule`);
  }
  return true;
}
