// priorityScore is the deterministic triage-ordering gate. World-class triage
// surfaces the unauth-reachable proven bug above the admin-only candidate of the
// same severity — these pin that the four signals (severity, proof, exposure,
// reach) combine and that resolved findings sink below actionable ones.

import { test } from "node:test";
import assert from "node:assert/strict";
import { priorityScore, sortByPriority } from "../scripts/lib/ranking.mjs";

function finding(overrides = {}) {
  return { fingerprint: "f".repeat(16), severity: "high", proofState: "open", ...overrides };
}

test("exposure breaks a tie between two same-severity, same-proof findings", () => {
  const unauth = priorityScore(finding({ exposure: "unauthenticated" }));
  const authed = priorityScore(finding({ exposure: "authenticated" }));
  assert.ok(unauth.score > authed.score, "unauthenticated must outrank authenticated");
  assert.equal(unauth.factors.exposure, 20);
  assert.equal(authed.factors.exposure, 10);
});

test("a proven high/unauth finding lands in the top tier (P0)", () => {
  const r = priorityScore(finding({ severity: "high", proofState: "proven", exposure: "unauthenticated" }));
  // 30 (high) + 25 (proven) + 20 (unauth) = 75 → P0
  assert.equal(r.score, 75);
  assert.equal(r.tier, "P0");
});

test("resolved findings (remediated/reviewed/noise) score 0 on the proof axis", () => {
  for (const proofState of ["remediated", "reviewed", "noise", "patch-validated"]) {
    assert.equal(priorityScore(finding({ proofState })).factors.proof, 0);
  }
});

test("reach: confirmed entry-point reachability beats a bare caller count", () => {
  const entry = priorityScore(finding({ reach: { entryReachable: true } }));
  const callers = priorityScore(finding({ reach: { callerCount: 4 } }));
  assert.equal(entry.factors.reach, 15);
  assert.ok(entry.factors.reach > callers.factors.reach);
  // explicitly-unreachable contributes nothing
  assert.equal(priorityScore(finding({ reach: { entryReachable: false } })).factors.reach, 0);
});

test("unknown/absent exposure is mid-weighted, not zero, so unlabeled findings aren't buried", () => {
  assert.equal(priorityScore(finding({})).factors.exposure, 8);
  assert.equal(priorityScore(finding({ exposure: "bogus-label" })).factors.exposure, 8);
});

test("sortByPriority is descending and deterministic (fingerprint breaks ties)", () => {
  const a = finding({ fingerprint: "aaaaaaaaaaaaaaaa", severity: "low", proofState: "candidate", priority: priorityScore(finding({ severity: "low", proofState: "candidate" })) });
  const b = finding({ fingerprint: "bbbbbbbbbbbbbbbb", severity: "critical", proofState: "proven", priority: priorityScore(finding({ severity: "critical", proofState: "proven" })) });
  const sorted = sortByPriority([a, b]);
  assert.equal(sorted[0].fingerprint, "bbbbbbbbbbbbbbbb");
});
