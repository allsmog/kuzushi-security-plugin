// Contracts for the deterministic severity derivation (scripts/lib/severity.mjs).
// These pin the precondition × access-level table and the "take the LOWER column"
// rule, including the exact cross-checks the rule is modeled on:
//   "0 preconditions but authenticated-only is MEDIUM, not HIGH;
//    1 precondition but local-only is LOW."

import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveSeverity, judgeClaimedSeverity, normalizeAccessLevel } from "../scripts/lib/severity.mjs";

// ---- the table, single-column ------------------------------------------------

test("0 preconditions + unauthenticated remote → HIGH", () => {
  const r = deriveSeverity({ preconditions: [], accessLevel: "unauthenticated-remote" });
  assert.equal(r.severity, "high");
  assert.equal(r.derived, true);
});

test("1-2 preconditions + authenticated → MEDIUM", () => {
  assert.equal(deriveSeverity({ preconditions: ["a"], accessLevel: "authenticated" }).severity, "medium");
  assert.equal(deriveSeverity({ preconditions: ["a", "b"], accessLevel: "authenticated" }).severity, "medium");
});

test("3+ preconditions OR local-only → LOW", () => {
  assert.equal(deriveSeverity({ preconditions: ["a", "b", "c"], accessLevel: "unauthenticated-remote" }).severity, "low");
  assert.equal(deriveSeverity({ preconditions: [], accessLevel: "local-only" }).severity, "low");
});

// ---- take the LOWER of the two columns (the crux of the rule) ----------------

test("cross-check: 0 preconditions but authenticated-only is MEDIUM, not HIGH", () => {
  // precondition column says HIGH, access column says MEDIUM → take the LOWER = MEDIUM.
  assert.equal(deriveSeverity({ preconditions: [], accessLevel: "authenticated" }).severity, "medium");
});

test("cross-check: 1 precondition but local-only is LOW", () => {
  // precondition column says MEDIUM, access column says LOW → take the LOWER = LOW.
  assert.equal(deriveSeverity({ preconditions: ["x"], accessLevel: "local" }).severity, "low");
});

test("a missing column never lowers the result", () => {
  // Only preconditions supplied (no access) → derive from preconditions alone.
  assert.equal(deriveSeverity({ preconditions: [] }).severity, "high");
  // Only access supplied (no preconditions) → derive from access alone.
  assert.equal(deriveSeverity({ accessLevel: "local" }).severity, "low");
});

// ---- threat-model boost: at most one step, never two, never past HIGH --------

test("threat-model match raises by exactly one step", () => {
  assert.equal(deriveSeverity({ preconditions: ["a"], accessLevel: "local", threatModelMatch: true }).severity, "medium"); // low → medium
  assert.equal(deriveSeverity({ preconditions: [], accessLevel: "authenticated", threatModelMatch: true }).severity, "high"); // medium → high
});

test("threat-model boost caps at HIGH (never auto-critical)", () => {
  const r = deriveSeverity({ preconditions: [], accessLevel: "unauthenticated-remote", threatModelMatch: true });
  assert.equal(r.severity, "high");
  assert.equal(r.boosted, false); // already HIGH, nothing to raise
});

// ---- fallback when nothing is derivable --------------------------------------

test("no columns → falls back to claimed severity, derived:false", () => {
  const r = deriveSeverity({ claimed: "critical" });
  assert.equal(r.severity, "critical");
  assert.equal(r.derived, false);
});

test("no columns and no claim → medium default, derived:false", () => {
  const r = deriveSeverity({});
  assert.equal(r.severity, "medium");
  assert.equal(r.derived, false);
});

test("unknown access level alone is not usable (treated as absent)", () => {
  assert.equal(normalizeAccessLevel("banana"), null);
  // unknown access + no preconditions → nothing derivable → fall back
  assert.equal(deriveSeverity({ accessLevel: "banana", claimed: "low" }).derived, false);
});

// ---- claimed-severity inflation judgment (advisory, never changes severity) --

test("judgeClaimedSeverity rewards accurate/understated, penalizes inflation", () => {
  assert.equal(judgeClaimedSeverity({ claimed: "high", derived: "high" }).score, 4); // accurate
  assert.equal(judgeClaimedSeverity({ claimed: "low", derived: "high" }).score, 5); // understated
  assert.ok(judgeClaimedSeverity({ claimed: "high", derived: "medium" }).score <= 0); // one step high
  assert.equal(judgeClaimedSeverity({ claimed: "critical", derived: "low" }).score, -5); // 3 steps inflated
});

test("judgeClaimedSeverity is neutral when it can't compare", () => {
  assert.equal(judgeClaimedSeverity({ claimed: "bogus", derived: "high" }).score, 0);
});
