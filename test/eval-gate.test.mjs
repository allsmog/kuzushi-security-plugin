import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateScoreboardGate, parseThreshold } from "../scripts/cmd/eval-gate.mjs";

const scoreboard = {
  schemaVersion: "eval-scoreboard.v2",
  aggregate: {
    routingRecall: 0.8,
    reasoningRecall: 0.5,
    siteContextRecall: 0.4,
    siteReasoningRecall: 0.75,
    blindRecall: 0.4,
    confirmedOnTarget: 0.3,
    provenOnTarget: 0.2,
    falseProofRate: 0,
    extraConfirmedPerCase: 0.75,
    extraProvenPerCase: 0,
    costPerTrueFinding: 42
  }
};

test("eval-gate parses decimal and percent thresholds", () => {
  assert.equal(parseThreshold("60%"), 0.6);
  assert.equal(parseThreshold("0.6"), 0.6);
  assert.equal(parseThreshold("42"), 42);
  assert.equal(parseThreshold("nope"), null);
});

test("eval-gate passes when all requested thresholds hold", () => {
  const result = evaluateScoreboardGate(scoreboard, {
    "min-routing-recall": "80%",
    "min-reasoning-recall": "0.5",
    "min-site-context-recall": "40%",
    "min-site-reasoning-recall": "75%",
    "max-false-proof-rate": "0",
    "max-extra-confirmed-per-case": "1",
    "max-cost-per-true-finding": "50"
  });
  assert.equal(result.ok, true);
  assert.equal(result.checks.length, 7);
});

test("eval-gate fails with explicit metric failures", () => {
  const result = evaluateScoreboardGate(scoreboard, {
    "min-blind-recall": "60%",
    "min-site-context-recall": "50%",
    "min-proven-on-target": "40%",
    "max-false-proof-rate": "-1",
    "max-extra-confirmed-per-case": "0.5"
  });
  assert.equal(result.ok, false);
  assert.equal(result.failures.length, 5);
  assert.ok(result.failures.some((f) => f.includes("blindRecall")));
  assert.ok(result.failures.some((f) => f.includes("siteContextRecall")));
  assert.ok(result.failures.some((f) => f.includes("provenOnTarget")));
  assert.ok(result.failures.some((f) => f.includes("falseProofRate")));
  assert.ok(result.failures.some((f) => f.includes("extraConfirmedPerCase")));
});
