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

import { rankFiles as rankFilesDF } from "../scripts/lib/risk-rank.mjs";
import { storeFor as storeForDF } from "../scripts/lib/artifact-store.mjs";
import { mkdtempSync as mkdtempDF, mkdirSync as mkdirDF, writeFileSync as writeDF } from "node:fs";
import { tmpdir as tmpdirDF } from "node:os";
import { join as joinDF } from "node:path";

test("Lever 5: a persisted taint flow boosts its endpoint file (dataflow-reach), inert without one", () => {
  const t = mkdtempDF(joinDF(tmpdirDF(), "kz-df-"));
  mkdirDF(joinDF(t, ".kuzushi"), { recursive: true });
  // Two plain helper files with no keyword/entry signal — equal a priori.
  writeDF(joinDF(t, "a.js"), "function fmt(s){ return s.trim(); }\n");
  writeDF(joinDF(t, "b.js"), "function calc(s){ return s.length; }\n");

  // Without any flow evidence the signal is inert: neither carries dataflow-reach.
  const before = rankFilesDF(t, { maxFiles: 10 });
  const aBefore = before.ranked.find((r) => r.filePath === "a.js");
  assert.ok(!aBefore.reasons.includes("dataflow-reach"), "no flow evidence → no boost");

  // Persist a real taint-analysis flow finding whose evidence touches a.js.
  writeDF(storeForDF(t).findingsPath, JSON.stringify({
    version: "1.0", schemaVersion: "findings.v1", target: t,
    findings: [{
      schemaVersion: "finding.v1", fingerprint: "f".repeat(16), source: "taint-analysis",
      cwe: "CWE-89", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }]
    }]
  }) + "\n");

  const after = rankFilesDF(t, { maxFiles: 10 });
  const aAfter = after.ranked.find((r) => r.filePath === "a.js");
  const bAfter = after.ranked.find((r) => r.filePath === "b.js");
  assert.ok(aAfter.reasons.includes("dataflow-reach"), "flow endpoint earns the dataflow-reach signal");
  assert.ok(aAfter.score > bAfter.score, "the flow-reached file now outranks its inert peer");
});

test("Lever 5: a deep-scan's OWN finding does NOT self-reinforce routing", () => {
  const t = mkdtempDF(joinDF(tmpdirDF(), "kz-df2-"));
  mkdirDF(joinDF(t, ".kuzushi"), { recursive: true });
  writeDF(joinDF(t, "c.js"), "function go(s){ return s; }\n");
  writeDF(storeForDF(t).findingsPath, JSON.stringify({
    version: "1.0", schemaVersion: "findings.v1", target: t,
    findings: [{ schemaVersion: "finding.v1", fingerprint: "d".repeat(16), source: "deep-scan",
      cwe: "CWE-79", status: "open", evidence: [{ filePath: "c.js", startLine: 1 }] }]
  }) + "\n");
  const r = rankFilesDF(t, { maxFiles: 10 });
  const c = r.ranked.find((x) => x.filePath === "c.js");
  assert.ok(!c.reasons.includes("dataflow-reach"), "deep-scan's own findings are excluded (no self-reinforcement)");
});
