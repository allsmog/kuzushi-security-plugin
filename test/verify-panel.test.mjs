// Contracts for the adversarial verify panel. The consensus math is the precision
// engine: a majority confirms, but a "confirmed" consensus with no concrete trigger
// from any lens must downgrade to inconclusive (agreement isn't proof). Also checks
// the end-to-end panel assemble reads per-lens drafts and patches the index.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { consensus, assembleVerifyPanel } from "../scripts/cmd/verify-panel-assemble.mjs";

const trigger = { pocSketch: { payload: "' OR 1=1--", howToTrigger: "GET /x?q=" }, evidenceAnchors: [{ filePath: "a.js", startLine: 1 }] };

test("consensus: 3/3 confirm with a trigger → confirmed", () => {
  const c = consensus([
    { verdict: "confirmed-exploitable", confidence: 0.9, ...trigger },
    { verdict: "confirmed-exploitable", confidence: 0.8, ...trigger },
    { verdict: "confirmed-exploitable", confidence: 0.7, ...trigger }
  ]);
  assert.equal(c.verdict, "confirmed-exploitable");
  assert.equal(c.agreement, 1);
});

test("consensus: 2/3 confirm (one with trigger) → confirmed", () => {
  const c = consensus([
    { verdict: "confirmed-exploitable", confidence: 0.8, ...trigger },
    { verdict: "confirmed-exploitable", confidence: 0.6 },
    { verdict: "not-exploitable", confidence: 0.5 }
  ]);
  assert.equal(c.verdict, "confirmed-exploitable");
});

test("consensus: 1/3 confirm → inconclusive (no majority)", () => {
  const c = consensus([
    { verdict: "confirmed-exploitable", confidence: 0.9, ...trigger },
    { verdict: "not-exploitable", confidence: 0.6 },
    { verdict: "inconclusive", confidence: 0.4 }
  ]);
  assert.equal(c.verdict, "inconclusive");
});

test("consensus: majority confirm but NO trigger anywhere → downgraded to inconclusive", () => {
  const c = consensus([
    { verdict: "confirmed-exploitable", confidence: 0.8 },
    { verdict: "confirmed-exploitable", confidence: 0.7 },
    { verdict: "not-exploitable", confidence: 0.5 }
  ]);
  assert.equal(c.verdict, "inconclusive");
  assert.equal(c.downgradedForNoTrigger, true);
});

test("panel assemble: reads per-lens drafts, patches the finding with a panel block", () => {
  const t = mkdtempSync(join(tmpdir(), "kz-vp-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  // Seed one open finding to verify.
  const doc = upsertFindings(t, [{ source: "deep-scan", refId: "d1", title: "SQLi", severity: "high",
    cwe: "CWE-89", verdict: "finding", evidence: [{ filePath: "a.js", startLine: 1 }], rationale: "x" }]);
  const fp = doc.findings[0].fingerprint;

  const runDir = join(storeFor(t).runsDir, "verify-panel-test");
  mkdirSync(runDir, { recursive: true });
  const vote = (lens, verdict, withTrigger) => ({ lens, candidates: [{ findingFingerprint: fp, verdict, confidence: 0.8,
    rationale: "the q param flows unsanitized into db.run building a SQL string; reachable from the route", ...(withTrigger ? trigger : {}) }] });
  writeFileSync(join(runDir, "draft.verify.0.json"), JSON.stringify(vote("reachability", "confirmed-exploitable", true)));
  writeFileSync(join(runDir, "draft.verify.1.json"), JSON.stringify(vote("guard-bypass", "confirmed-exploitable", false)));
  writeFileSync(join(runDir, "draft.verify.2.json"), JSON.stringify(vote("impact", "not-exploitable", false)));

  const res = assembleVerifyPanel(t, runDir);
  assert.equal(res.status, "completed");
  assert.equal(res.verdictCounts["confirmed-exploitable"], 1);
  const f = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings.find((x) => x.fingerprint === fp);
  assert.equal(f.verification.verdict, "confirmed-exploitable");
  assert.equal(f.verification.panel.voteCount, 3);
  assert.equal(f.status, "confirmed");
});
