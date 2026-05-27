// Contracts for the shared findings index — the canonical record every producer
// writes and every consumer reads. Regressions here (e.g. a verdict→status drift
// or a broken patch merge) corrupt the whole pipeline, so they are asserted here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  verdictToStatus, verifyVerdictToStatus, pocVerdictToStatus, fixVerdictToStatus,
  fingerprint, upsertFindings, patchFindings, proofStateFor
} from "../scripts/lib/findings.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";

function tmp() { return mkdtempSync(join(tmpdir(), "kz-find-")); }
function readDoc(t) { return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")); }

const baseFinding = (over = {}) => ({
  source: "threat-hunt", refId: "r1", title: "t", severity: "high", cwe: "89",
  verdict: "exploitable", status: "open", evidence: [{ filePath: "src/a.js", startLine: 10 }],
  rationale: "x", nextChecks: [], ...over
});

test("verdict→status maps are stable (the cross-module contract)", () => {
  assert.equal(verdictToStatus("exploitable"), "open");
  assert.equal(verdictToStatus("reviewed-no-impact"), "reviewed");
  assert.equal(verdictToStatus("likely-library-noise"), "noise");
  assert.equal(verdictToStatus("finding"), "open");
  assert.equal(verdictToStatus("candidate"), "needs-evidence");
  assert.equal(verdictToStatus("rejected"), "reviewed");
  assert.equal(verifyVerdictToStatus("confirmed-exploitable"), "confirmed");
  assert.equal(verifyVerdictToStatus("not-exploitable"), "reviewed");
  assert.equal(pocVerdictToStatus("exploited"), "proven");
  assert.equal(pocVerdictToStatus("not-reproduced"), "reviewed");
  // /fix: only "validated" transitions status; everything else leaves it alone.
  assert.equal(fixVerdictToStatus("validated"), "patched");
  assert.equal(fixVerdictToStatus("exploit-still-fires"), null);
  assert.equal(fixVerdictToStatus("build-failed"), null);
});

test("fingerprint is stable + keyed on source|refId|file|line", () => {
  const a = fingerprint(baseFinding());
  const b = fingerprint(baseFinding());
  assert.equal(a, b, "same inputs → same fingerprint");
  assert.notEqual(a, fingerprint(baseFinding({ refId: "r2" })));
  assert.notEqual(a, fingerprint(baseFinding({ evidence: [{ filePath: "src/a.js", startLine: 11 }] })));
  assert.match(a, /^[0-9a-f]{16}$/);
});

test("upsertFindings dedupes by fingerprint (latest wins) + builds summary", () => {
  const t = tmp();
  upsertFindings(t, [baseFinding()]);
  upsertFindings(t, [baseFinding({ title: "updated title" })]); // same fp
  upsertFindings(t, [baseFinding({ refId: "r2", evidence: [{ filePath: "src/b.js", startLine: 1 }] })]);
  const doc = readDoc(t);
  assert.equal(doc.findings.length, 2, "duplicate fp collapsed, distinct fp kept");
  assert.equal(doc.findings.find((f) => f.refId === "r1").title, "updated title", "latest wins");
  assert.equal(doc.summary.total, 2);
  assert.equal(doc.summary.byStatus.open, 2);
});

test("patchFindings shallow-merges onto a finding + throws on unknown fingerprint", () => {
  const t = tmp();
  upsertFindings(t, [baseFinding()]);
  const fp = readDoc(t).findings[0].fingerprint;
  patchFindings(t, [{ fingerprint: fp, status: "confirmed", verification: { verdict: "confirmed-exploitable", confidence: 0.9, pocReady: true, verifiedAt: new Date().toISOString() } }]);
  const f = readDoc(t).findings[0];
  assert.equal(f.status, "confirmed");
  assert.equal(f.verification.pocReady, true);
  assert.equal(f.title, "t", "untouched fields preserved");
  assert.throws(() => patchFindings(t, [{ fingerprint: "deadbeef", status: "x" }]), /unknown fingerprint/);
});

test("a chains ref survives a later fix patch (no clobber)", () => {
  const t = tmp();
  upsertFindings(t, [baseFinding({ status: "proven" })]);
  const fp = readDoc(t).findings[0].fingerprint;
  patchFindings(t, [{ fingerprint: fp, chains: ["chain-abc"] }]);
  patchFindings(t, [{ fingerprint: fp, status: "patched", fix: {
    verdict: "validated", patchPath: "/tmp/x.diff", applied: false,
    validation: { exploitRegressionPassed: true, functionalRegressionPassed: true, pocPlusPassed: true }
  } }]);
  const f = readDoc(t).findings[0];
  assert.deepEqual(f.chains, ["chain-abc"], "chains ref not lost by the fix patch");
  assert.equal(f.fix.verdict, "validated");
});

test("upsertFindings relativizes absolute evidence paths under the target", () => {
  const t = tmp();
  const abs = join(t, "src/app/App.java"); // absolute, under the target
  upsertFindings(t, [baseFinding({ refId: "abs", evidence: [{ filePath: abs, startLine: 7 }] })]);
  const f = readDoc(t).findings[0];
  assert.equal(f.evidence[0].filePath, "src/app/App.java", "absolute path under target → relative");
  // a path NOT under the target is left as-is (can't safely relativize)
  upsertFindings(t, [baseFinding({ refId: "outside", evidence: [{ filePath: "/etc/hosts", startLine: 1 }] })]);
  const g = readDoc(t).findings.find((x) => x.refId === "outside");
  assert.equal(g.evidence[0].filePath, "/etc/hosts", "path outside target unchanged");
  // already-relative paths pass through untouched
  upsertFindings(t, [baseFinding({ refId: "rel", evidence: [{ filePath: "lib/x.js", startLine: 2 }] })]);
  assert.equal(readDoc(t).findings.find((x) => x.refId === "rel").evidence[0].filePath, "lib/x.js");
});

test("proofStateFor reflects the lifecycle (open→confirmed→proven→patched→remediated)", () => {
  assert.equal(proofStateFor({ status: "open" }), "open");
  assert.equal(proofStateFor({ status: "confirmed", verification: { verdict: "confirmed-exploitable" } }), "confirmed");
  assert.equal(proofStateFor({ status: "proven", poc: { proofVerdict: "exploited" } }), "proven");
  assert.equal(proofStateFor({ status: "patched" }), "patch-validated");
  assert.equal(proofStateFor({ status: "remediated" }), "remediated");
  assert.equal(proofStateFor({ status: "reviewed" }), "reviewed");
});
