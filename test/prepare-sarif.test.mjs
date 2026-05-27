// Contracts for the prepare-phase candidate selection (what each capability
// considers actionable), the SARIF exporter, and the harnessLinkage
// normalization in fix-finalize. All engine-independent (no docker/codeql/joern).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { upsertFindings, patchFindings } from "../scripts/lib/findings.mjs";
import { storeFor, openRun } from "../scripts/lib/artifact-store.mjs";
import { prepareFix } from "../scripts/cmd/fix-prepare.mjs";
import { finalizeFix } from "../scripts/cmd/fix-finalize.mjs";
import { prepareRuleSynth } from "../scripts/cmd/rule-synth-prepare.mjs";
import { prepareChain } from "../scripts/cmd/chain-prepare.mjs";
import { exportSarif } from "../scripts/cmd/export-sarif.mjs";

function tmp() { return mkdtempSync(join(tmpdir(), "kz-prep-")); }
const finding = (over = {}) => ({
  source: "threat-hunt", refId: "f", title: "t", severity: "high", cwe: "89",
  verdict: "exploitable", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }],
  rationale: "x", nextChecks: [], ...over
});

// ---- fix-prepare candidate selection ----------------------------------------

test("fix-prepare selects only confirmed/proven findings (not open static-only)", () => {
  const t = tmp();
  upsertFindings(t, [finding({ refId: "open1", status: "open" })]);
  assert.throws(() => prepareFix(t, {}), /no fixable findings/, "open-only → nothing to fix");

  upsertFindings(t, [finding({ refId: "proven1", status: "proven", evidence: [{ filePath: "b.js", startLine: 2 }] })]);
  const r = prepareFix(t, {});
  assert.equal(r.candidateCount, 1, "the proven finding is a fix candidate; the open one is not");
});

test("fix-prepare excludes findings that already have a fix block", () => {
  const t = tmp();
  upsertFindings(t, [finding({ refId: "p", status: "proven" })]);
  const fp = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0].fingerprint;
  patchFindings(t, [{ fingerprint: fp, fix: { verdict: "exploit-still-fires", patchPath: "/tmp/x.diff", applied: false } }]);
  assert.throws(() => prepareFix(t, {}), /no fixable findings/, "already-attempted fix is skipped");
});

// ---- rule-synth-prepare gating ----------------------------------------------

test("rule-synth-prepare reports no-seeds, then no-engine once a seed exists", () => {
  const t = tmp();
  upsertFindings(t, [finding({ refId: "open", status: "open" })]); // a finding exists but is not a seed
  assert.equal(prepareRuleSynth(t, {}).status, "no-seeds", "no confirmed/proven seed");
  upsertFindings(t, [finding({ refId: "conf", status: "confirmed", evidence: [{ filePath: "c.js", startLine: 3 }] })]);
  // No CodeQL DB / Joern CPG built in a bare temp dir → no-engine (unless this
  // machine has neither, which is the same outcome).
  assert.equal(prepareRuleSynth(t, {}).status, "no-engine");
});

// ---- chain-prepare member selection -----------------------------------------

test("chain-prepare needs >=2 live findings and excludes reviewed/noise", () => {
  const t = tmp();
  upsertFindings(t, [finding({ refId: "a", status: "open" })]);
  assert.throws(() => prepareChain(t, {}), /at least 2 live findings/);
  upsertFindings(t, [
    finding({ refId: "b", status: "reviewed", evidence: [{ filePath: "b.js", startLine: 2 }] }),
    finding({ refId: "c", status: "noise", evidence: [{ filePath: "c.js", startLine: 3 }] })
  ]);
  assert.throws(() => prepareChain(t, {}), /at least 2 live findings/, "reviewed+noise don't count as live");
  upsertFindings(t, [finding({ refId: "d", status: "confirmed", evidence: [{ filePath: "d.js", startLine: 4 }] })]);
  assert.equal(prepareChain(t, {}).memberCount, 2, "open + confirmed = 2 live members");
});

// ---- SARIF export -----------------------------------------------------------

test("export-sarif emits valid SARIF 2.1.0 with a driver, rules, and results", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "s1", status: "open", cwe: "89" }),
    finding({ refId: "s2", status: "open", cwe: "78", evidence: [{ filePath: "x.js", startLine: 9 }] })
  ]);
  const r = exportSarif(t, { all: true });
  assert.ok(r.resultCount >= 2, "results emitted");
  const sarif = JSON.parse(readFileSync(r.sarifPath, "utf8"));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(Array.isArray(sarif.runs) && sarif.runs[0].tool.driver, "has a tool driver");
  assert.ok(Array.isArray(sarif.runs[0].results) && sarif.runs[0].results.length >= 2, "has results");
  const r0 = sarif.runs[0].results[0];
  assert.ok(r0.ruleId && r0.locations?.[0]?.physicalLocation?.artifactLocation?.uri, "result has ruleId + location");
});

// ---- harnessLinkage normalization (via the no-harness degraded path) --------

async function fixVerdictFor(t, harnessLinkage) {
  upsertFindings(t, [finding({ status: "proven" })]);
  const fp = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0].fingerprint;
  // proven finding whose poc harnessDir does NOT exist → degraded no-harness path
  patchFindings(t, [{ fingerprint: fp, poc: { proofVerdict: "exploited", proofLevel: 4, backend: "local", harnessDir: "/tmp/does-not-exist-kz", provenAt: new Date().toISOString() } }]);
  const run = openRun(t, "fix");
  writeFileSync(join(run.runDir, "draft.fix.json"), JSON.stringify({ candidates: [{
    findingFingerprint: fp, language: "c", patch: "--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-x\n+y\n",
    patchRationale: "r".repeat(160), targetFiles: ["a.c"], harnessLinkage,
    functionalCheck: { kind: "none" }
  }] }));
  const res = await finalizeFix(t, run.runDir, {});
  return JSON.parse(readFileSync(storeFor(t).fixPath, "utf8")).results[0];
}

test("fix-finalize normalizes harnessLinkage: 'direct' → 'links-target', 'inlined' stays", async () => {
  assert.equal((await fixVerdictFor(tmp(), "direct")).harnessLinkage, "links-target", "off-spec value normalized");
  assert.equal((await fixVerdictFor(tmp(), undefined)).harnessLinkage, "links-target", "missing value defaults");
  assert.equal((await fixVerdictFor(tmp(), "inlined")).harnessLinkage, "inlined", "explicit inlined preserved");
});
