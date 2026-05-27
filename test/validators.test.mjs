// Contracts for the promote/proof validators that were previously untested: the
// /poc proof-tier classifier (pure), the /verify fp-gate (negativePoc +
// devilsAdvocate required for a decisive verdict), and the closed-verdict
// enforcement shared by threat-hunt / systems-hunt / taint-analysis finalizers.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyResult } from "../scripts/lib/sandbox.mjs";
import { assembleVerify } from "../scripts/cmd/verify-assemble.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { storeFor, openRun } from "../scripts/lib/artifact-store.mjs";

function tmp() { return mkdtempSync(join(tmpdir(), "kz-val-")); }
const cmd = (name) => new URL(`../scripts/cmd/${name}.mjs`, import.meta.url).pathname;

// ---- /poc proof-tier classifier (pure) --------------------------------------

test("classifyResult maps runs to the proof tiers", () => {
  assert.deepEqual(classifyResult({ signal: "SIGSEGV" }), { proofLevel: 4, proofVerdict: "exploited" });
  assert.deepEqual(classifyResult({ exitCode: 139 }), { proofLevel: 4, proofVerdict: "exploited" }, "128+signal");
  assert.equal(classifyResult({ exitCode: 1, stderr: "ERROR: AddressSanitizer: heap-buffer-overflow" }).proofVerdict, "exploited");
  assert.equal(classifyResult({ exitCode: 1, stdout: "panic: index out of range" }).proofVerdict, "exploited");
  assert.equal(classifyResult({ exitCode: 1, stderr: "" }, "nonzero").proofVerdict, "exploited", "expectedSignal=nonzero");
  assert.deepEqual(classifyResult({ exitCode: 0, stdout: "ok" }), { proofLevel: 2, proofVerdict: "not-reproduced" });
  assert.equal(classifyResult({ exitCode: 1, stderr: "error[E0277]: cannot find" }).proofVerdict, "harness-failed-build");
  assert.equal(classifyResult({ skipped: true, reason: "no backend" }).proofVerdict, "error");
  assert.equal(classifyResult({ timedOut: true }).proofVerdict, "timeout");
});

// ---- /verify fp-gate --------------------------------------------------------

function verifyDraft(over = {}) {
  return {
    verdict: "confirmed-exploitable", confidence: 0.9,
    attackVector: "av", preconditions: ["p"],
    pocSketch: { payload: "X", howToTrigger: "call f" },
    evidenceAnchors: [{ filePath: "a.js", startLine: 1 }],
    rationale: "r".repeat(160),
    negativePoc: "a benign in-spec input is handled safely, proving the trigger discriminates",
    devilsAdvocate: "the opposite verdict would argue a guard exists, but no guard is present on the traced path here",
    ...over
  };
}

test("verify-assemble accepts a fully fp-gated confirmed verdict → confirmed + pocReady", () => {
  const t = tmp();
  upsertFindings(t, [{ source: "threat-hunt", refId: "v", title: "t", severity: "high", cwe: "89", verdict: "exploitable", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }], rationale: "x", nextChecks: [] }]);
  const fp = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0].fingerprint;
  const run = openRun(t, "verify");
  writeFileSync(join(run.runDir, "draft.verify.json"), JSON.stringify({ candidates: [{ findingFingerprint: fp, ...verifyDraft() }] }));
  assembleVerify(t, run.runDir);
  const f = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0];
  assert.equal(f.status, "confirmed");
  assert.equal(f.verification.pocReady, true);
});

test("verify-assemble rejects a confirmed verdict missing the fp-gate fields", () => {
  const t = tmp();
  upsertFindings(t, [{ source: "threat-hunt", refId: "v", title: "t", severity: "high", cwe: "89", verdict: "exploitable", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }], rationale: "x", nextChecks: [] }]);
  const fp = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0].fingerprint;
  const run = openRun(t, "verify");
  for (const missing of ["negativePoc", "devilsAdvocate"]) {
    const d = verifyDraft(); delete d[missing];
    writeFileSync(join(run.runDir, "draft.verify.json"), JSON.stringify({ candidates: [{ findingFingerprint: fp, ...d }] }));
    const r = spawnSync("node", [cmd("verify-assemble"), "--target", t, "--run-dir", run.runDir], { encoding: "utf8" });
    assert.notEqual(r.status, 0, `confirmed-exploitable without ${missing} must be rejected`);
  }
});

// ---- closed-verdict enforcement on the promoters ----------------------------

const cases = [
  { script: "threat-hunt-finalize", draftFile: "draft.threat-hunt.json", kind: "threat-hunt", body: { candidates: [{ threatId: "t1", candidateId: "t1", verdict: "definitely-bad", rationale: "x".repeat(220), evidenceAnchors: [{ filePath: "a.js", startLine: 1 }] }] } },
  { script: "systems-hunt-finalize", draftFile: "draft.systems-hunt.json", kind: "systems-hunt", body: { candidates: [{ candidateId: "c1", verdict: "definitely-bad", rationale: "x".repeat(220), evidenceAnchors: [{ filePath: "a.c", startLine: 1 }] }] } },
  { script: "taint-analysis-assemble", draftFile: "draft.findings.json", kind: "taint", body: { findings: [{ id: "f1", verdict: "definitely-bad", rationale: "x".repeat(140), evidence: [{ filePath: "a.js", startLine: 1 }] }] } }
];

for (const c of cases) {
  test(`${c.script} rejects a verdict outside its closed set`, () => {
    const t = tmp();
    const run = openRun(t, c.kind);
    writeFileSync(join(run.runDir, c.draftFile), JSON.stringify(c.body));
    const r = spawnSync("node", [cmd(c.script), "--target", t, "--run-dir", run.runDir], { encoding: "utf8" });
    assert.notEqual(r.status, 0, "an out-of-set verdict must fail the gate");
    assert.match(r.stderr, /invalid verdict|must be one of/i);
  });
}
