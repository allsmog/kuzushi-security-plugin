// majorityVerifyVerdict is the host-side conservative vote over independent
// verifier passes. These pin that it needs a STRICT majority to claim exploitable
// and collapses a split to inconclusive (never over-claiming), plus the
// verify-assemble integration that the HOST — not the agent — decides the verdict.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { majorityVerifyVerdict } from "../scripts/lib/voting.mjs";
import { assembleVerify } from "../scripts/cmd/verify-assemble.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { storeFor, openRun } from "../scripts/lib/artifact-store.mjs";

test("strict majority for exploitable; otherwise conservative", () => {
  assert.equal(majorityVerifyVerdict(["confirmed-exploitable", "confirmed-exploitable", "not-exploitable"]).verdict, "confirmed-exploitable");
  assert.equal(majorityVerifyVerdict(["not-exploitable", "not-exploitable", "confirmed-exploitable"]).verdict, "not-exploitable");
  // 1-1 split → inconclusive, not exploitable (no over-claiming)
  assert.equal(majorityVerifyVerdict(["confirmed-exploitable", "not-exploitable"]).verdict, "inconclusive");
  // exactly half exploitable is NOT a strict majority → inconclusive
  assert.equal(majorityVerifyVerdict(["confirmed-exploitable", "confirmed-exploitable", "not-exploitable", "not-exploitable"]).verdict, "inconclusive");
});

test("records agreement + tally; empty/garbage → inconclusive", () => {
  const r = majorityVerifyVerdict(["confirmed-exploitable", "confirmed-exploitable", "inconclusive"]);
  assert.equal(r.verdict, "confirmed-exploitable");
  assert.equal(r.total, 3);
  assert.equal(r.agreement, Number((2 / 3).toFixed(3)));
  assert.deepEqual(majorityVerifyVerdict([]).verdict, "inconclusive");
  assert.equal(majorityVerifyVerdict(["bogus", "junk"]).total, 0);
});

function seedFinding(t) {
  upsertFindings(t, [{ source: "threat-hunt", refId: "v", title: "t", severity: "high", cwe: "89", verdict: "exploitable", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }], rationale: "x", nextChecks: [] }]);
  return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0].fingerprint;
}

test("verify-assemble: HOST computes the majority — a split collapses to inconclusive even if the agent wrote 'confirmed'", () => {
  const t = mkdtempSync(join(tmpdir(), "kz-vote-"));
  const fp = seedFinding(t);
  const run = openRun(t, "verify");
  // Agent claims confirmed-exploitable but supplies a 1-1 split vote → host overrides.
  writeFileSync(join(run.runDir, "draft.verify.json"), JSON.stringify({ candidates: [{
    findingFingerprint: fp,
    verdict: "confirmed-exploitable",
    votes: ["confirmed-exploitable", "not-exploitable"],
    confidence: 0.9,
    rationale: "r".repeat(160)
  }] }));
  assembleVerify(t, run.runDir);
  const f = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0];
  assert.equal(f.verification.verdict, "inconclusive", "host majority overrode the agent's claim");
  assert.equal(f.verification.voting.total, 2);
  assert.equal(f.verification.voting.agreement, 0); // 1-1 split → 0 agreement on the winner
});

test("verify-assemble: a 2/3 exploitable majority lands confirmed (with full fp-gate evidence)", () => {
  const t = mkdtempSync(join(tmpdir(), "kz-vote2-"));
  const fp = seedFinding(t);
  const run = openRun(t, "verify");
  writeFileSync(join(run.runDir, "draft.verify.json"), JSON.stringify({ candidates: [{
    findingFingerprint: fp,
    verdict: "not-exploitable", // agent's stated field is ignored — votes decide
    votes: ["confirmed-exploitable", "confirmed-exploitable", "not-exploitable"],
    confidence: 0.8,
    pocSketch: { payload: "X", howToTrigger: "call f" },
    evidenceAnchors: [{ filePath: "a.js", startLine: 1 }],
    negativePoc: "a benign in-spec input is handled safely, proving the trigger discriminates",
    devilsAdvocate: "the opposite verdict would argue a guard exists, but none is present on the traced path",
    rationale: "r".repeat(160)
  }] }));
  assembleVerify(t, run.runDir);
  const f = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0];
  assert.equal(f.verification.verdict, "confirmed-exploitable");
  assert.equal(f.status, "confirmed");
  assert.equal(f.verification.voting.agreement, Number((2 / 3).toFixed(3)));
});
