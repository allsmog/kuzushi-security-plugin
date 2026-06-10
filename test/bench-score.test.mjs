// scoreFindings is the benchmark's measurement instrument. These pin the three
// metrics that matter — recall (missed bugs), precision (false alarms), and
// falseProofRate (proving a non-bug, the soundness failure differential testing
// guards) — plus the matching rules they depend on.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreFindings, _internals } from "../scripts/lib/bench-score.mjs";

const GT = {
  expectations: [
    { id: "v1", kind: "vuln", cwe: "CWE-78", filePath: "target/server.js", line: 9 },
    { id: "v2", kind: "vuln", cwe: "CWE-22", filePath: "target/files.py", line: 13 },
    { id: "decoy", kind: "safe", cwe: "CWE-78", filePath: "target/server.js", line: 16 }
  ]
};

function f(over) {
  return { fingerprint: "x".repeat(16), status: "open", evidence: [{ filePath: over.filePath, startLine: over.line }], ...over };
}

test("a perfect run: recall 1, precision 1, no false proofs", () => {
  const actual = [
    f({ cwe: "CWE-78", filePath: "target/server.js", line: 9, status: "proven" }),
    f({ cwe: "CWE-22", filePath: "target/files.py", line: 13, status: "confirmed" })
  ];
  const s = scoreFindings(GT, actual);
  assert.equal(s.recall, 1);
  assert.equal(s.precision, 1);
  assert.equal(s.falseProofs, 0);
  assert.equal(s.falseNegatives, 0);
});

test("a missed bug lowers recall but not precision", () => {
  const actual = [f({ cwe: "CWE-78", filePath: "target/server.js", line: 9 })];
  const s = scoreFindings(GT, actual);
  assert.equal(s.truePositives, 1);
  assert.equal(s.falseNegatives, 1);
  assert.equal(s.recall, 0.5);
  assert.equal(s.precision, 1);
});

test("flagging a safe decoy is a false positive and lowers precision", () => {
  const actual = [
    f({ cwe: "CWE-78", filePath: "target/server.js", line: 9 }),
    f({ cwe: "CWE-22", filePath: "target/files.py", line: 13 }),
    f({ cwe: "CWE-78", filePath: "target/server.js", line: 16 }) // hits the decoy
  ];
  const s = scoreFindings(GT, actual);
  assert.equal(s.falsePositives, 1);
  assert.equal(s.recall, 1);
  assert.equal(s.precision, 2 / 3 === Number((2 / 3).toFixed(4)) ? s.precision : s.precision); // 0.6667
  assert.equal(s.precision, 0.6667);
});

test("a PROVEN hit on a decoy is a false proof — the soundness metric", () => {
  const actual = [f({ cwe: "CWE-78", filePath: "target/server.js", line: 16, status: "proven" })];
  const s = scoreFindings(GT, actual);
  assert.equal(s.falseProofs, 1);
  assert.equal(s.falseProofRate, 1);
});

test("a rejected/reviewed finding on a decoy is the tool correctly declining — not an FP", () => {
  const actual = [
    f({ cwe: "CWE-78", filePath: "target/server.js", line: 9 }),
    f({ cwe: "CWE-22", filePath: "target/files.py", line: 13 }),
    f({ cwe: "CWE-78", filePath: "target/server.js", line: 16, status: "rejected" })
  ];
  const s = scoreFindings(GT, actual);
  assert.equal(s.falsePositives, 0);
  assert.equal(s.precision, 1);
});

test("CWE mismatch prevents a spurious match when matchCwe is on", () => {
  // A SQLi finding sitting on the cmdi line should not be credited for v1.
  const actual = [f({ cwe: "CWE-89", filePath: "target/server.js", line: 9 })];
  const s = scoreFindings(GT, actual);
  assert.equal(s.truePositives, 0); // wrong CWE, no credit
});

test("path suffix matching: absolute actual path matches relative ground truth", () => {
  assert.equal(_internals.samePath("/repo/target/server.js", "target/server.js"), true);
  assert.equal(_internals.samePath("target/server.js", "other/server.js"), false);
});

test("strict mode counts an unmatched active finding as a false positive", () => {
  const actual = [
    f({ cwe: "CWE-78", filePath: "target/server.js", line: 9 }),
    f({ cwe: "CWE-22", filePath: "target/files.py", line: 13 }),
    f({ cwe: "CWE-94", filePath: "target/other.js", line: 5 }) // not in ground truth
  ];
  const lenient = scoreFindings(GT, actual);
  const strict = scoreFindings(GT, actual, { strict: true });
  assert.equal(lenient.falsePositives, 0);
  assert.equal(strict.falsePositives, 1);
  assert.equal(strict.unmatchedCount, 1);
});

test("accepts a findings.json document or a bare array", () => {
  const doc = { findings: [f({ cwe: "CWE-78", filePath: "target/server.js", line: 9 })] };
  assert.equal(scoreFindings(GT, doc).truePositives, 1);
});
