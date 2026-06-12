// Contract for the eval harness's scoring helpers — the part that decides whether an
// agent run "found" the planted bug. The deep-hunt lane must score a cross-file flow as
// a HIT when the expected line is the SINK or any intermediate hop (not just evidence[0]),
// or the harness would under-count exactly the interprocedural bugs it exists to measure.
// No LLM here — pure matching logic (the harness's main() is import-guarded).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  aggregateEvalRows,
  anchorMatch,
  expectedContextInDeepHuntAnchors,
  expectedContextInDeepScanPrep,
  expectedVulnerabilities,
  expectedSafeDecoys,
  falseProofStats,
  findingHitsExpected
} from "../eval/eval.mjs";

const expected = (over = {}) => ({ filePath: "src/db.js", line: 42, ...over });

test("anchorMatch (deep-scan lane): matches the finding's primary anchor within tolerance", () => {
  const f = { evidence: [{ filePath: "src/db.js", startLine: 45 }] };
  assert.equal(anchorMatch(expected(), f), true, "within ±6 lines is a hit");
  assert.equal(anchorMatch(expected(), { evidence: [{ filePath: "src/db.js", startLine: 99 }] }), false, "far line misses");
  assert.equal(anchorMatch(expected(), { evidence: [{ filePath: "src/other.js", startLine: 42 }] }), false, "wrong file misses");
});

test("findingHitsExpected (deep-hunt lane): hits when the expected line is the SINK, not evidence[0]", () => {
  // source is evidence[0] in a different file; the planted bug line is the sink.
  const f = { evidence: [{ filePath: "src/handler.js", startLine: 12 }, { filePath: "src/db.js", startLine: 42 }] };
  assert.equal(findingHitsExpected(expected(), f), true, "sink anchor (evidence[1]) counts as a hit");
});

test("findingHitsExpected: hits when the expected line is an intermediate hop in the path", () => {
  const f = {
    evidence: [{ filePath: "src/handler.js", startLine: 12 }, { filePath: "src/db.js", startLine: 90 }],
    evidenceGraph: { nodes: [
      { filePath: "src/handler.js", startLine: 12, role: "source" },
      { filePath: "src/svc.js", startLine: 41, role: "passes value" },   // the planted line is here
      { filePath: "src/db.js", startLine: 90, role: "sink" }
    ] }
  };
  assert.equal(findingHitsExpected(expected({ filePath: "src/svc.js", line: 42 }), f), true, "a middle hop within tolerance is a hit");
});

test("findingHitsExpected: misses when no anchor or path node matches the expected file/line", () => {
  const f = {
    evidence: [{ filePath: "src/handler.js", startLine: 12 }],
    evidenceGraph: { nodes: [{ filePath: "src/handler.js", startLine: 12 }, { filePath: "src/cache.js", startLine: 7 }] }
  };
  assert.equal(findingHitsExpected(expected(), f), false, "expected db.js:42 not on the path → miss");
});

test("expectedVulnerabilities supports both legacy expected[] and bench expectations[]", () => {
  assert.deepEqual(
    expectedVulnerabilities({ expected: [{ filePath: "a.js", line: 1 }] }),
    [{ filePath: "a.js", line: 1 }],
    "legacy eval fixtures still load"
  );
  assert.deepEqual(
    expectedVulnerabilities({ expectations: [
      { id: "real", kind: "vuln", filePath: "a.js", line: 1 },
      { id: "decoy", kind: "safe", filePath: "a.js", line: 9 }
    ] }),
    [{ id: "real", kind: "vuln", filePath: "a.js", line: 1 }],
    "safe decoys are precision pressure, not expected hits"
  );
  assert.deepEqual(
    expectedSafeDecoys({ expectations: [
      { id: "real", kind: "vuln", filePath: "a.js", line: 1 },
      { id: "decoy", kind: "safe", filePath: "a.js", line: 9 }
    ] }),
    [{ id: "decoy", kind: "safe", filePath: "a.js", line: 9 }],
    "safe decoys are retained for false-proof scoring"
  );
});

test("aggregateEvalRows separates routing recall from reasoning recall", () => {
  const agg = aggregateEvalRows([
    { name: "routed-found", runs: [{ routed: true, inContext: true, siteInContext: true, found: true, confirmed: true, proven: false, provenTotal: 1, falseProofs: 0, extraConfirmed: 0, cost: 2 }] },
    { name: "routed-missed", runs: [{ routed: true, inContext: true, siteInContext: false, found: false, confirmed: false, proven: false, provenTotal: 1, falseProofs: 1, extraConfirmed: 1, cost: 3 }] },
    { name: "not-routed", runs: [{ routed: false, inContext: false, siteInContext: false, found: false, confirmed: false, proven: false, provenTotal: 0, falseProofs: 0, extraConfirmed: 0, cost: 1 }] }
  ]);

  assert.equal(agg.routingRecall, 2 / 3, "routing sees two of three cases");
  assert.equal(agg.reasoningRecall, 1 / 2, "reasoning denominator is only the in-context cases");
  assert.equal(agg.siteContextRecall, 1 / 3, "site-context tracks exact obligation/lead/anchor coverage");
  assert.equal(agg.siteReasoningRecall, 1, "site reasoning denominator is only site-context runs");
  assert.equal(agg.blindRecall, 1 / 3, "end-to-end recall remains over the full corpus");
  assert.equal(agg.confirmedOnTarget, 1 / 3);
  assert.equal(agg.falseProofRate, 1 / 2);
  assert.equal(agg.extraConfirmedPerCase, 1 / 3);
  assert.equal(agg.costPerTrueFinding, 6);
});

test("falseProofStats counts proven findings on safe decoys", () => {
  const findings = [
    { status: "proven", evidence: [{ filePath: "src/safe.js", startLine: 11 }] },
    { status: "proven", evidence: [{ filePath: "src/other.js", startLine: 1 }] },
    { status: "reviewed", poc: { proofVerdict: "exploited" }, evidence: [{ filePath: "src/safe.js", startLine: 11 }] }
  ];
  const stats = falseProofStats(findings, [{ kind: "safe", filePath: "src/safe.js", line: 9 }]);
  assert.equal(stats.provenTotal, 2, "only proven/empirical findings count in the denominator");
  assert.equal(stats.falseProofs, 1, "a proven hit on a safe decoy is a false proof");
  assert.equal(stats.falseProofRate, 0.5);
});

test("expectedContextInDeepScanPrep distinguishes file context from obligation site context", () => {
  const prep = {
    files: [
      { filePath: "src/a.c", obligations: [{ line: 12, kind: "raw-copy" }] },
      { filePath: "src/b.c", obligations: [] }
    ],
    obligationOverlay: { obligations: [{ filePath: "src/late.c", line: 90, kind: "lifetime-free" }] },
    cpgLeads: [{ filePath: "src/flow.c", sourceLine: 20, sinkLine: 35 }]
  };
  assert.deepEqual(
    expectedContextInDeepScanPrep([expected({ filePath: "src/b.c", line: 200 })], prep),
    { fileContext: true, siteContext: false },
    "reading the file is not the same as routing the planted site"
  );
  assert.deepEqual(
    expectedContextInDeepScanPrep([expected({ filePath: "src/late.c", line: 94 })], prep),
    { fileContext: false, siteContext: true },
    "long-tail overlay sites count as site context even outside the file budget"
  );
  assert.deepEqual(
    expectedContextInDeepScanPrep([expected({ filePath: "src/flow.c", line: 36 })], prep),
    { fileContext: false, siteContext: true },
    "CPG source/sink leads count as site context"
  );
});

test("expectedContextInDeepHuntAnchors distinguishes file anchors from exact site anchors", () => {
  const anchors = [
    { filePath: "src/a.js", line: 1, kind: "file" },
    { filePath: "src/b.js", line: 40, kind: "sink" }
  ];
  assert.deepEqual(
    expectedContextInDeepHuntAnchors([expected({ filePath: "src/a.js", line: 90 })], anchors),
    { fileContext: true, siteContext: false }
  );
  assert.deepEqual(
    expectedContextInDeepHuntAnchors([expected({ filePath: "src/b.js", line: 42 })], anchors),
    { fileContext: true, siteContext: true }
  );
});
