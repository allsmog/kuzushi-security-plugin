// Guards the SCORER + the recorded findings snapshot — NOT that the producers fire.
//
// Honesty note (Lever 0): the findings.json files this scores are hand-recorded to
// match expected.json, so the recall=1/precision=1 here is a property of the scorer
// wiring and the frozen snapshot, not evidence that any producer surfaced the bug. The
// producer-firing regression net is the LIVE recall test (bench-live-recall.test.mjs),
// which runs the deterministic prepare phase and asserts the planted site is routed.
// Keep both: this pins the scorer's contract; that pins the producers' behavior.

import { test } from "node:test";
import assert from "node:assert/strict";
import { runBenchmark } from "../scripts/cmd/benchmark.mjs";

test("the bundled corpus scores a perfect recall/precision with no false proofs", () => {
  const r = runBenchmark({ matchCwe: true });
  assert.ok(r.cases.length >= 2, "expected at least two corpus cases");
  assert.equal(r.corpus.recall, 1, "a recorded case is missing its planted bug");
  assert.equal(r.corpus.precision, 1, "a recorded case flagged a safe decoy");
  assert.equal(r.corpus.falseProofs, 0, "a recorded case proved a non-bug");
});

test("each case has both a vuln and a safe decoy (recall AND precision pressure)", () => {
  const r = runBenchmark({ matchCwe: true });
  for (const c of r.cases) {
    assert.ok(c.vulnTotal >= 1, `${c.case}: no planted vuln`);
    assert.ok(c.decoyTotal >= 1, `${c.case}: no safe decoy`);
  }
});
