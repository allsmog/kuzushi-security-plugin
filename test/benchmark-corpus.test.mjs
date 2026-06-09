// Guards the bundled benchmark corpus: every recorded case must score a clean
// recall=1, precision=1, zero false proofs. If a future change to the scorer or a
// case fixture regresses this, CI fails loudly — the corpus is the regression net
// for the producers, so the net itself must stay sound.

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
