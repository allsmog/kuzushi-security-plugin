// Contract for the eval harness's scoring helpers — the part that decides whether an
// agent run "found" the planted bug. The deep-hunt lane must score a cross-file flow as
// a HIT when the expected line is the SINK or any intermediate hop (not just evidence[0]),
// or the harness would under-count exactly the interprocedural bugs it exists to measure.
// No LLM here — pure matching logic (the harness's main() is import-guarded).

import { test } from "node:test";
import assert from "node:assert/strict";
import { anchorMatch, findingHitsExpected } from "../eval/eval.mjs";

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
