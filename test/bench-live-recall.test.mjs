// LIVE candidate-recall gate — the honest regression net for the PRODUCERS.
//
// The integrity problem this fixes (Lever 0): the corpus scorer test
// (benchmark-corpus.test.mjs) scores frozen, hand-recorded `findings.json` files that
// were authored to match `expected.json`. Its recall=1.0 is therefore TAUTOLOGICAL — it
// proves the scorer wiring works, NOT that any producer actually fires. A producer could
// silently stop surfacing a planted bug and that test would still pass.
//
// This test runs the producers' DETERMINISTIC prepare phase live (no LLM) on every
// bundled case and asserts the planted vulnerable site is actually surfaced. If a change
// breaks a producer's routing, `npm test` fails here — which is what a regression net is
// supposed to do. It also pins the file-vs-site recall split so the file-level number
// can't silently drift back into "ranked the file" masquerading as "found the site".

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runCase } from "../bench/run.mjs";

const CASES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "bench", "cases");

function cases() {
  return readdirSync(CASES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(CASES_DIR, d.name, "expected.json")))
    .map((d) => d.name)
    .sort();
}

// Run every case once; cache so the (slowish) sweep prepare runs a single time.
let RESULTS;
function results() {
  if (!RESULTS) RESULTS = cases().map((n) => runCase(join(CASES_DIR, n), n));
  return RESULTS;
}

test("the live deep lane routes EVERY planted bug file (producers actually fire)", () => {
  const rs = results();
  assert.ok(rs.length >= 8, `expected the full bundled corpus, saw ${rs.length} cases`);
  const missed = rs.filter((r) => r.deepRecall < 1).map((r) => r.name);
  assert.equal(missed.length, 0, `deep lane failed to route the bug file for: ${missed.join(", ")}`);
});

test("the deep lane never regresses below the pattern lane on any case", () => {
  for (const r of results()) {
    assert.ok(r.deepRecall >= r.patternRecall,
      `${r.name}: deep recall ${r.deepRecall} < pattern ${r.patternRecall}`);
  }
});

// Site-level (line-aware) recall is the honest number. It is allowed to be below
// file-level (some bugs are ranked-but-not-line-pinned), but pin a floor so it can't
// silently collapse — and so the file-vs-site gap stays auditable.
test("overall site-level recall clears the honest floor", () => {
  const rs = results();
  const totExpected = rs.reduce((a, r) => a + r.expected, 0) || 1;
  const site = rs.reduce((a, r) => a + r.deepSiteRecall * r.expected, 0) / totExpected;
  const file = rs.reduce((a, r) => a + r.deepRecall * r.expected, 0) / totExpected;
  assert.ok(site >= 0.8, `site-level deep recall ${(site * 100).toFixed(1)}% below 80% floor`);
  assert.ok(file >= site, "file-level recall should be ≥ site-level recall");
});
