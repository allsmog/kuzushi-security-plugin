// rankCatalog decides which CWEs /taint-analysis hunts first. These pin the
// threat-intel feedback loop: a bug class that /threat-intel surfaced as a live
// CVE for this stack should outrank a generic catalog entry, because empirical
// evidence the class is exploitable in code like this is a stronger prior.

import { test } from "node:test";
import assert from "node:assert/strict";
import { rankCatalog, normalizeCweId } from "../scripts/lib/taint-catalog.mjs";

// Minimal fake catalog so the test is independent of the shipped JSON.
const ENTRIES = [
  { cwe: "CWE-89", taintClass: "sql-injection", languages: ["javascript"], sourceSignals: ["req.body"], sinkSignals: ["query("], structuralQueries: ["execute("], sanitizerSignals: [] },
  { cwe: "CWE-79", taintClass: "xss", languages: ["javascript"], sourceSignals: ["req.query"], sinkSignals: ["innerHTML"], structuralQueries: ["render("], sanitizerSignals: [] },
  { cwe: "CWE-502", taintClass: "deserialization", languages: ["javascript"], sourceSignals: ["body"], sinkSignals: ["unserialize("], structuralQueries: ["pickle.loads("], sanitizerSignals: [] }
];

const context = { languages: ["javascript"], frameworks: [], entryPoints: [], ormOrDb: [] };

test("a threat-intel CVE CWE is boosted above an equal generic entry", () => {
  const threatIntel = { invariants: [{ statement: "untrusted body reaches unserialize", cwe: "CWE-502", sinkSignals: ["unserialize("] }] };
  const ranked = rankCatalog({ context, threatIntel, entries: ENTRIES });
  assert.equal(ranked[0].cwe, "CWE-502", "the live-CVE CWE should rank first");
  assert.ok(ranked[0].reasons.includes("threat-intel CVE"));
});

test("without threat-intel the deserialization entry is not specially boosted", () => {
  const ranked = rankCatalog({ context, entries: ENTRIES });
  const deser = ranked.find((e) => e.cwe === "CWE-502");
  assert.ok(!deser.reasons.includes("threat-intel CVE"));
});

test("intel CWE ids are normalized (89, CWE_89, cwe-89 all match)", () => {
  for (const form of ["502", "CWE_502", "cwe-502"]) {
    const ranked = rankCatalog({ context, threatIntel: { invariants: [{ cwe: form }] }, entries: ENTRIES });
    assert.ok(ranked.find((e) => e.cwe === "CWE-502").reasons.includes("threat-intel CVE"), `form ${form} should match`);
  }
  assert.equal(normalizeCweId("cwe-502"), "CWE-502");
});
