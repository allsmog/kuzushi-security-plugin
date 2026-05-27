// Regression: threat-model-assemble silently dropped any threat whose STRIDE
// category had a space ("Information Disclosure", "Elevation of Privilege",
// "Denial of Service") because the normalizer only mapped "_" → "-", not spaces.
// On the real dailypay run that lost 7 of 14 threats — including the two
// highest-severity ones (token extraction, cookie fanout). It also flattened
// every severity to "medium" because impact arrived as prose ("CRITICAL — …")
// and only an exact "critical" matched. Both are pinned here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeStrideCategory, normalizeImpact } from "../scripts/cmd/threat-model-assemble.mjs";

test("normalizeStrideCategory accepts spaced / cased / underscored spellings", () => {
  // The exact strings the real agent emitted (title-case, spaces) must survive.
  assert.equal(normalizeStrideCategory("Information Disclosure"), "information-disclosure");
  assert.equal(normalizeStrideCategory("Elevation of Privilege"), "elevation-of-privilege");
  assert.equal(normalizeStrideCategory("Denial of Service"), "denial-of-service");
  assert.equal(normalizeStrideCategory("information_disclosure"), "information-disclosure");
  assert.equal(normalizeStrideCategory("Spoofing"), "spoofing");
  assert.equal(normalizeStrideCategory("  Tampering  "), "tampering");
  // genuinely unknown categories still return null (so the gate still rejects junk)
  assert.equal(normalizeStrideCategory("not-a-stride-thing"), null);
  assert.equal(normalizeStrideCategory(""), null);
});

test("normalizeImpact reads the leading severity word out of prose", () => {
  assert.equal(normalizeImpact("CRITICAL — full account takeover; drains EWA balance"), "critical");
  assert.equal(normalizeImpact("HIGH - MITM reads Bearer tokens"), "high");
  assert.equal(normalizeImpact("MEDIUM-HIGH — session replay exposure"), "medium");
  assert.equal(normalizeImpact("critical"), "critical");      // clean enum still works
  assert.equal(normalizeImpact("low"), "low");
  assert.equal(normalizeImpact("unspecified prose"), "medium"); // safe default
});
