// Regression: x-ray evidence must stay bounded. On a real decompiled target
// (jadx / RN bundle) a single "line" can be hundreds of KB — e.g. a Kotlin
// `@Metadata(...)` blob — which bloated entry-points.md to 500KB+ and buried the
// real boundaries. clipEvidence collapses whitespace and caps the length while
// keeping a short, locatable snippet (file:line is the real anchor).

import { test } from "node:test";
import assert from "node:assert/strict";
import { clipEvidence, MAX_EVIDENCE_CHARS } from "../scripts/cmd/x-ray.mjs";

test("clipEvidence leaves short evidence intact (just collapses whitespace)", () => {
  assert.equal(clipEvidence("r1 = r0.redirectUri;"), "r1 = r0.redirectUri;");
  assert.equal(clipEvidence("  a\t b\n c "), "a b c");
  assert.equal(clipEvidence(undefined), "");
});

test("clipEvidence caps a pathological decompiled line (the 236KB @Metadata bug)", () => {
  const blob = "@Metadata(d1 = {" + "\\u0000\\u0002".repeat(60000) + "})"; // ~720KB single line
  const out = clipEvidence(blob);
  assert.ok(out.length <= MAX_EVIDENCE_CHARS + 40, `capped (got ${out.length})`);
  assert.match(out, /… \[truncated \d+ chars\]$/, "marks that it was truncated");
  assert.ok(out.startsWith("@Metadata"), "keeps the locatable prefix");
});
