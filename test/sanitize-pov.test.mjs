// End-to-end contract for /sanitize-pov: given a memory finding and a harness that
// drives it, the finalize must compile WITH sanitizers, run, and let the sanitizer
// abort promote the finding to `proven` with the exact CWE — and must NOT promote a
// clean run or a build failure (no false proofs). Gated on a C compiler.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { detectToolchain } from "../scripts/lib/sanitizers.mjs";
import { finalizeSanitizePov } from "../scripts/cmd/sanitize-pov-finalize.mjs";

const tc = detectToolchain();
const CC = tc.cc;

function repoWithFinding(cwe = "CWE-121") {
  const t = mkdtempSync(join(tmpdir(), "kz-spov-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
  const doc = upsertFindings(t, [{ source: "systems-hunt", refId: "s1", title: "overflow in f", severity: "high",
    cwe, verdict: "exploitable", evidence: [{ filePath: "f.c", startLine: 1 }], rationale: "x" }]);
  return { t, fp: doc.findings[0].fingerprint };
}
function runDirWithDraft(t, draft) {
  const rd = join(storeFor(t).runsDir, "spov-test");
  mkdirSync(rd, { recursive: true });
  writeFileSync(join(rd, "draft.sanitize-pov.json"), JSON.stringify(draft));
  return rd;
}
function finding(t, fp) {
  return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings.find((f) => f.fingerprint === fp);
}

test("sanitize-pov: a sanitizer abort promotes the finding to proven with the sanitizer's CWE", { skip: CC ? false : "no C compiler" }, async () => {
  const { t, fp } = repoWithFinding("CWE-119"); // start vague; sanitizer should sharpen it
  const rd = runDirWithDraft(t, { trustLocal: true, povs: [{
    findingFingerprint: fp, language: "c",
    harnessFiles: [{ name: "harness.c", content: "#include <string.h>\nint main(){char b[8];volatile int n=64;memset(b,'A',n);return b[0];}\n" }],
    buildRunCommand: `${CC} -fsanitize=address,undefined -g -O0 harness.c -o h && ./h`
  }] });
  const res = await finalizeSanitizePov(t, rd, { trustLocal: true, backend: "local" });
  assert.equal(res.status, "completed");
  assert.equal(res.provenCount, 1, "the overflow must be sanitizer-proven");
  const f = finding(t, fp);
  assert.equal(f.status, "proven");
  assert.equal(f.poc.proofVerdict, "exploited");
  assert.ok(f.poc.sanitizer, "a sanitizer block is attached");
  assert.match(f.poc.sanitizer.cwe, /CWE-(121|787)/, "CWE sharpened from the report");
  assert.match(f.cwe, /CWE-(121|787)/, "finding CWE updated to the proven class");
});

test("sanitize-pov: a clean harness does NOT promote (no false proof)", { skip: CC ? false : "no C compiler" }, async () => {
  const { t, fp } = repoWithFinding();
  const rd = runDirWithDraft(t, { trustLocal: true, povs: [{
    findingFingerprint: fp, language: "c",
    harnessFiles: [{ name: "harness.c", content: "int main(){return 0;}\n" }],
    buildRunCommand: `${CC} -fsanitize=address,undefined -g harness.c -o h && ./h`
  }] });
  const res = await finalizeSanitizePov(t, rd, { trustLocal: true, backend: "local" });
  assert.equal(res.provenCount, 0, "a clean run proves nothing");
  assert.notEqual(finding(t, fp).status, "proven");
});

test("sanitize-pov: a build failure is harness-failed-build, never proven", { skip: CC ? false : "no C compiler" }, async () => {
  const { t, fp } = repoWithFinding();
  const rd = runDirWithDraft(t, { trustLocal: true, povs: [{
    findingFingerprint: fp, language: "c",
    harnessFiles: [{ name: "harness.c", content: "int main(){ this is not c }\n" }],
    buildRunCommand: `${CC} -fsanitize=address,undefined -g harness.c -o h && ./h`
  }] });
  const res = await finalizeSanitizePov(t, rd, { trustLocal: true, backend: "local" });
  assert.equal(res.provenCount, 0);
  assert.notEqual(finding(t, fp).status, "proven");
});
