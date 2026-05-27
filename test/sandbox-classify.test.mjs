// classifyResult is the deterministic proof-verdict gate for /poc. These pin the
// soundness fix surfaced by an end-to-end Docker dogfood: a harness that never
// loaded (MODULE_NOT_FOUND, exit 1) was being scored "exploited" — a false proof —
// because the expected-nonzero / textual-crash heuristics ran before the
// build-failure gate. Build failures must never read as exploitation; only a
// genuine signal death may.

import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyResult } from "../scripts/lib/sandbox.mjs";

const MODULE_NOT_FOUND =
  "Error: Cannot find module '/work/harness.js'\n    at Module._resolveFilename (node:internal/modules/cjs/loader)\n  code: 'MODULE_NOT_FOUND'";

test("MODULE_NOT_FOUND with exit 1 is harness-failed-build, not exploited (the regressed false positive)", () => {
  // expectedSignal:"nonzero" is exactly what the dogfooded harness declared.
  const r = classifyResult({ exitCode: 1, signal: null, stdout: "", stderr: MODULE_NOT_FOUND }, "nonzero");
  assert.equal(r.proofVerdict, "harness-failed-build");
  assert.equal(r.proofLevel, 1);
});

test("a compile/syntax failure is not a proof even with expectedSignal nonzero", () => {
  const r = classifyResult({ exitCode: 1, signal: null, stdout: "", stderr: "SyntaxError: Unexpected token" }, "nonzero");
  assert.equal(r.proofVerdict, "harness-failed-build");
});

test("a genuine signal death still outranks a build-fail substring", () => {
  // SIGSEGV is real exploitation evidence; build-fail noise in output must not mask it.
  const r = classifyResult({ exitCode: null, signal: "SIGSEGV", stdout: "cannot find symbol foo", stderr: "" }, "crash");
  assert.equal(r.proofVerdict, "exploited");
  assert.equal(r.proofLevel, 4);
});

test("expected-nonzero exit with a clean (non-build-fail) trace is still exploited", () => {
  // The legitimate path: harness loaded, asserted the bug, exit 1 on purpose.
  const r = classifyResult(
    { exitCode: 1, signal: null, stdout: "EXPLOITED CWE-78: injected marker observed", stderr: "" },
    "nonzero"
  );
  assert.equal(r.proofVerdict, "exploited");
  assert.equal(r.proofLevel, 3);
});

test("textual crash pattern (ASan) scores exploited", () => {
  const r = classifyResult({ exitCode: 1, signal: null, stdout: "", stderr: "==1==ERROR: AddressSanitizer: heap-buffer-overflow" }, "crash");
  assert.equal(r.proofVerdict, "exploited");
});

test("clean run with no repro is not-reproduced", () => {
  const r = classifyResult({ exitCode: 0, signal: null, stdout: "not reproduced: marker absent", stderr: "" }, "nonzero");
  assert.equal(r.proofVerdict, "not-reproduced");
  assert.equal(r.proofLevel, 2);
});

test("timeout and spawn errors stay level-1 errors, never exploited", () => {
  assert.equal(classifyResult({ timedOut: true }).proofVerdict, "timeout");
  assert.equal(classifyResult({ spawnError: true, exitCode: null }).proofVerdict, "error");
  assert.equal(classifyResult({ skipped: true, reason: "no backend" }).proofVerdict, "error");
});
