// classifyResult is the deterministic proof-verdict gate for /poc. These pin the
// soundness fix surfaced by an end-to-end Docker dogfood: a harness that never
// loaded (MODULE_NOT_FOUND, exit 1) was being scored "exploited" — a false proof —
// because the expected-nonzero / textual-crash heuristics ran before the
// build-failure gate. Build failures must never read as exploitation; only a
// genuine signal death may.

import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyResult, classifyDifferential, classifyRuns } from "../scripts/lib/sandbox.mjs";

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

// classifyDifferential is the negative-control gate: a harness that fires on the
// attack AND on the benign negativePoc is NOT a proof. These pin that the strongest
// rung (level 5) requires the negative control to stay clean.
const FIRES = { exitCode: null, signal: "SIGABRT", stdout: "", stderr: "" };
const CLEAN = { exitCode: 0, signal: null, stdout: "ok", stderr: "" };

test("attack fires + benign clean → discriminated proof at level 5", () => {
  const r = classifyDifferential(FIRES, CLEAN, "crash");
  assert.equal(r.proofVerdict, "exploited");
  assert.equal(r.proofLevel, 5);
  assert.equal(r.differential, "discriminated");
});

test("attack fires + benign ALSO fires → non-discriminating, NOT a proof", () => {
  const r = classifyDifferential(FIRES, FIRES, "crash");
  assert.equal(r.proofVerdict, "non-discriminating");
  assert.equal(r.proofLevel, 2);
  assert.equal(r.differential, "benign-also-fired");
});

test("attack fires + benign couldn't run cleanly → attack level kept, flagged inconclusive", () => {
  const benignBuildFail = { exitCode: 1, signal: null, stdout: "", stderr: "SyntaxError: Unexpected token" };
  const r = classifyDifferential(FIRES, benignBuildFail, "crash");
  assert.equal(r.proofVerdict, "exploited");
  assert.equal(r.proofLevel, 4); // attack's own signal-death level, not promoted to 5
  assert.equal(r.differential, "benign-inconclusive");
});

test("attack did not fire → the attack verdict is returned unchanged (no false promotion)", () => {
  const r = classifyDifferential(CLEAN, CLEAN, "nonzero");
  assert.equal(r.proofVerdict, "not-reproduced");
  assert.equal(r.differential, "attack-did-not-fire");
});

// classifyRuns folds reproducibility (the 3/3 standard) into the verdict: the top
// tier requires a clean negative control AND full reproducibility; a flaky crash
// is still real but caps below it and carries the rate.
test("fully reproducible attack + clean benign → level 5, rate 1 (the gold standard)", () => {
  const r = classifyRuns({ attackResults: [FIRES, FIRES, FIRES], benignResult: CLEAN, expectedSignal: "crash" });
  assert.equal(r.proofVerdict, "exploited");
  assert.equal(r.proofLevel, 5);
  assert.deepEqual(r.reproductions, { fired: 3, total: 3, rate: 1 });
});

test("flaky attack (1/3) + clean benign → still exploited but capped at level 4 with the rate", () => {
  const r = classifyRuns({ attackResults: [FIRES, CLEAN, CLEAN], benignResult: CLEAN, expectedSignal: "crash" });
  assert.equal(r.proofVerdict, "exploited");
  assert.equal(r.proofLevel, 4); // not 5 — flakiness caps it
  assert.equal(r.reproductions.rate, Number((1 / 3).toFixed(3)));
});

test("never fired across N runs → not a proof, reproduction rate 0", () => {
  const r = classifyRuns({ attackResults: [CLEAN, CLEAN, CLEAN], benignResult: CLEAN, expectedSignal: "nonzero" });
  assert.notEqual(r.proofVerdict, "exploited");
  assert.equal(r.reproductions.fired, 0);
  assert.equal(r.differential, "attack-did-not-fire");
});

test("reproducible attack but benign ALSO fires → non-discriminating regardless of rate", () => {
  const r = classifyRuns({ attackResults: [FIRES, FIRES, FIRES], benignResult: FIRES, expectedSignal: "crash" });
  assert.equal(r.proofVerdict, "non-discriminating");
  assert.equal(r.proofLevel, 2);
});
