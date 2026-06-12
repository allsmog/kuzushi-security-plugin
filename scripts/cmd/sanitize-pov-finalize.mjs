#!/usr/bin/env node
// Finalize phase for /sanitize-pov. Writes the agent's harness, compiles+runs it under
// AddressSanitizer/UBSan in the sandbox, and lets the SANITIZER REPORT decide the
// verdict — no LLM in this step, the abort is the oracle. A recognized sanitizer error
// → the finding is `proven` (status), with the exact error class + CWE attached; a
// clean run → `not-reproduced`; a build failure → `harness-failed-build` (never a false
// proof). Mirrors /poc's block shape so it slots into the proof ladder.

import { resolve, join } from "node:path";
import { existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { patchFindings, pocVerdictToStatus } from "../lib/findings.mjs";
import { runInSandbox, classifyResult, detectBackend } from "../lib/sandbox.mjs";
import { parseSanitizerReport, SANITIZE_ENV } from "../lib/sanitizers.mjs";

function fail(message) { console.error(`sanitize-pov-finalize: ${message}`); process.exit(1); }

// The feedback half of the execution-grounded loop (Lever 2). When execution does NOT
// confirm a claimed memory bug, the finding shouldn't just silently change status — the
// next agent pass (a re-verify, a better harness, or a retraction) needs to know WHY and
// WHAT to do. This turns "ASan ran clean" into an actionable instruction instead of a dead
// `reviewed` record. `exploited` returns null (no feedback needed — it's proven).
function executionFeedback(r) {
  const where = r.findingFingerprint ? `finding ${r.findingFingerprint}` : "the finding";
  const log = `See the run log: ${r.logPath}.`;
  switch (r.proofVerdict) {
    case "exploited":
      return null;
    case "not-reproduced":
      return `Execution did NOT reproduce the claimed memory bug for ${where}: the harness built and ran clean under AddressSanitizer/UBSan with no abort. Either the harness doesn't drive attacker input to the sink (revise it — confirm the input reaches the dangerous line and the size/precondition that triggers the bug is met), or the reading-based claim is a false positive (retract it). Do not re-assert it as proven without an abort. ${log}`;
    case "harness-failed-build":
      return `The execution harness for ${where} FAILED TO BUILD — the claim is UNVERIFIED by execution, not refuted. Fix the build (missing deps, toolchain, or sanitizer flags) and retry, or lower confidence until it can be run. ${log}`;
    case "non-discriminating":
      return `The harness for ${where} fired on benign input too, so it does not discriminate the bug — it is not proof. Tighten the harness so only the malicious input aborts. ${log}`;
    case "timeout":
      return `The execution harness for ${where} timed out before producing a verdict — unverified, not refuted. Reduce the input size or raise the timeout and retry. ${log}`;
    default:
      return `Execution of the harness for ${where} errored before a verdict (${r.proofVerdict}) — unverified, not refuted. Inspect and retry. ${log}`;
  }
}

const envPrefix = Object.entries(SANITIZE_ENV).map(([k, v]) => `${k}='${v}'`).join(" ");

async function runOne(pov, runDir, backendInfo, trustLocal) {
  const harnessDir = join(runDir, "harness", pov.findingFingerprint || `pov-${Math.abs(hash(pov.buildRunCommand))}`);
  mkdirSync(harnessDir, { recursive: true });
  for (const f of pov.harnessFiles ?? []) {
    if (!f?.name || f.name.includes("..")) continue;
    const p = join(harnessDir, f.name);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, String(f.content ?? ""));
  }
  // Sanitizer env is forced regardless of what the agent wrote, so an abort can't be
  // recovered/swallowed and leaks are off (we only prove corruption here).
  const runCommand = `${envPrefix} ${pov.buildRunCommand}`;
  const result = await runInSandbox({
    backend: backendInfo.backend, language: pov.language ?? "c",
    harnessDir, runCommand, timeoutMs: Number(pov.timeoutMs ?? 120000), trustLocal
  });
  const out = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const report = parseSanitizerReport(out);
  const classified = classifyResult(result);

  // The sanitizer report is the oracle. It outranks the generic classifier: a parsed
  // ASan/UBSan error = proven (unless the harness never built).
  let proofVerdict = classified.proofVerdict;
  let proofLevel = classified.proofLevel;
  if (report && classified.proofVerdict !== "harness-failed-build") {
    proofVerdict = "exploited"; proofLevel = 4;
  }
  const logPath = join(harnessDir, "run.log");
  writeFileSync(logPath, out);
  return {
    findingFingerprint: pov.findingFingerprint,
    proofVerdict, proofLevel,
    backend: result.backend ?? backendInfo.backend,
    durationMs: result.durationMs ?? null,
    harnessDir, runCommand, logPath,
    sanitizer: report,            // { tool, errorClass, cwe, frame0 } or null
    skipped: Boolean(result.skipped),
    reason: result.reason ?? null
  };
}

function hash(s) { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }

export async function finalizeSanitizePov(target, runDir, input = {}) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.sanitize-pov.json");
  if (!existsSync(draftPath)) fail(`no draft.sanitize-pov.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.sanitize-pov.json is not valid JSON"); }
  const povs = Array.isArray(draft.povs) ? draft.povs : (draft.buildRunCommand ? [draft] : null);
  if (!povs || !povs.length) fail("draft must have povs[] (each { findingFingerprint, language, harnessFiles[], buildRunCommand })");
  for (const p of povs) {
    if (!p.findingFingerprint) fail("each pov needs a findingFingerprint");
    if (!p.buildRunCommand) fail(`pov ${p.findingFingerprint}: needs a buildRunCommand that compiles WITH -fsanitize and runs the harness`);
  }

  // Executing code requires a sandbox; local execution requires explicit consent.
  // /sanitize-pov compiles the TARGET's code with sanitizers, which needs the host
  // build env — so `local` is the natural backend (consented via trustLocal), and a
  // generic docker image usually lacks the project's toolchain/deps. Honor an explicit
  // backend override; otherwise detect (docker if a daemon answers, else local).
  const override = input.backend ?? draft.backend;
  const backendInfo = override ? { backend: override, reason: "explicit override" } : detectBackend();
  const trustLocal = Boolean(input.trustLocal ?? draft.trustLocal);

  const provenAt = new Date().toISOString();
  const results = [];
  for (const pov of povs) results.push(await runOne(pov, resolvedRunDir, backendInfo, trustLocal));

  const doc = { schemaVersion: "sanitize-pov.v1", generatedAt: provenAt, target: resolvedTarget, backend: backendInfo.backend, results };
  atomicWrite(store.sanitizePovPath, `${JSON.stringify(doc, null, 2)}\n`);
  atomicWrite(join(resolvedRunDir, "sanitize-pov.json"), `${JSON.stringify(doc, null, 2)}\n`);

  // Patch findings: a sanitizer-proven finding → proven, with the exact CWE the
  // sanitizer reported (ground-truth precision). Non-proven runs attach the poc block
  // but don't claim more than the run showed.
  const patches = results.map((r) => ({
    fingerprint: r.findingFingerprint,
    status: pocVerdictToStatus(r.proofVerdict),
    ...(r.sanitizer?.cwe && r.proofVerdict === "exploited" ? { cwe: r.sanitizer.cwe } : {}),
    poc: {
      schemaVersion: "poc.v1",
      proofLevel: r.proofLevel,
      proofVerdict: r.proofVerdict,
      backend: r.backend,
      durationMs: r.durationMs,
      harnessDir: r.harnessDir,
      runCommand: r.runCommand,
      logPath: r.logPath,
      provenAt,
      ...(r.sanitizer ? { sanitizer: { tool: r.sanitizer.tool, errorClass: r.sanitizer.errorClass, cwe: r.sanitizer.cwe, frame0: r.sanitizer.frame0 } } : {}),
      // Closed-loop feedback: an actionable message when execution did NOT prove the
      // claim, so a downstream pass revises the harness or retracts — instead of the
      // failed run becoming a silent dead end.
      ...(executionFeedback(r) ? { executionFeedback: executionFeedback(r) } : {})
    }
  }));
  let findingsDoc = null;
  try { findingsDoc = patchFindings(resolvedTarget, patches); } catch (e) { /* unknown fingerprint(s) — surface below */ fail(String(e.message || e)); }

  const proven = results.filter((r) => r.proofVerdict === "exploited");
  const run = openRun(resolvedTarget, "sanitize-pov-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    backend: backendInfo.backend,
    provenCount: proven.length,
    proven: proven.map((r) => ({ fingerprint: r.findingFingerprint, ...(r.sanitizer ?? {}) })),
    verdicts: results.map((r) => ({ fingerprint: r.findingFingerprint, proofVerdict: r.proofVerdict, sanitizer: r.sanitizer?.errorClass ?? null })),
    sanitizePovPath: store.sanitizePovPath,
    findingsSummary: findingsDoc?.summary
  };
  run.finalize(result);
  return result;
}

async function main() {
  if (process.argv.includes("--help")) {
    console.log("sanitize-pov-finalize --target <path> --run-dir <dir> [--input '{\"trustLocal\":true}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir", "input", "input-file"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(await finalizeSanitizePov(flags.target, flags["run-dir"], loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
