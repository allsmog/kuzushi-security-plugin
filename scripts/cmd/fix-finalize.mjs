#!/usr/bin/env node
// Finalize phase for /fix — the deterministic PoC⁺ validation engine. For each
// patch the fixer drafted, it: copies the target into a throwaway sandbox workdir,
// overlays the existing /poc harness, applies the unified diff to the COPY (never
// the working tree), then runs two phases in the sandbox:
//   Phase A — re-run the PoC harness; the patch STOPS the exploit when the run no
//             longer classifies as "exploited" (a post-patch build failure does
//             NOT count as a stop — that's the PVBench trap).
//   Phase B — run the functional/regression check; it must still pass.
// validated = A ∧ B. The verdict + a `fix` block (applied:false) are attached onto
// the finding. Only "validated" advances status (→ patched). The working tree is
// never modified here — that's fix-apply, behind explicit approval.

import { resolve, join, isAbsolute, normalize } from "node:path";
import { existsSync, readFileSync, mkdirSync, mkdtempSync, rmSync, cpSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { patchFindings, fixVerdictToStatus } from "../lib/findings.mjs";
import { detectBackend, runInSandbox, classifyResult } from "../lib/sandbox.mjs";
import { oracleSummaryForFinding } from "../lib/oracles.mjs";

const MIN_RATIONALE_LENGTH = 150;
const VALID_EXPECTATIONS = new Set(["exit-zero", "assert-output"]);
const VALID_KINDS = new Set(["repo-tests", "behavioral-harness", "none"]);
const COPY_SKIP = new Set([".git", "node_modules", ".kuzushi", "vendor", "build", "dist", "target", ".joern"]);

function fail(message) {
  console.error(`fix-finalize: ${message}`);
  process.exit(1);
}

// Static draft validation (shape only; the empirical verdict is computed here,
// not taken from the agent).
function validate(candidates) {
  for (const c of candidates) {
    const id = c.findingFingerprint ?? "(missing fingerprint)";
    if (!c.findingFingerprint) fail("a candidate is missing findingFingerprint");
    const patch = String(c.patch ?? "");
    if (!/^(diff |--- |@@ |Index: )/m.test(patch)) {
      fail(`${id}: patch does not look like a unified diff (need ---/+++/@@ headers)`);
    }
    if (String(c.patchRationale ?? "").length < MIN_RATIONALE_LENGTH) {
      fail(`${id}: patchRationale is too short (min ${MIN_RATIONALE_LENGTH}). Root-cause the bug + explain why behavior is preserved.`);
    }
    const fc = c.functionalCheck ?? {};
    if (!VALID_KINDS.has(fc.kind)) fail(`${id}: functionalCheck.kind must be one of ${[...VALID_KINDS].join(", ")}`);
    if (fc.kind !== "none" && !VALID_EXPECTATIONS.has(fc.expectation)) {
      fail(`${id}: functionalCheck.expectation must be one of ${[...VALID_EXPECTATIONS].join(", ")}`);
    }
    if (c.semanticCheck) {
      const sc = c.semanticCheck;
      if (!VALID_KINDS.has(sc.kind)) fail(`${id}: semanticCheck.kind must be one of ${[...VALID_KINDS].join(", ")}`);
      if (sc.kind !== "none" && !VALID_EXPECTATIONS.has(sc.expectation)) {
        fail(`${id}: semanticCheck.expectation must be one of ${[...VALID_EXPECTATIONS].join(", ")}`);
      }
    }
    // Path-traversal guard: every target file must stay within the repo.
    for (const tf of c.targetFiles ?? []) {
      if (isAbsolute(tf) || normalize(tf).startsWith("..")) fail(`${id}: targetFile escapes the repo: ${tf}`);
    }
  }
}

// A functional run "passes" when it exited cleanly with no crash markers.
function functionalPassed(run) {
  if (!run || run.skipped || run.timedOut || run.spawnError) return false;
  if (typeof run.exitCode === "number" && run.exitCode !== 0) return false;
  return true;
}

function runnableCheck(check) {
  return check && check.kind !== "none" && check.runCommand;
}

export async function finalizeFix(target, runDir, options = {}) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.fix.json");
  if (!existsSync(draftPath)) fail(`no draft.fix.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.fix.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");
  validate(draft.candidates);

  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) fail(`${store.findingsPath} not found`);
  const findingByFp = new Map((findingsDoc.findings ?? []).map((f) => [f.fingerprint, f]));

  const { backend, reason } = detectBackend();
  const trustLocal = Boolean(options.trustLocal);
  const timeoutMs = Number(options.timeoutMs ?? 90000);
  const logsRun = openRun(resolvedTarget, "fix-finalize");

  const results = [];
  const sandboxRoots = [];
  try {
  for (const c of draft.candidates) {
    const fp = c.findingFingerprint;
    const finding = findingByFp.get(fp);
    if (!finding) fail(`${fp}: no matching finding in findings.json`);
    const oracle = c.semanticOracle ?? oracleSummaryForFinding(finding);
    // Normalize harnessLinkage to the two meaningful values: only an explicit
    // "inlined" gets the inlined treatment; any other value (e.g. an agent's
    // "direct", or null) is treated and recorded as "links-target".
    const harnessLinkage = c.harnessLinkage === "inlined" ? "inlined" : "links-target";

    // Persist the diff under the run dir (fix-apply references this path).
    const patchDir = join(resolvedRunDir, "fix", fp);
    const patchPath = join(patchDir, "patch.diff");
    mkdirSync(patchDir, { recursive: true });
    writeFileSync(patchPath, c.patch.endsWith("\n") ? c.patch : `${c.patch}\n`);

    const poc = finding.poc ?? null;
    const hasHarness = Boolean(poc?.harnessDir && existsSync(poc.harnessDir));
    const runnableBackend = backend === "docker" || (backend === "local" && trustLocal);

    // Degraded path: no harness, or no sandbox to run it in. Persist the diff,
    // do not claim it stops anything.
    if (!hasHarness || !runnableBackend) {
      results.push({
        findingFingerprint: fp, verdict: "unvalidated-no-harness", language: c.language ?? null,
        patchPath, harnessLinkage,
        stops: null, functional: null, applied: false,
        note: !hasHarness ? "no /poc harness to validate against" : `no runnable sandbox (${reason})`
      });
      continue;
    }

    // Build the sandbox workdir OUTSIDE the target (a copy under the target would
    // recurse into itself): patched repo copy + the poc harness overlaid.
    const sandboxRoot = mkdtempSync(join(tmpdir(), "kuzushi-fix-"));
    sandboxRoots.push(sandboxRoot);
    const repoDir = join(sandboxRoot, "work");
    mkdirSync(repoDir, { recursive: true });
    cpSync(resolvedTarget, repoDir, { recursive: true, filter: (src) => !COPY_SKIP.has(src.split(/[\\/]/).pop()) });
    cpSync(poc.harnessDir, repoDir, { recursive: true });

    // Apply the diff to the COPY (git apply works outside a repo, cwd-relative).
    const check = spawnSync("git", ["apply", "--check", patchPath], { cwd: repoDir, encoding: "utf8" });
    if (check.status !== 0) {
      results.push({
        findingFingerprint: fp, verdict: "build-failed", language: c.language ?? null, patchPath,
        harnessLinkage, stops: null, functional: null, applied: false,
        note: `git apply --check failed: ${(check.stderr ?? "").slice(0, 300)}`
      });
      continue;
    }
    spawnSync("git", ["apply", patchPath], { cwd: repoDir, encoding: "utf8" });

    // An inlined harness carries its own copy of the vulnerable code, so a patch
    // to the repo files can't be shown to affect it — don't claim a result.
    if (harnessLinkage === "inlined") {
      results.push({
        findingFingerprint: fp, verdict: "needs-more-evidence", language: c.language ?? null, patchPath,
        harnessLinkage: "inlined", stops: null, functional: null, applied: false,
        note: "harness inlines the vulnerable code; patch effect on it is indeterminate — regenerate a harness that builds against the target files"
      });
      continue;
    }

    // Phase A — stops-exploit: re-run the PoC against the patched copy.
    const stopRun = await runInSandbox({
      backend, language: poc.language ?? c.language, harnessDir: repoDir,
      runCommand: poc.runCommand, timeoutMs, trustLocal
    });
    const stopClass = classifyResult(stopRun, poc.expectedSignal ?? "crash");
    logsRun.writeText(`fix-${fp}-stops.log`, [
      `# fix stops-exploit ${fp}`, `runCommand: ${poc.runCommand}`,
      `proofVerdict: ${stopClass.proofVerdict} (exploit ${stopClass.proofVerdict === "exploited" ? "STILL FIRES" : "stopped"})`,
      "## stdout", stopRun.stdout ?? "", "## stderr", stopRun.stderr ?? ""
    ].join("\n"));

    // A post-patch build failure is NOT a clean stop (PVBench trap).
    const postPatchBuildFailed = stopClass.proofVerdict === "harness-failed-build";
    const exploitStopped = stopClass.proofVerdict !== "exploited" && !postPatchBuildFailed;

    if (postPatchBuildFailed) {
      results.push({
        findingFingerprint: fp, verdict: "build-failed", language: c.language ?? null, patchPath,
        harnessLinkage,
        stops: { proofVerdict: stopClass.proofVerdict, backend: stopRun.backend }, functional: null, applied: false,
        note: "patched copy no longer builds — the patch broke compilation, not a valid fix"
      });
      continue;
    }
    if (!exploitStopped) {
      results.push({
        findingFingerprint: fp, verdict: "exploit-still-fires", language: c.language ?? null, patchPath,
        harnessLinkage,
        stops: { proofVerdict: stopClass.proofVerdict, backend: stopRun.backend }, functional: null, applied: false,
        note: "PoC harness still triggers the bug after the patch"
      });
      continue;
    }

    // Phase A2 — fuzz re-prove: if a fuzz harness exists for this finding, re-run
    // the FUZZER against the patched copy. A class of inputs (not just the single
    // PoC payload) must fail to crash. Only an actual crash blocks validation —
    // a fuzz-harness build/timeout issue is inconclusive, not a fix failure.
    let fuzzReprove = null;
    if (c.fuzz?.harnessDir && existsSync(c.fuzz.harnessDir)) {
      cpSync(c.fuzz.harnessDir, repoDir, { recursive: true });
      const fuzzTimeoutMs = Math.max(timeoutMs, 180000);
      const fuzzRun = await runInSandbox({
        backend, language: c.fuzz.language ?? c.language, harnessDir: repoDir,
        runCommand: c.fuzz.runCommand, timeoutMs: fuzzTimeoutMs, trustLocal
      });
      const fuzzClass = classifyResult(fuzzRun, c.fuzz.expectedSignal ?? "crash");
      logsRun.writeText(`fix-${fp}-fuzz-reprove.log`, [
        `# fix fuzz re-prove ${fp}`, `runCommand: ${c.fuzz.runCommand}`,
        `proofVerdict: ${fuzzClass.proofVerdict} (fuzzer ${fuzzClass.proofVerdict === "exploited" ? "STILL CRASHES" : "found no crash"})`,
        "## stdout", fuzzRun.stdout ?? "", "## stderr", fuzzRun.stderr ?? ""
      ].join("\n"));
      fuzzReprove = { passed: fuzzClass.proofVerdict !== "exploited", proofVerdict: fuzzClass.proofVerdict, backend: fuzzRun.backend };
      if (fuzzClass.proofVerdict === "exploited") {
        results.push({
          findingFingerprint: fp, verdict: "exploit-still-fires", language: c.language ?? null, patchPath,
          harnessLinkage,
          stops: { proofVerdict: stopClass.proofVerdict, backend: stopRun.backend }, fuzzReprove,
          functional: null, applied: false,
          note: "fuzzer still crashes the patched code — a class of inputs the single PoC missed; the patch is incomplete"
        });
        continue;
      }
    }

    // Phase B — functional/regression check.
    const fc = c.functionalCheck ?? {};
    let functional;
    if (!runnableCheck(fc)) {
      functional = { kind: fc.kind ?? "none", passed: false, note: "no functional check supplied" };
    } else {
      const funcDir = fc.kind === "behavioral-harness" && fc.functionalDir && existsSync(fc.functionalDir) ? fc.functionalDir : repoDir;
      const funcRun = await runInSandbox({ backend, language: poc.language ?? c.language, harnessDir: funcDir, runCommand: fc.runCommand, timeoutMs, trustLocal });
      const passed = functionalPassed(funcRun);
      logsRun.writeText(`fix-${fp}-func.log`, [
        `# fix functional ${fp}`, `kind: ${fc.kind}  runCommand: ${fc.runCommand}`,
        `exitCode: ${funcRun.exitCode ?? ""}  passed: ${passed}`,
        "## stdout", funcRun.stdout ?? "", "## stderr", funcRun.stderr ?? ""
      ].join("\n"));
      functional = { kind: fc.kind, passed, exitCode: funcRun.exitCode ?? null };
    }

    // Phase C — semantic oracle regression when the CWE is supported. The agent
    // supplies a semanticCheck shaped like functionalCheck, using the oracle
    // controls from fix-prepare. Unsupported CWEs do not block validation.
    const sc = c.semanticCheck ?? {};
    let semantic;
    if (!oracle) {
      semantic = { oracle: null, passed: true, note: "no semantic oracle for this CWE" };
    } else if (!runnableCheck(sc)) {
      semantic = { oracle: oracle.id, passed: false, note: "semantic oracle available but no semanticCheck supplied" };
    } else {
      const semDir = sc.kind === "behavioral-harness" && sc.semanticDir && existsSync(sc.semanticDir) ? sc.semanticDir : repoDir;
      const semRun = await runInSandbox({ backend, language: poc.language ?? c.language, harnessDir: semDir, runCommand: sc.runCommand, timeoutMs, trustLocal });
      const passed = functionalPassed(semRun);
      logsRun.writeText(`fix-${fp}-semantic.log`, [
        `# fix semantic ${fp}`, `oracle: ${oracle.id}`, `kind: ${sc.kind}  runCommand: ${sc.runCommand}`,
        `exitCode: ${semRun.exitCode ?? ""}  passed: ${passed}`,
        "## stdout", semRun.stdout ?? "", "## stderr", semRun.stderr ?? ""
      ].join("\n"));
      semantic = { oracle: oracle.id, passed, exitCode: semRun.exitCode ?? null };
    }

    // A fuzz harness that crashed already short-circuited above, so reaching here
    // means fuzzReprove (if present) passed. Record it; absent ⇒ does not gate.
    const fuzzReproveOk = fuzzReprove === null ? true : fuzzReprove.passed;
    const verdict = functional.passed && semantic.passed && fuzzReproveOk ? "validated" : "stops-exploit-breaks-function";
    const validation = {
      exploitRegressionPassed: true,
      functionalRegressionPassed: Boolean(functional.passed),
      semanticRegressionPassed: Boolean(semantic.passed),
      fuzzReprovePassed: fuzzReprove === null ? null : Boolean(fuzzReprove.passed),
      pocPlusPassed: Boolean(functional.passed && semantic.passed && fuzzReproveOk),
      semanticOracle: semantic.oracle
    };
    results.push({
      findingFingerprint: fp, verdict, language: c.language ?? null, patchPath,
      harnessLinkage,
      stops: { proofVerdict: stopClass.proofVerdict, backend: stopRun.backend },
      fuzzReprove, functional, semantic, validation, applied: false,
      note: verdict === "validated"
        ? `PoC⁺: exploit stopped, functional + semantic checks passed${fuzzReprove ? ", and the fuzzer found no crash on the patched code" : ""}`
        : "exploit stopped but functional or semantic regression did not pass"
    });
  }
  } finally {
    for (const dir of sandboxRoots) { try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } }
  }

  const validatedAt = new Date().toISOString();
  const doc = {
    version: "1.0", generatedAt: validatedAt, target: resolvedTarget,
    backend, sandboxReason: reason,
    scope: "PoC⁺ validation in a sandbox copy — the working tree is never modified here (see /fix apply)",
    results
  };
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  atomicWrite(store.fixPath, json);
  atomicWrite(join(resolvedRunDir, "fix.json"), json);

  // Attach a `fix` block onto each finding. Only "validated" transitions status.
  const patches = results.map((r) => {
    const status = fixVerdictToStatus(r.verdict);
    const patch = {
      fingerprint: r.findingFingerprint,
      fix: {
        schemaVersion: "fix.v1",
        verdict: r.verdict, patchPath: r.patchPath, harnessLinkage: r.harnessLinkage,
        validation: r.validation ?? {
          exploitRegressionPassed: r.verdict === "validated",
          functionalRegressionPassed: r.verdict === "validated",
          semanticRegressionPassed: r.verdict === "validated",
          pocPlusPassed: r.verdict === "validated",
          semanticOracle: null
        },
        stops: r.stops, fuzzReprove: r.fuzzReprove ?? null, functional: r.functional, applied: false, validatedAt, note: r.note
      }
    };
    if (status) patch.status = status;
    return patch;
  });
  const updated = patchFindings(resolvedTarget, patches);

  const verdictCounts = results.reduce((acc, r) => { acc[r.verdict] = (acc[r.verdict] ?? 0) + 1; return acc; }, {});
  const result = {
    ok: true, status: "completed", target: resolvedTarget, backend, sandboxReason: reason,
    candidateCount: results.length, verdictCounts,
    validated: results.filter((r) => r.verdict === "validated").map((r) => r.findingFingerprint),
    fixPath: store.fixPath, findingsPath: store.findingsPath, findingsSummary: updated.summary
  };
  logsRun.finalize(result);
  return result;
}

async function main() {
  if (process.argv.includes("--help")) {
    console.log("fix-finalize --target <path> --run-dir <dir> [--trust-local] [--timeout-ms 90000]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help", "trust-local"], value: ["target", "run-dir", "timeout-ms"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(await finalizeFix(flags.target, flags["run-dir"], {
    trustLocal: Boolean(flags["trust-local"]),
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined
  }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
