#!/usr/bin/env node
// Finalize phase for /poc. For each harness the agent wrote, run it in the
// sandbox (docker --network none, or gated local with --trust-local), classify
// the result into a proof verdict + level, persist .kuzushi/poc.json with the run
// logs, and attach a `poc` block onto each finding (updating its status). The
// agent does NOT run anything — this host script is the deterministic executor,
// so the empirical proof is reproducible. Degrades gracefully when no sandbox is
// available: records backend "none" and keeps the harness for a manual run.

import { resolve, join, isAbsolute } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { patchFindings, pocVerdictToStatus } from "../lib/findings.mjs";
import { detectBackend, runInSandbox, classifyResult } from "../lib/sandbox.mjs";

function fail(message) {
  console.error(`poc-assemble: ${message}`);
  process.exit(1);
}

export async function assemblePoc(target, runDir, options = {}) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.poc.json");
  if (!existsSync(draftPath)) fail(`no draft.poc.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.poc.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  const { backend, reason } = detectBackend();
  const trustLocal = Boolean(options.trustLocal);
  const timeoutMs = Number(options.timeoutMs ?? 60000);
  const logsRun = openRun(resolvedTarget, "poc-assemble");

  const results = [];
  for (const c of draft.candidates) {
    const fp = c.findingFingerprint;
    if (!fp) fail("a candidate is missing findingFingerprint");
    if (!c.runCommand) fail(`${fp}: candidate is missing runCommand`);
    const harnessDir = isAbsolute(c.harnessDir ?? "") ? c.harnessDir : join(resolvedRunDir, c.harnessDir ?? "");
    if (!existsSync(harnessDir)) fail(`${fp}: harnessDir does not exist: ${harnessDir}`);

    const run = await runInSandbox({
      backend, language: c.language, harnessDir,
      runCommand: c.runCommand, timeoutMs, trustLocal
    });
    const verdict = classifyResult(run, c.expectedSignal ?? "crash");

    // Persist the run log next to the canonical artifact for inspection.
    const logName = `poc-${fp}.log`;
    logsRun.writeText(logName, [
      `# poc ${fp}`, `backend: ${run.backend}`, `runCommand: ${c.runCommand}`,
      `exitCode: ${run.exitCode ?? ""}  signal: ${run.signal ?? ""}  timedOut: ${run.timedOut ?? false}`,
      `proofLevel: ${verdict.proofLevel}  proofVerdict: ${verdict.proofVerdict}`,
      "", "## stdout", run.stdout ?? "", "## stderr", run.stderr ?? ""
    ].join("\n"));

    results.push({
      findingFingerprint: fp,
      language: c.language ?? null,
      proofLevel: verdict.proofLevel,
      proofVerdict: verdict.proofVerdict,
      backend: run.backend,
      durationMs: run.durationMs ?? null,
      harnessDir,
      runCommand: c.runCommand,
      logPath: join(logsRun.runDir, logName),
      note: verdict.note ?? (run.skipped ? reason : undefined)
    });
  }

  const provenAt = new Date().toISOString();
  const doc = { version: "1.0", generatedAt: provenAt, target: resolvedTarget, backend, sandboxReason: reason, results };
  atomicWrite(store.pocPath, `${JSON.stringify(doc, null, 2)}\n`);
  atomicWrite(join(resolvedRunDir, "poc.json"), `${JSON.stringify(doc, null, 2)}\n`);

  // Attach the poc block onto each finding + update its status.
  const patches = results.map((r) => ({
    fingerprint: r.findingFingerprint,
    status: pocVerdictToStatus(r.proofVerdict),
    poc: {
      schemaVersion: "poc.v1",
      proofLevel: r.proofLevel,
      proofVerdict: r.proofVerdict,
      backend: r.backend,
      durationMs: r.durationMs,
      harnessDir: r.harnessDir,
      runCommand: r.runCommand,
      logPath: r.logPath,
      provenAt
    }
  }));
  const findingsDoc = patchFindings(resolvedTarget, patches);

  const verdictCounts = results.reduce((acc, r) => { acc[r.proofVerdict] = (acc[r.proofVerdict] ?? 0) + 1; return acc; }, {});
  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    backend,
    sandboxReason: reason,
    candidateCount: results.length,
    verdictCounts,
    proven: results.filter((r) => r.proofVerdict === "exploited").map((r) => r.findingFingerprint),
    pocPath: store.pocPath,
    findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  logsRun.finalize(result);
  return result;
}

async function main() {
  if (process.argv.includes("--help")) {
    console.log("poc-assemble --target <path> --run-dir <dir> [--trust-local] [--timeout-ms 60000]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help", "trust-local"], value: ["target", "run-dir", "timeout-ms"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  const result = await assemblePoc(flags.target, flags["run-dir"], {
    trustLocal: Boolean(flags["trust-local"]),
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined
  });
  emitResult(result);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
