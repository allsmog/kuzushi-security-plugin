#!/usr/bin/env node
// Execute runnable fuzz harnesses from .kuzushi/fuzz/fuzz-plan.json in the same
// sandbox runner used by /poc. The agent/user must provide the actual harness;
// this host script only runs declared commands and records empirical evidence.

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { detectBackend, runInSandbox, classifyResult } from "../lib/sandbox.mjs";

export async function fuzzRun(target, options = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const plan = readJsonIfPresent(options.planPath ?? store.fuzzPlanPath);
  if (!plan) throw new Error(`${store.fuzzPlanPath} not found — run /fuzz-init first`);

  const { backend, reason } = detectBackend();
  const trustLocal = Boolean(options.trustLocal);
  const run = openRun(resolvedTarget, "fuzz-run");
  const results = [];
  for (const c of plan.candidates ?? []) {
    if (!c.runCommand || !c.harnessDir || !existsSync(c.harnessDir)) {
      results.push({
        findingFingerprint: c.findingFingerprint,
        engine: c.engine,
        language: c.language,
        status: "not-runnable",
        proofLevel: 1,
        proofVerdict: "error",
        note: "missing harnessDir or runCommand"
      });
      continue;
    }
    const timeoutMs = Number(options.timeoutMs ?? c.timeoutMs ?? 120000);
    const fuzzResult = await runInSandbox({
      backend,
      language: c.language,
      harnessDir: c.harnessDir,
      runCommand: c.runCommand,
      timeoutMs,
      trustLocal
    });
    const classified = classifyResult(fuzzResult, c.expectedSignal ?? "crash");
    const logName = `fuzz-${c.findingFingerprint}.log`;
    run.writeText(logName, [
      `# fuzz ${c.findingFingerprint}`,
      `engine: ${c.engine}`,
      `backend: ${fuzzResult.backend}`,
      `runCommand: ${c.runCommand}`,
      `proofLevel: ${classified.proofLevel}`,
      `proofVerdict: ${classified.proofVerdict}`,
      "",
      "## stdout",
      fuzzResult.stdout ?? "",
      "## stderr",
      fuzzResult.stderr ?? ""
    ].join("\n"));
    results.push({
      findingFingerprint: c.findingFingerprint,
      engine: c.engine,
      language: c.language,
      harnessDir: c.harnessDir,
      runCommand: c.runCommand,
      backend: fuzzResult.backend,
      durationMs: fuzzResult.durationMs ?? null,
      proofLevel: classified.proofLevel,
      proofVerdict: classified.proofVerdict,
      logPath: `${run.runDir}/${logName}`,
      note: classified.note ?? fuzzResult.reason ?? null
    });
  }

  const doc = {
    version: "1.0",
    schemaVersion: "fuzz-run.v1",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    backend,
    sandboxReason: reason,
    results
  };
  atomicWrite(store.fuzzRunPath, `${JSON.stringify(doc, null, 2)}\n`);
  run.writeJson("fuzz-run.json", doc);
  const verdictCounts = results.reduce((acc, r) => { acc[r.proofVerdict] = (acc[r.proofVerdict] ?? 0) + 1; return acc; }, {});
  const result = { ok: true, status: "completed", target: resolvedTarget, backend, fuzzRunPath: store.fuzzRunPath, candidateCount: results.length, verdictCounts };
  run.finalize(result);
  return result;
}

async function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-run --target <path> [--trust-local] [--timeout-ms 120000]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help", "trust-local"], value: ["target", "plan", "timeout-ms"] });
  if (!flags.target) {
    console.error("fuzz-run: --target is required");
    process.exit(1);
  }
  emitResult(await fuzzRun(flags.target, {
    trustLocal: Boolean(flags["trust-local"]),
    planPath: flags.plan,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined
  }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
