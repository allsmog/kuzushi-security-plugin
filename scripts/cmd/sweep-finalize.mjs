#!/usr/bin/env node
// Finalize phase for /sweep. The per-producer finalizes already promoted their
// verdicts into findings.json (each guarded by the findings lock, so the parallel
// fan-out can't lose-update). This step is the aggregator: re-derive the coverage
// map from the plan, read the resulting findings index, fold in the optional
// per-job run report the coordinator drafted, and write sweep.json +
// coverage-map.json. No findings are promoted here — it only summarizes.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { inventory } from "../lib/sharding.mjs";
import { buildCoverageMap } from "../lib/coverage.mjs";

function fail(message) {
  console.error(`sweep-finalize: ${message}`);
  process.exit(1);
}

export function finalizeSweep(target, runDir) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);

  // The plan is in the run dir; fall back to the canonical store copy.
  let plan = null;
  if (runDir) {
    const p = join(resolve(runDir), "sweep-plan.json");
    if (existsSync(p)) plan = JSON.parse(readFileSync(p, "utf8"));
  }
  if (!plan) plan = readJsonIfPresent(store.sweepPlanPath);
  if (!plan) fail("no sweep-plan.json found — run sweep-prepare first");

  const maxFilesPerShard = Number(plan.input?.maxFilesPerShard ?? 60);
  const inv = inventory(resolvedTarget);
  const coverage = buildCoverageMap(plan, inv.files, { maxFilesPerShard });

  // Optional run report the coordinator wrote: per-job {jobId, producer, status,
  // candidateCount}. Used only for the human-facing summary, never for promotion.
  let jobReport = [];
  if (runDir) {
    const draftPath = join(resolve(runDir), "draft.sweep.json");
    if (existsSync(draftPath)) {
      try {
        const draft = JSON.parse(readFileSync(draftPath, "utf8"));
        if (Array.isArray(draft.jobs)) jobReport = draft.jobs;
      } catch { fail("draft.sweep.json is not valid JSON"); }
    }
  }

  const findingsDoc = readJsonIfPresent(store.findingsPath) ?? { findings: [], summary: { total: 0 } };

  const sweep = {
    schemaVersion: "sweep.v1",
    target: resolvedTarget,
    offline: Boolean(plan.offline),
    shardCount: plan.shardCount,
    jobCount: plan.jobCount,
    producerSet: plan.producerSet,
    jobsReported: jobReport.length,
    jobReport,
    coverage: {
      totalFiles: coverage.totalFiles,
      coveredFileCount: coverage.coveredFileCount,
      uncoveredFileCount: coverage.uncoveredFileCount,
      coveragePct: coverage.coveragePct
    },
    findingsSummary: findingsDoc.summary ?? { total: (findingsDoc.findings ?? []).length }
  };

  atomicWrite(store.sweepPath, `${JSON.stringify(sweep, null, 2)}\n`);
  atomicWrite(store.coverageMapPath, `${JSON.stringify(coverage, null, 2)}\n`);

  const run = openRun(resolvedTarget, "sweep-finalize");
  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    coveragePct: coverage.coveragePct,
    uncoveredShards: coverage.uncovered.length,
    findingsTotal: sweep.findingsSummary.total ?? 0,
    sweepPath: store.sweepPath,
    coverageMapPath: store.coverageMapPath,
    findingsPath: store.findingsPath
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("sweep-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target) fail("--target is required");
  emitResult(finalizeSweep(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
