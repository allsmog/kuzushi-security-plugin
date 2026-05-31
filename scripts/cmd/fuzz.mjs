#!/usr/bin/env node
// Consolidated fuzz workflow entrypoint. The staged scripts remain available for
// precise replay, but /fuzz is the canonical UX surface:
//   plan     -> initialize campaign + harness workspace
//   run      -> execute declared harnesses
//   triage   -> group exploited results
//   minimize -> record minimization status
//   promote  -> attach empirical fuzz proof to findings
//   status   -> summarize current fuzz artifacts
//   replay   -> run/triage/minimize/promote an existing plan

import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { fuzzInit } from "./fuzz-init.mjs";
import { fuzzRun } from "./fuzz-run.mjs";
import { fuzzTriage } from "./fuzz-triage.mjs";
import { fuzzMinimize } from "./fuzz-minimize.mjs";
import { fuzzPromote } from "./fuzz-promote.mjs";
import { prepareFuzzDiscover } from "./fuzz-discover-prepare.mjs";

function artifact(path) {
  if (!existsSync(path)) return { present: false };
  const doc = readJsonIfPresent(path);
  return {
    present: true,
    path,
    mtime: statSync(path).mtime.toISOString(),
    schemaVersion: doc?.schemaVersion ?? doc?.version ?? null,
    summary: doc?.summary ?? null,
    resultCount: doc?.results?.length ?? null,
    candidateCount: doc?.candidates?.length ?? null
  };
}

export function fuzzStatus(target) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  return {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    artifacts: {
      plan: artifact(store.fuzzPlanPath),
      run: artifact(store.fuzzRunPath),
      triage: artifact(store.fuzzTriagePath),
      minimize: artifact(store.fuzzMinimizePath),
      promote: artifact(store.fuzzPromotePath)
    }
  };
}

export async function fuzzWorkflow(target, { stage = "status", input = {}, trustLocal = false, timeoutMs = undefined, planPath = undefined } = {}) {
  const resolvedStage = String(stage ?? "status");
  if (resolvedStage === "status") return fuzzStatus(target);
  // Discovery-by-execution: deterministic recon prep (no pre-existing finding needed).
  // The coordinator spawns the fuzz-discoverer agent against the prep, then runs the
  // returned assembleCommand (fuzz-discover-finalize) — the same prepare→agent→finalize
  // shape as /sanitize-pov, but it FINDS bugs rather than only proving known ones.
  if (resolvedStage === "discover") return prepareFuzzDiscover(target, input);
  if (resolvedStage === "plan" || resolvedStage === "init") return fuzzInit(target, input);
  if (resolvedStage === "run") return fuzzRun(target, { trustLocal, timeoutMs, planPath });
  if (resolvedStage === "triage") return fuzzTriage(target);
  if (resolvedStage === "minimize") return fuzzMinimize(target);
  if (resolvedStage === "promote") return fuzzPromote(target);
  if (resolvedStage === "replay") {
    const run = await fuzzRun(target, { trustLocal, timeoutMs, planPath });
    const triage = fuzzTriage(target);
    const minimize = fuzzMinimize(target);
    const promote = fuzzPromote(target);
    return {
      ok: true,
      status: "completed",
      target: resolve(target),
      stage: "replay",
      run,
      triage,
      minimize,
      promote
    };
  }
  throw new Error(`unknown fuzz stage "${resolvedStage}" (expected status|discover|plan|run|triage|minimize|promote|replay)`);
}

async function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz --target <path> [--stage status|discover|plan|run|triage|minimize|promote|replay] [--trust-local] [--timeout-ms 120000]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["help", "trust-local"],
    value: ["target", "stage", "plan", "timeout-ms", "input", "input-file"]
  });
  if (!flags.target) {
    console.error("fuzz: --target is required");
    process.exit(1);
  }
  emitResult(await fuzzWorkflow(flags.target, {
    stage: flags.stage ?? "status",
    input: loadInput(flags),
    trustLocal: Boolean(flags["trust-local"]),
    planPath: flags.plan,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined
  }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
