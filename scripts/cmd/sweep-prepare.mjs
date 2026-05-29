#!/usr/bin/env node
// Prepare phase for /sweep — the whole-repo orchestrator.
//
// Xint Code's headline is "thousands of parallel agents over the whole repo".
// kuzushi already has the producers and a fingerprint-deduped findings index;
// what it lacked was a planner that fans them out across EVERY shard of the repo
// instead of only the threat-model-seeded hotspots. This script does the
// deterministic part: build the inventory, shard the repo, and emit a job
// manifest (shard × applicable producer) with budget-scaled caps. The
// sweep-coordinator agent then runs the jobs in parallel; sweep-finalize
// aggregates coverage. No reasoning happens here — same repo → same plan.

import { resolve, join } from "node:path";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { inventory, planShards } from "../lib/sharding.mjs";
import { findBinaries } from "../lib/binaries.mjs";

const CMD_DIR = import.meta.dirname ?? resolve(".");

// Languages a producer is worth running against. "any" = run on every shard.
const WEB_LANGS = ["Java", "Kotlin", "Scala", "JavaScript", "TypeScript", "Python", "Ruby", "PHP", "Go"];
const NATIVE_LANGS = ["C", "C++", "Rust", "Objective-C", "Go"];

// The producer registry. scope:"shard" → one job per applicable shard;
// scope:"repo" → a single repo-wide job. `network:true` producers are skipped
// when the sweep is run with { offline:true } (the zero-exfil guarantee).
const PRODUCERS = {
  "threat-hunt": { agent: "threat-hunter", scope: "repo", langs: "any", requires: "threat-model", default: true },
  // Whole-file deep reader — the un-pattern-gated recall lever. Off by default
  // (token-expensive); included when the sweep is run with { deep:true }.
  "deep-scan": { agent: "deep-scanner", scope: "shard", langs: "any", deepOnly: true, default: false },
  // Interprocedural hypothesis hunt — walks source→sink across files. Also deepOnly
  // (token-expensive); the cross-file recall lever beyond the whole-file reader.
  "deep-hunt": { agent: "deep-hunter", scope: "shard", langs: "any", deepOnly: true, default: false },
  "taint-analysis": { agent: "taint-triager", scope: "shard", langs: "any", default: true },
  authz: { agent: "authz-reviewer", scope: "shard", langs: WEB_LANGS, default: true },
  "logic-hunt": { agent: "logic-hunter", scope: "shard", langs: WEB_LANGS, default: true },
  "crypto-review": { agent: "crypto-reviewer", scope: "shard", langs: "any", default: true },
  "sharp-edges": { agent: "sharp-edges-analyzer", scope: "shard", langs: "any", default: true },
  "systems-hunt": { agent: "systems-hunter", scope: "shard", langs: NATIVE_LANGS, default: true },
  "binary-recon": { agent: "binary-recon", scope: "repo", langs: "any", requires: "binaries", default: true },
  iac: { agent: "iac-reviewer", scope: "repo", langs: "any", default: true },
  sast: { agent: "sast-triager", scope: "shard", langs: "any", requires: "semgrep", default: true },
  "supply-chain": { agent: "supply-chain-auditor", scope: "repo", langs: "any", network: true, default: true }
};

function shardLangs(shard) {
  return new Set(Object.keys(shard.byLanguage).filter((l) => l !== "Other"));
}

function appliesToShard(spec, shard) {
  if (spec.langs === "any") return true;
  const langs = shardLangs(shard);
  return spec.langs.some((l) => langs.has(l));
}

// Per-shard candidate cap scales with shard size so a big shard isn't silently
// under-sampled (the recall failure mode) but a tiny one doesn't waste a budget.
function capFor(fileCount) {
  return Math.min(24, Math.max(4, Math.ceil(fileCount / 3)));
}

// Deterministic requirement gating: a producer that needs something the repo
// doesn't have is recorded in `skipped`, not silently dropped or blindly queued.
function meetsRequirement(requires, target, store, binaries) {
  if (requires === "threat-model") return existsSync(store.threatModelPath);
  if (requires === "semgrep") return spawnSync("semgrep", ["--version"], { stdio: "ignore" }).status === 0;
  if (requires === "binaries") return binaries.length > 0;
  return true;
}

function cliOk(cmd, args = ["--version"]) {
  try { return spawnSync(cmd, args, { stdio: "ignore" }).status === 0; } catch { return false; }
}

// Interprocedural depth is best-effort: cross-file taint wants a CodeQL DB / Joern
// CPG. In deep mode we recommend building them when the engines are present and the
// DBs aren't, and we say so honestly when they're not (the flow tracing degrades to
// same-file linking). This only RECOMMENDS — the coordinator runs the build.
function interprocPlan({ deep, offline, store }) {
  if (!deep) return null;
  const codeqlDb = existsSync(store.codeqlDbDir);
  const joernCpg = existsSync(store.joernCpgPath);
  if (codeqlDb || joernCpg) {
    return { status: "ready", codeqlDb, joernCpg, note: "prebuilt semantic DB present — flow tracing can cross files." };
  }
  if (offline) {
    return { status: "degraded", reason: "offline — not building semantic DBs; cross-file flow tracing degrades to same-file linking." };
  }
  const haveCodeql = cliOk("codeql");
  const haveJoern = cliOk("joern-parse", ["--help"]) || cliOk("joern", ["--help"]);
  if (!haveCodeql && !haveJoern) {
    return { status: "unavailable", reason: "no codeql/joern CLI on PATH — install for cross-file depth; flow tracing degrades to same-file linking." };
  }
  const which = haveCodeql && haveJoern ? "both" : haveCodeql ? "codeql" : "joern";
  return {
    status: "recommended",
    engines: { codeql: haveCodeql, joern: haveJoern },
    note: "engines available but no DB built — build for cross-file depth before flow-tracing jobs.",
    buildCommand: `node "${join(CMD_DIR, "build-databases.mjs")}" --target "${store.target}" --input '{"which":"${which}","background":true}'`
  };
}

function prepareCommand(producer, target, prepInput) {
  const input = JSON.stringify(prepInput).replace(/"/g, '\\"');
  return `node "${join(CMD_DIR, `${producer}-prepare.mjs`)}" --target "${target}" --input "${input}"`;
}

export function prepareSweep(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const offline = Boolean(input.offline);
  const deep = Boolean(input.deep);
  const maxFilesPerShard = Number(input.maxFilesPerShard ?? 60);

  const requested = Array.isArray(input.producers) && input.producers.length
    ? new Set(input.producers)
    : null;

  const inv = inventory(resolvedTarget);
  const shards = planShards(inv.files, { maxFilesPerShard });
  const binaries = findBinaries(resolvedTarget);

  const selected = Object.entries(PRODUCERS).filter(([name, spec]) => {
    if (requested) return requested.has(name);
    // deepOnly producers (the token-heavy whole-file reader) join only in deep mode.
    if (spec.deepOnly) return deep;
    return spec.default;
  });

  const jobs = [];
  const skipped = [];
  let jobId = 0;
  for (const [producer, spec] of selected) {
    if (offline && spec.network) {
      skipped.push({ producer, reason: "offline: producer may make network calls" });
      continue;
    }
    if (spec.requires && !meetsRequirement(spec.requires, resolvedTarget, store, binaries)) {
      skipped.push({ producer, reason: `requirement not met: ${spec.requires}` });
      continue;
    }
    if (spec.scope === "repo") {
      const prepInput = { sweep: true, ...(spec.requires ? { requires: spec.requires } : {}) };
      jobs.push({
        jobId: `j${++jobId}`,
        producer,
        agent: spec.agent,
        scope: "repo",
        shardId: null,
        scopeDir: ".",
        requires: spec.requires ?? null,
        prepInput,
        prepareCommand: prepareCommand(producer, resolvedTarget, prepInput)
      });
      continue;
    }
    // scope: shard
    let emitted = 0;
    for (const shard of shards) {
      if (!appliesToShard(spec, shard)) continue;
      // deep-scan budgets by files-to-read; pattern producers budget by candidate hits.
      const prepInput = spec.deepOnly
        ? { sweep: true, scopeDir: shard.scopeDir, maxFiles: capFor(shard.fileCount) }
        : { sweep: true, scopeDir: shard.scopeDir, maxCandidates: capFor(shard.fileCount) };
      jobs.push({
        jobId: `j${++jobId}`,
        producer,
        agent: spec.agent,
        scope: "shard",
        shardId: shard.id,
        scopeDir: shard.scopeDir,
        requires: spec.requires ?? null,
        prepInput,
        prepareCommand: prepareCommand(producer, resolvedTarget, prepInput)
      });
      emitted += 1;
    }
    if (!emitted) skipped.push({ producer, reason: "no shard matched the producer's languages" });
  }

  const run = openRun(resolvedTarget, "sweep");
  const plan = {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    offline,
    deep,
    inventory: { totalFiles: inv.totalFiles, byLanguage: inv.byLanguage },
    shardCount: shards.length,
    shards: shards.map((s) => ({ id: s.id, name: s.name, scopeDir: s.scopeDir, fileCount: s.fileCount, byLanguage: s.byLanguage })),
    producerSet: selected.map(([name]) => name),
    interproc: interprocPlan({ deep, offline, store }),
    jobCount: jobs.length,
    jobs,
    skipped,
    input
  };
  run.writeJson("sweep-plan.json", plan);
  // Mirror the plan to the canonical store path so sweep-finalize / the hook can
  // find the latest plan without knowing the run id.
  atomicWrite(store.sweepPlanPath, `${JSON.stringify(plan, null, 2)}\n`);

  return {
    ok: true,
    status: jobs.length ? "prepared" : "no-jobs",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    planPath: store.sweepPlanPath,
    shardCount: shards.length,
    jobCount: jobs.length,
    producerSet: plan.producerSet,
    skipped,
    finalizeCommand: `node "${join(CMD_DIR, "sweep-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('sweep-prepare --target <path> [--input \'{"offline":false,"producers":["authz"],"maxFilesPerShard":60}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("sweep-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareSweep(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
