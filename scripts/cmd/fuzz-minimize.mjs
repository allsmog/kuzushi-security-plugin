#!/usr/bin/env node
// Record minimization status for triaged fuzz crashes. Engine-specific corpus
// minimization commands can be added to the fuzz plan later; this MVP preserves
// crash groups and refuses to invent a minimized input when none was produced.

import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";

export function fuzzMinimize(target) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const triage = readJsonIfPresent(store.fuzzTriagePath);
  if (!triage) throw new Error(`${store.fuzzTriagePath} not found — run /fuzz-triage first`);
  const results = (triage.groups ?? []).map((group) => ({
    crashHash: group.crashHash,
    findingFingerprints: [...new Set((group.crashes ?? []).map((c) => c.findingFingerprint))],
    status: "not-minimized",
    minimizedInputPath: null,
    note: "No engine-specific minimizer command was supplied; crash group is preserved for manual minimization."
  }));
  const doc = {
    version: "1.0",
    schemaVersion: "fuzz-minimize.v1",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    results,
    summary: { groupCount: results.length, minimized: results.filter((r) => r.status === "minimized").length }
  };
  atomicWrite(store.fuzzMinimizePath, `${JSON.stringify(doc, null, 2)}\n`);
  const run = openRun(resolvedTarget, "fuzz-minimize");
  run.writeJson("fuzz-minimize.json", doc);
  const result = { ok: true, status: "completed", target: resolvedTarget, fuzzMinimizePath: store.fuzzMinimizePath, summary: doc.summary };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-minimize --target <path>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target"] });
  if (!flags.target) {
    console.error("fuzz-minimize: --target is required");
    process.exit(1);
  }
  emitResult(fuzzMinimize(flags.target));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
