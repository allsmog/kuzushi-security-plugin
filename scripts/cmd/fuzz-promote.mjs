#!/usr/bin/env node
// Promote empirical fuzz evidence back into findings.json. Existing findings
// get a fuzz block and move to proven only when /fuzz-run produced an exploited
// verdict. No crash, no promotion.

import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { patchFindings } from "../lib/findings.mjs";

export function fuzzPromote(target) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const runDoc = readJsonIfPresent(store.fuzzRunPath);
  if (!runDoc) throw new Error(`${store.fuzzRunPath} not found — run /fuzz-run first`);
  const triage = readJsonIfPresent(store.fuzzTriagePath);
  const minimize = readJsonIfPresent(store.fuzzMinimizePath);
  const provenAt = new Date().toISOString();
  const exploited = (runDoc.results ?? []).filter((r) => r.proofVerdict === "exploited");
  const crashByFp = new Map();
  for (const group of triage?.groups ?? []) {
    for (const crash of group.crashes ?? []) crashByFp.set(crash.findingFingerprint, group.crashHash);
  }
  const minimizedByHash = new Map((minimize?.results ?? []).map((r) => [r.crashHash, r]));
  const patches = exploited.map((r) => {
    const crashHash = crashByFp.get(r.findingFingerprint) ?? null;
    const minimized = crashHash ? minimizedByHash.get(crashHash) : null;
    return {
      fingerprint: r.findingFingerprint,
      status: "proven",
      fuzz: {
        schemaVersion: "fuzz.v1",
        proofLevel: r.proofLevel,
        proofVerdict: r.proofVerdict,
        engine: r.engine,
        backend: r.backend,
        harnessDir: r.harnessDir,
        runCommand: r.runCommand,
        logPath: r.logPath,
        crashHash,
        minimizedInputPath: minimized?.minimizedInputPath ?? null,
        provenAt
      }
    };
  });
  const findingsDoc = patches.length ? patchFindings(resolvedTarget, patches) : readJsonIfPresent(store.findingsPath);
  const doc = {
    version: "1.0",
    schemaVersion: "fuzz-promote.v1",
    generatedAt: provenAt,
    target: resolvedTarget,
    promoted: patches.map((p) => p.fingerprint),
    summary: { promoted: patches.length }
  };
  atomicWrite(store.fuzzPromotePath, `${JSON.stringify(doc, null, 2)}\n`);
  const run = openRun(resolvedTarget, "fuzz-promote");
  run.writeJson("fuzz-promote.json", doc);
  const result = { ok: true, status: "completed", target: resolvedTarget, fuzzPromotePath: store.fuzzPromotePath, summary: doc.summary, findingsSummary: findingsDoc?.summary ?? null };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-promote --target <path>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target"] });
  if (!flags.target) {
    console.error("fuzz-promote: --target is required");
    process.exit(1);
  }
  emitResult(fuzzPromote(flags.target));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
