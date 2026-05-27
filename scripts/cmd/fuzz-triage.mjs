#!/usr/bin/env node
// Triage fuzz-run results into crash groups. This is deterministic and only
// treats sandbox-classified "exploited" runs as empirical crash evidence.

import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";

function hashLog(path) {
  if (!path || !existsSync(path)) return null;
  const text = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean).slice(-80).join("\n");
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

export function fuzzTriage(target) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const runDoc = readJsonIfPresent(store.fuzzRunPath);
  if (!runDoc) throw new Error(`${store.fuzzRunPath} not found — run /fuzz-run first`);
  const crashes = (runDoc.results ?? [])
    .filter((r) => r.proofVerdict === "exploited")
    .map((r) => ({
      findingFingerprint: r.findingFingerprint,
      engine: r.engine,
      language: r.language,
      proofLevel: r.proofLevel,
      logPath: r.logPath,
      crashHash: hashLog(r.logPath) ?? `${r.findingFingerprint}-${r.engine}`,
      minimizable: Boolean(r.harnessDir)
    }));
  const groups = Object.values(crashes.reduce((acc, c) => {
    acc[c.crashHash] ??= { crashHash: c.crashHash, count: 0, crashes: [] };
    acc[c.crashHash].count += 1;
    acc[c.crashHash].crashes.push(c);
    return acc;
  }, {}));
  const doc = {
    version: "1.0",
    schemaVersion: "fuzz-triage.v1",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    groups,
    summary: { crashCount: crashes.length, groupCount: groups.length }
  };
  atomicWrite(store.fuzzTriagePath, `${JSON.stringify(doc, null, 2)}\n`);
  const run = openRun(resolvedTarget, "fuzz-triage");
  run.writeJson("fuzz-triage.json", doc);
  const result = { ok: true, status: "completed", target: resolvedTarget, fuzzTriagePath: store.fuzzTriagePath, summary: doc.summary };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-triage --target <path>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target"] });
  if (!flags.target) {
    console.error("fuzz-triage: --target is required");
    process.exit(1);
  }
  emitResult(fuzzTriage(flags.target));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
