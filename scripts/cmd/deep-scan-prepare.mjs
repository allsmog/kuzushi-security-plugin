#!/usr/bin/env node
// Prepare phase for /deep-scan — the whole-file deep reader.
//
// Every other producer is pattern-gated: it greps for known-dangerous shapes, so a
// bug that doesn't match a pattern is never surfaced (the recall ceiling). /deep-scan
// removes that gate. It picks the highest-risk files (within a token budget) and
// hands the deep-scanner agent the *files themselves* to read in full and reason
// about from first principles — the way a human auditor finds the bugs scanners miss.
// Deterministic here: same repo + artifacts → same ranked file list. No reasoning.

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { rankFiles } from "../lib/risk-rank.mjs";
import { buildCodeGraph } from "./code-graph-build.mjs";

export function prepareDeepScan(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxFiles = Number(input.maxFiles ?? 30);
  const scopeDir = input.scopeDir ?? ".";

  // Reachability-driven ranking needs a code-graph. Build/refresh it first (cheap
  // ripgrep heuristic; uses a Joern CPG automatically if one exists) unless one is
  // already present and the caller opted out. This is what lets risk-rank prioritize
  // high-blast-radius core files over keyword matches.
  const store = storeFor(resolvedTarget);
  if (input.buildCodeGraph !== false && !existsSync(store.codeGraphPath)) {
    try { buildCodeGraph(resolvedTarget, {}); } catch { /* ranking degrades to keyword/churn */ }
  }

  const { ranked, totalCandidates, unread } = rankFiles(resolvedTarget, { maxFiles, scopeDir });

  const run = openRun(resolvedTarget, "deep-scan");
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    scopeDir,
    references: artifactSnapshot(resolvedTarget),
    budget: { maxFiles },
    totalCandidates,
    unreadCount: unread,          // honest: how many in-scope files were NOT read
    fileCount: ranked.length,
    files: ranked,                // [{ filePath, language, score, reasons[] }]
    input
  });

  return {
    ok: true,
    status: ranked.length ? "prepared" : "no-files",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.deep-scan.json"),
    fileCount: ranked.length,
    unreadCount: unread,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "deep-scan-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('deep-scan-prepare --target <path> [--input \'{"maxFiles":25,"scopeDir":"src"}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("deep-scan-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareDeepScan(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
