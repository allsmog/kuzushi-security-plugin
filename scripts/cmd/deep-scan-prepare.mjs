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
import { languageOf } from "../lib/sharding.mjs";
import { extractObligations } from "../lib/sink-obligations.mjs";
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

  // Explicit focus: when the caller names specific files, deep-read exactly those
  // (skip ranking). Useful to drill into a subsystem — and to isolate the
  // breadth-vs-depth variable in eval (read one file deeply, not 30 shallowly).
  let ranked;
  let totalCandidates;
  let unread;
  if (Array.isArray(input.files) && input.files.length) {
    ranked = input.files.map((f) => ({ filePath: String(f).replace(/^\.\//, ""), language: languageOf(String(f)), score: null, reasons: ["explicit-focus"] }));
    totalCandidates = ranked.length;
    unread = 0;
  } else {
    ({ ranked, totalCandidates, unread } = rankFiles(resolvedTarget, { maxFiles, scopeDir }));
  }

  // Attach memory-sink obligations per file (AIxCC-style): a finite checklist of
  // dangerous primitives the agent must discharge, instead of hoping it spots them
  // while free-reading. Only native files yield obligations; others get [].
  let obligationCount = 0;
  if (input.obligations !== false) {
    for (const f of ranked) {
      f.obligations = extractObligations(resolvedTarget, f.filePath);
      obligationCount += f.obligations.length;
    }
  }

  // Cost control is the FILE budget (maxFiles) + function-scoped discharge (the agent
  // pulls each obligation's enclosing function via tree_sitter:node_at, not the whole
  // file). The per-file `obligations` list is the checklist the agent works for each
  // file it reads — it is even-sampled so a dangerous site deep in a long file (e.g.
  // redis t_stream.c's xackdel buffer at L3538) survives. We deliberately do NOT
  // collapse to a global top-K: a file with many sites (t_stream.c) would lose its one
  // vulnerable site to higher-ranked files' noise.

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
    obligationCount,              // memory-sink sites the agent must discharge (per file)
    files: ranked,                // [{ filePath, language, score, reasons[], obligations[] }]
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
