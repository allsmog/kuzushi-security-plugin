#!/usr/bin/env node
// Prepare phase for /sast (semgrep-driven scan → triage → findings).
//
// SAST hits are noisy leads, not findings — so this stage just opens a run and
// hands the agent the paths. The agent runs `semgrep:scan` (MCP), triages the
// hits against the source, and writes a draft; finalize promotes the kept ones.
// Read-only; deterministic.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { hasContextRun } from "../lib/context-status.mjs";

export function prepareSast(target, input = {}) {
  const resolvedTarget = resolve(target);
  // Best-effort language hint from the context run (optional).
  let languages = [];
  try {
    const status = hasContextRun(resolvedTarget);
    if (status?.built && status.runDir) {
      const ctx = readJsonIfPresent(join(status.runDir, "context.json"));
      languages = Object.entries(ctx?.inventory?.byLanguage ?? {})
        .filter(([l, c]) => l !== "Other" && Number(c) > 0).map(([l]) => l);
    }
  } catch { /* languages stay empty */ }

  const run = openRun(resolvedTarget, "sast");
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    languages,
    references: artifactSnapshot(resolvedTarget),
    config: input.config ?? "auto",
    input
  });

  return {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.sast.json"),
    languages,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "sast-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("sast-prepare --target <path> [--input '{\"config\":\"auto\"}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("sast-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareSast(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
