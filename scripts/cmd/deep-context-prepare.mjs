#!/usr/bin/env node
// Prepare phase for /deep-context — a deep reasoning pass that builds a
// system-understanding model BEFORE threat modeling / hunting. It digests the
// context inventory + x-ray entry points and hands the context-analyst agent the
// scope to reason over. Context only; no findings. Read-only, deterministic.

import { existsSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";

function latestContext(store) {
  if (!existsSync(store.runsDir)) return null;
  let latest = null;
  for (const entry of readdirSync(store.runsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("host-context-")) continue;
    const ctx = join(store.runsDir, entry.name, "context.json");
    if (!existsSync(ctx)) continue;
    const mtime = statSync(ctx).mtime;
    if (!latest || mtime > latest.mtime) latest = { path: ctx, mtime };
  }
  return latest ? readJsonIfPresent(latest.path) : null;
}

export function prepareDeepContext(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const context = latestContext(store);
  const entryPointsJson = join(store.xRayDir, "entry-points.json");
  const xRayMd = join(store.xRayDir, "x-ray.md");
  const entryPoints = existsSync(entryPointsJson) ? readJsonIfPresent(entryPointsJson) : null;

  const run = openRun(resolvedTarget, "deep-context");
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    scope: {
      totalFiles: context?.inventory?.totalFiles ?? null,
      byLanguage: context?.inventory?.byLanguage ?? null,
      componentHints: context?.componentHints ?? null,
      xRayMarkdownPath: existsSync(xRayMd) ? xRayMd : null,
      entryPoints: Array.isArray(entryPoints) ? entryPoints.slice(0, 60) : null
    },
    input
  });

  return {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.deep-context.json"),
    contextPresent: Boolean(context),
    xrayPresent: existsSync(xRayMd),
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "deep-context-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("deep-context-prepare --target <path>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("deep-context-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareDeepContext(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
