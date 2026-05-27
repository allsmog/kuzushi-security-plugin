#!/usr/bin/env node
// Prepare a PASTA threat-model run: open a run dir, digest the scope inputs
// (latest context.json + x-ray artifacts if present), and emit JSON telling the
// threat-modeler agent exactly where to write each stage file. The agent then
// fills pasta-s1..s4.json and calls threat-model-assemble.mjs.

import { resolve, join } from "node:path";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
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

function xrayScope(target) {
  const xRayDir = storeFor(target).xRayDir;
  const entryPointsJson = join(xRayDir, "entry-points.json");
  const xRayMd = join(xRayDir, "x-ray.md");
  return {
    present: existsSync(xRayMd),
    xRayMarkdown: existsSync(xRayMd) ? xRayMd : null,
    entryPoints: existsSync(entryPointsJson) ? readJsonIfPresent(entryPointsJson) : null
  };
}

export function prepareThreatModel(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const run = openRun(resolvedTarget, "threat-model");

  const context = latestContext(store);
  const xray = xrayScope(resolvedTarget);
  const deepContext = readJsonIfPresent(store.deepContextPath);
  run.writeJson("input.json", input);

  const stageFiles = {
    s1: join(run.runDir, "pasta-s1.json"),
    s2: join(run.runDir, "pasta-s2.json"),
    s3: join(run.runDir, "pasta-s3.json"),
    s4: join(run.runDir, "pasta-s4.json"),
    narrative: join(run.runDir, "pasta-narrative.json")
  };

  return {
    ok: true,
    status: "prepared",
    methodology: input.methodology ?? "pasta",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    stageFiles,
    stages: [
      { id: "s1", name: "Objectives", writes: "pasta-s1.json", focus: "business & security objectives, in-scope assets, attacker goals" },
      { id: "s2", name: "Scope", writes: "pasta-s2.json", focus: "actors, services, databases, components, data_flows" },
      { id: "s3", name: "Decomposition", writes: "pasta-s3.json", focus: "DFD: external_entities/entry_points/processes/data_stores (or dfd_elements), data_flows, trust_boundaries" },
      { id: "s4", name: "Threats", writes: "pasta-s4.json", focus: "threats[]: id, title, stride_category, description, attack_scenario, impact, probability, gaps, existing_controls, recommended_mitigations, related_cwe, target_element_ids, evidence_anchors" }
    ],
    scope: {
      context: context
        ? {
            totalFiles: context.inventory?.totalFiles ?? null,
            byLanguage: context.inventory?.byLanguage ?? null,
            componentHints: context.componentHints ?? null
          }
        : null,
      xray: {
        present: xray.present,
        xRayMarkdownPath: xray.xRayMarkdown,
        entryPointCount: Array.isArray(xray.entryPoints) ? xray.entryPoints.length : null,
        entryPoints: Array.isArray(xray.entryPoints) ? xray.entryPoints.slice(0, 40) : null
      },
      // Deep system-understanding model from /deep-context, if it has been run —
      // a strong grounding for the PASTA decomposition (S3) and threats (S4).
      deepContext: deepContext
        ? {
            present: true,
            path: store.deepContextPath,
            systemOverview: deepContext.systemOverview ?? null,
            moduleCount: (deepContext.modules ?? []).length,
            invariants: (deepContext.invariants ?? []).slice(0, 20),
            trustBoundaries: (deepContext.trustBoundaries ?? []).slice(0, 20),
            openQuestions: (deepContext.openQuestions ?? []).slice(0, 20)
          }
        : { present: false }
    },
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "threat-model-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("threat-model-prepare --target <path> [--input <json>]: open a PASTA run and emit stage paths + scope inputs.");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["help"],
    value: ["target", "input", "input-file"]
  });
  if (!flags.target) {
    console.error("threat-model-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareThreatModel(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
