#!/usr/bin/env node
// Prepare a threat-intel research run: open a run dir, digest the scope inputs
// (detected stack from context, the threat model if present, x-ray entry points,
// and any dependency manifests/lockfiles), and emit JSON telling the
// threat-intel-researcher agent where to write each stage file.

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

// Dependency manifests/lockfiles at the repo root (bounded; for version-checking
// CVE applicability). Big lockfiles are noted as present without slurping them.
const MANIFESTS = [
  "package.json", "package-lock.json", "go.mod", "go.sum", "Gemfile.lock",
  "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt"
];

function collectManifests(target) {
  const out = [];
  for (const name of MANIFESTS) {
    const path = join(target, name);
    if (!existsSync(path)) continue;
    let size = 0;
    try { size = statSync(path).size; } catch {}
    const entry = { name, path, sizeBytes: size };
    // Include content for small manifests (not giant lockfiles) so the agent can
    // read declared dependency versions.
    if (size > 0 && size <= 64 * 1024 && !name.endsWith(".lock") && name !== "package-lock.json" && name !== "go.sum") {
      try { entry.content = readFileSync(path, "utf8").slice(0, 16 * 1024); } catch {}
    }
    out.push(entry);
  }
  return out;
}

export function prepareThreatIntel(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const run = openRun(resolvedTarget, "threat-intel");

  const context = latestContext(store);
  const threatModel = readJsonIfPresent(store.threatModelPath);
  const xRayEntryPoints = readJsonIfPresent(join(store.xRayDir, "entry-points.json"));
  run.writeJson("input.json", input);

  const stageFiles = {
    stackCves: join(run.runDir, "intel-stack-cves.json"),
    similarApps: join(run.runDir, "intel-similar-apps.json"),
    invariants: join(run.runDir, "intel-invariants.json")
  };

  return {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    stageFiles,
    severityFilter: ["critical", "high"],
    scope: {
      languages: context?.inventory?.byLanguage ?? null,
      componentHints: context?.componentHints ?? null,
      manifests: collectManifests(resolvedTarget),
      threatModel: threatModel
        ? {
            methodology: threatModel.methodology ?? null,
            threatCount: Array.isArray(threatModel.threats) ? threatModel.threats.length : 0,
            relatedCwes: [...new Set((threatModel.threats ?? []).flatMap((t) => t.relatedCwe ?? []))].slice(0, 30),
            topThreats: (threatModel.threats ?? []).slice(0, 12).map((t) => ({ id: t.id, title: t.title, category: t.category, impact: t.impact }))
          }
        : null,
      entryPoints: Array.isArray(xRayEntryPoints) ? xRayEntryPoints.slice(0, 40) : null
    },
    stages: [
      { id: "stack-cves", writes: "intel-stack-cves.json", focus: "recent (≤18mo) CRITICAL/HIGH CVEs for the detected frameworks/SDKs/deps; version-check against manifests; concrete checks_to_run" },
      { id: "similar-apps", writes: "intel-similar-apps.json", focus: "the app's domain + CVE classes / public incidents in similar apps & their SDKs" },
      { id: "invariants", writes: "intel-invariants.json", focus: "distill the CVEs into machine-checkable invariants with source/sink/sanitizer signals + CWE + taint_class" }
    ],
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "threat-intel-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("threat-intel-prepare --target <path> [--input <json>]: open a research run and emit scope + stage paths.");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("threat-intel-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareThreatIntel(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
