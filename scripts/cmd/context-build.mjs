#!/usr/bin/env node
// Build a compact repository context snapshot: file inventory, language
// breakdown, top component hints, and pointers to existing artifacts. Writes
// <target>/.kuzushi/runs/host-context-*/context.json so the rest of the kuzushi
// pipeline can consume it.
//
// Importable: call buildContext(target, input) directly (the SessionStart hook
// does this — no subprocess). Runnable: `context-build --target <path>`.

import { resolve } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import {
  storeFor,
  openRun,
  artifactSnapshot,
  emitResult
} from "../lib/artifact-store.mjs";
import { listFiles, runRg } from "../lib/ripgrep.mjs";

function languageFromPath(path) {
  if (path.endsWith(".java")) return "Java";
  if (path.endsWith(".kt") || path.endsWith(".kts")) return "Kotlin";
  if (path.endsWith(".rb") || path.endsWith(".erb")) return "Ruby";
  if (path.endsWith(".py")) return "Python";
  if (path.endsWith(".js") || path.endsWith(".jsx") || path.endsWith(".mjs") || path.endsWith(".cjs")) return "JavaScript";
  if (path.endsWith(".ts") || path.endsWith(".tsx")) return "TypeScript";
  if (path.endsWith(".c") || path.endsWith(".h")) return "C";
  if (path.endsWith(".cc") || path.endsWith(".cpp") || path.endsWith(".hpp")) return "C++";
  if (path.endsWith(".rs")) return "Rust";
  if (path.endsWith(".go")) return "Go";
  if (path.endsWith(".php")) return "PHP";
  if (path.endsWith(".scala")) return "Scala";
  return "Other";
}

const COMPONENT_MARKERS = [
  { glob: "Gemfile", role: "Ruby app (probably Rails)" },
  { glob: "package.json", role: "Node.js project" },
  { glob: "Cargo.toml", role: "Rust workspace" },
  { glob: "go.mod", role: "Go module" },
  { glob: "build.gradle*", role: "Gradle / Android / JVM" },
  { glob: "pom.xml", role: "Maven project" },
  { glob: "AndroidManifest.xml", role: "Android app manifest" },
  { glob: "Dockerfile", role: "Containerized" },
  { glob: "compile_commands.json", role: "Clang compile DB present" }
];

// Core builder. Performs the inventory, writes the run artifacts, returns the
// result envelope. Throws only on unexpected I/O failure.
export function buildContext(target, input = {}) {
  const resolved = resolve(target);
  const store = storeFor(resolved);
  const run = openRun(resolved, "context");

  const limit = Number(input.inventoryLimit ?? 200);
  const files = listFiles(resolved);
  const byLanguage = {};
  for (const file of files) {
    const lang = languageFromPath(file);
    byLanguage[lang] = (byLanguage[lang] ?? 0) + 1;
  }
  const sampleFiles = files.slice(0, limit);

  const componentHints = [];
  for (const marker of COMPONENT_MARKERS) {
    const result = runRg(resolved, ["--files", "-g", marker.glob]);
    const hits = result.ok ? result.stdout.split(/\r?\n/).filter(Boolean) : [];
    if (hits.length > 0) {
      componentHints.push({ marker: marker.glob, role: marker.role, count: hits.length, files: hits.slice(0, 5) });
    }
  }

  const result = {
    ok: true,
    status: "completed",
    target: resolved,
    runId: run.runId,
    runDir: run.runDir,
    store: store.storeName,
    inventory: {
      totalFiles: files.length,
      byLanguage,
      sampleFiles
    },
    componentHints,
    artifacts: artifactSnapshot(resolved)
  };

  run.writeJson("input.json", input);
  run.writeJson("context.json", result);
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("context-build --target <path> [--input <json>]: build a repo context snapshot.");
    process.exit(0);
  }

  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["json", "help"],
    value: ["target", "input", "input-file"]
  });

  if (!flags.target) {
    console.error("context-build: --target is required");
    process.exit(1);
  }

  const input = loadInput(flags);
  emitResult(buildContext(flags.target, input));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
