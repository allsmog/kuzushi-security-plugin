#!/usr/bin/env node
// Install the curated starter query pack into a target's .kuzushi/rules/.
//
// Deep-by-default has two halves: a built DB/CPG (auto-build) and QUERIES to run
// against it. Without shipped queries the agent hand-writes CodeQL/Joern on every
// run — slow and inconsistent. This copies the maintainer-curated starter queries
// (packs/starter/) into <target>/.kuzushi/rules/{codeql,joern}/ and registers each
// in the digest-attested pack manifest (validated.compile = true), so the codeql/
// joern MCP servers will run them by default — the execution gate (assertRunnable)
// checks the on-disk bytes against the digest we record here.

import { existsSync, readFileSync, mkdirSync, copyFileSync } from "node:fs";
import { resolve, join, dirname, relative, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, emitResult } from "../lib/artifact-store.mjs";
import { writePack, digestBytes } from "../lib/rule-pack.mjs";

const STARTER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "packs", "starter");

function fail(message) {
  console.error(`install-starter-pack: ${message}`);
  process.exit(1);
}

export function installStarterPack(target) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const manifestPath = join(STARTER_DIR, "manifest.json");
  if (!existsSync(manifestPath)) fail(`starter manifest not found at ${manifestPath}`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

  const entries = [];
  const installed = [];
  for (const rule of manifest.rules ?? []) {
    const src = join(STARTER_DIR, rule.file);
    if (!existsSync(src)) fail(`starter rule file missing: ${src}`);
    // Mirror the pack layout: codeql/<lang>/<file> or joern/<file> under rules/.
    const destDir = rule.engine === "codeql"
      ? join(store.rulesCodeqlDir, rule.language ?? "any")
      : store.rulesJoernDir;
    mkdirSync(destDir, { recursive: true });
    const dest = join(destDir, basename(rule.file));
    copyFileSync(src, dest);
    const bytes = readFileSync(dest);
    const fileRel = relative(resolvedTarget, dest);
    entries.push({
      ruleId: rule.ruleId,
      engine: rule.engine,
      language: rule.language ?? "any",
      cwe: rule.cwe,
      seed: "shipped-starter",
      file: fileRel,
      digest: digestBytes(bytes),
      // The execution gate requires validated.compile; for a shipped pack this
      // attests maintainer + CI validation (the engine isn't required to install).
      validated: {
        compile: true,
        source: "shipped-starter",
        note: "curated by maintainers; CI re-validates compile/fire against the engine when present"
      },
      title: rule.title ?? rule.ruleId
    });
    installed.push(fileRel);
  }

  const pack = writePack(resolvedTarget, entries);
  return {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    installedCount: entries.length,
    installed,
    rulePackManifestPath: store.rulePackManifestPath,
    ruleCount: pack.rules.length
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("install-starter-pack --target <path>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target"] });
  if (!flags.target) fail("--target is required");
  emitResult(installStarterPack(flags.target));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
