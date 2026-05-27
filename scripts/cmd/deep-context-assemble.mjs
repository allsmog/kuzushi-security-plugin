#!/usr/bin/env node
// Finalize phase for /deep-context. Validates the system-understanding model the
// context-analyst drafted and persists .kuzushi/deep-context.json. This is a
// CONTEXT artifact — no findings, no verdicts. It enforces the context-only
// boundary (rejects vuln/severity/exploit fields) and a minimum of real content.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";

const ARRAY_SECTIONS = ["modules", "entryPoints", "actors", "trustBoundaries", "dataStores", "invariants", "openQuestions"];
// The context phase must not assess vulnerabilities — that's threat-hunt/verify.
const FORBIDDEN_KEYS = ["findings", "vulnerabilities", "severity", "verdict", "exploit", "cwe"];

function fail(message) {
  console.error(`deep-context-assemble: ${message}`);
  process.exit(1);
}

function assertNoVulnFields(obj, where) {
  if (!obj || typeof obj !== "object") return;
  for (const k of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.includes(k.toLowerCase())) {
      fail(`${where}: key "${k}" is out of scope — /deep-context builds understanding only (no vuln/severity/verdict/exploit). Use /threat-hunt for that.`);
    }
  }
}

export function assembleDeepContext(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.deep-context.json");
  if (!existsSync(draftPath)) fail(`no draft.deep-context.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.deep-context.json is not valid JSON"); }

  for (const section of ARRAY_SECTIONS) {
    if (draft[section] !== undefined && !Array.isArray(draft[section])) {
      fail(`"${section}" must be an array if present`);
    }
  }
  // Context-only boundary check (top level + each entry).
  assertNoVulnFields(draft, "draft");
  for (const section of ARRAY_SECTIONS) {
    for (const entry of draft[section] ?? []) assertNoVulnFields(entry, `${section}[]`);
  }

  const modules = draft.modules ?? [];
  const invariants = draft.invariants ?? [];
  if (modules.length < 1 || invariants.length < 1) {
    fail(`a useful deep-context needs at least one module and one invariant (got ${modules.length} modules, ${invariants.length} invariants). If the repo is too opaque, record what's unclear in openQuestions.`);
  }
  if (!draft.systemOverview || String(draft.systemOverview).trim().length < 80) {
    fail(`"systemOverview" (≥80 chars) is required — a short prose model of what the system does and how data moves.`);
  }

  const doc = {
    version: "1.0",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    systemOverview: String(draft.systemOverview),
    modules,
    entryPoints: draft.entryPoints ?? [],
    actors: draft.actors ?? [],
    trustBoundaries: draft.trustBoundaries ?? [],
    dataStores: draft.dataStores ?? [],
    invariants,
    openQuestions: draft.openQuestions ?? []
  };
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  atomicWrite(store.deepContextPath, json);
  atomicWrite(join(resolvedRunDir, "deep-context.json"), json);

  const run = openRun(resolvedTarget, "deep-context-assemble");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    counts: Object.fromEntries(ARRAY_SECTIONS.map((s) => [s, (doc[s] ?? []).length])),
    deepContextPath: store.deepContextPath
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("deep-context-assemble --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(assembleDeepContext(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
