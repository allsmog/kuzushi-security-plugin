#!/usr/bin/env node
// Assemble the invariant-tester's results stage file (invariant-findings.json)
// into the canonical .kuzushi/invariant-results.json with a verdict summary.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, atomicWrite, emitResult } from "../lib/artifact-store.mjs";

const VERDICTS = new Set(["hold", "violated", "needs-review"]);

function str(v) { return typeof v === "string" ? v.trim() : ""; }

function normVerdict(v) {
  const s = str(v).toLowerCase().replace("needs_review", "needs-review");
  return VERDICTS.has(s) ? s : "needs-review";
}

function normEvidence(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.map((e) => ({
    file: str(e?.file),
    line: Number(e?.line) || null,
    snippet: str(e?.snippet),
    note: str(e?.note)
  })).filter((e) => e.file);
}

export function assembleInvariantResults(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const stagePath = join(resolvedRunDir, "invariant-findings.json");
  if (!existsSync(stagePath)) {
    throw new Error(`no invariant-findings.json in ${resolvedRunDir}`);
  }
  let stage;
  try { stage = JSON.parse(readFileSync(stagePath, "utf8")); } catch {
    throw new Error(`invariant-findings.json is not valid JSON`);
  }
  const raw = Array.isArray(stage?.results) ? stage.results : Array.isArray(stage) ? stage : [];

  const results = raw.map((r) => ({
    invariantId: str(r?.invariantId),
    statement: str(r?.statement),
    cwe: str(r?.cwe),
    severity: str(r?.severity),
    verdict: normVerdict(r?.verdict),
    evidence: normEvidence(r?.evidence),
    toolsUsed: Array.isArray(r?.toolsUsed) ? r.toolsUsed.filter((t) => typeof t === "string") : []
  })).filter((r) => r.invariantId);

  const summary = { total: results.length, violated: 0, needsReview: 0, hold: 0 };
  for (const r of results) {
    if (r.verdict === "violated") summary.violated += 1;
    else if (r.verdict === "needs-review") summary.needsReview += 1;
    else summary.hold += 1;
  }

  const document = { version: "1.0", generatedAt: new Date().toISOString(), target: resolvedTarget, results, summary };
  const json = `${JSON.stringify(document, null, 2)}\n`;
  atomicWrite(store.invariantResultsPath, json);
  atomicWrite(join(resolvedRunDir, "invariant-results.json"), json);

  return { ok: true, status: "completed", target: resolvedTarget, invariantResultsPath: store.invariantResultsPath, runDir: resolvedRunDir, summary };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("invariant-assemble --target <path> --run-dir <dir>: normalize invariant results into .kuzushi/invariant-results.json.");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) {
    console.error("invariant-assemble: --target and --run-dir are required");
    process.exit(1);
  }
  emitResult(assembleInvariantResults(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
