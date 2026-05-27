#!/usr/bin/env node
// Finalize phase for /path-solve. Validates each path-solution the agent drafted,
// persists .kuzushi/path-solve.json, and attaches a `pathSolution` block onto the
// finding (evidence /verify and /fuzz reuse). Does NOT change the finding's verdict
// — it's solver evidence, not a proof.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { patchFindings } from "../lib/findings.mjs";

const VALID_BACKENDS = new Set(["llm", "z3", "crosshair"]);
const MIN_RATIONALE_LENGTH = 120;

function fail(message) {
  console.error(`path-solve-assemble: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.findingFingerprint ?? "(missing fingerprint)";
    if (!c.findingFingerprint) fail("a candidate is missing findingFingerprint");
    if (!VALID_BACKENDS.has(c.backend)) {
      fail(`${id}: invalid backend "${c.backend}"; must be one of ${[...VALID_BACKENDS].join(", ")}`);
    }
    if (!Array.isArray(c.guards) || c.guards.length < 1) {
      fail(`${id}: at least one extracted guard is required (the path predicate between source and sink).`);
    }
    for (const g of c.guards) {
      if (!g.filePath || g.line === undefined || !g.predicate) {
        fail(`${id}: each guard needs { filePath, line, predicate, branchToTake }.`);
      }
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Explain the predicate and how the input satisfies (or can't satisfy) it.`);
    }
    if (c.reachable && !(c.solvedInput && c.solvedInput.payload)) {
      fail(`${id}: reachable:true requires solvedInput.payload (the concrete input that reaches the sink).`);
    }
  }
}

export function assemblePathSolve(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.path-solve.json");
  if (!existsSync(draftPath)) fail(`no draft.path-solve.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.path-solve.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const solvedAt = new Date().toISOString();
  const doc = { version: "1.0", generatedAt: solvedAt, target: resolvedTarget, candidates: draft.candidates };
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  atomicWrite(store.pathSolvePath, json);
  atomicWrite(join(resolvedRunDir, "path-solve.json"), json);

  const patches = draft.candidates.map((c) => ({
    fingerprint: c.findingFingerprint,
    pathSolution: {
      schemaVersion: "pathSolution.v1",
      backend: c.backend,
      reachable: Boolean(c.reachable),
      guards: c.guards,
      solvedInput: c.solvedInput ?? null,
      unsolvedGuards: Array.isArray(c.unsolvedGuards) ? c.unsolvedGuards : [],
      confidence: Math.min(1, Math.max(0, Number(c.confidence) || 0)),
      rationale: String(c.rationale ?? ""),
      solvedAt
    }
  }));
  const findingsDoc = patchFindings(resolvedTarget, patches);

  const reachableCount = draft.candidates.filter((c) => c.reachable).length;
  const byBackend = draft.candidates.reduce((acc, c) => { acc[c.backend] = (acc[c.backend] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "path-solve-assemble");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    candidateCount: draft.candidates.length, reachableCount, byBackend,
    pathSolvePath: store.pathSolvePath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("path-solve-assemble --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(assemblePathSolve(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
