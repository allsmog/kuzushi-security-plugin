#!/usr/bin/env node
// Finalize phase for /sast. Validates the triaged semgrep hits the agent kept,
// persists .kuzushi/sast.json, and promotes verdicts into .kuzushi/findings.json
// (source "sast"). Closed verdict set mirrors taint-analysis triage.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const MIN_RATIONALE_LENGTH = 120;

function fail(message) {
  console.error(`sast-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.ruleId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`hit ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`hit ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Say why the hit is a real issue or a false positive, by reading the source.`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`hit ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`hit ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
  }
}

export function finalizeSast(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.sast.json");
  if (!existsSync(draftPath)) fail(`no draft.sast.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.sast.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.sastPath, json);
  atomicWrite(join(resolvedRunDir, "sast.json"), json);

  const newFindings = draft.candidates.map((c, i) => {
    const cwe = (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "";
    const evidence = (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    return {
      source: "sast",
      refId: c.ruleId ?? `sast-${i + 1}`,
      title: c.title ?? c.ruleId ?? `SAST hit ${i + 1}`,
      severity: c.severity ?? "",
      cwe,
      verdict: c.verdict,
      status: verdictToStatus(c.verdict),
      evidence,
      rationale: String(c.rationale ?? ""),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : []
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "sast-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    hitCount: draft.candidates.length, verdictCounts,
    sastPath: store.sastPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("sast-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeSast(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
