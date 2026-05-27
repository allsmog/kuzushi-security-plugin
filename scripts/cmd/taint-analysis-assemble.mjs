#!/usr/bin/env node
// Assemble phase for /taint-analysis. Validates the triager's draft.findings.json
// (closed verdict set, evidence anchors, rationale depth, minEvidenceLevel gate),
// persists .kuzushi/taint-analysis.json, and promotes the verdicts into the
// shared .kuzushi/findings.json index with source:"taint-analysis".

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const EVIDENCE_RANK = { candidate: 0, linked: 1, path: 2 };
const MIN_RATIONALE_LENGTH = 120;

function fail(message) {
  console.error(`taint-analysis-assemble: ${message}`);
  process.exit(1);
}

function refLabel(f, i) {
  const anchor = f.sinkAnchor ?? f.evidenceAnchors?.[0] ?? {};
  return `${f.cwe ?? "CWE-?"}@${anchor.filePath ?? `#${i}`}:${anchor.startLine ?? 0}`;
}

// Validate structure; downgrade any `finding` whose evidenceLevel is below the
// run's minEvidenceLevel to `candidate` (IRIS: findings require linked/path).
function validateAndGate(findings, minLevel) {
  const minRank = EVIDENCE_RANK[minLevel] ?? 1;
  const downgraded = [];
  for (let i = 0; i < findings.length; i += 1) {
    const f = findings[i];
    const id = refLabel(f, i);
    if (!VALID_VERDICTS.has(f.verdict)) {
      fail(`finding ${id}: invalid verdict "${f.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (!(f.evidenceLevel in EVIDENCE_RANK)) {
      fail(`finding ${id}: invalid evidenceLevel "${f.evidenceLevel}"; must be one of ${Object.keys(EVIDENCE_RANK).join(", ")}`);
    }
    const rationale = String(f.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`finding ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). State the source, the sink, the flow, and why it is/isn't reachable.`);
    }
    if (f.verdict === "finding") {
      const anchors = Array.isArray(f.evidenceAnchors) ? f.evidenceAnchors : [];
      if (!anchors.length) fail(`finding ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`finding ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
      if ((EVIDENCE_RANK[f.evidenceLevel] ?? 0) < minRank) {
        f.verdict = "candidate";
        f.gatedFrom = "finding";
        downgraded.push(id);
      }
    }
  }
  return { downgraded };
}

export function assembleTaintAnalysis(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const prep = readJsonIfPresent(join(resolvedRunDir, "prep.json")) ?? {};
  const minLevel = prep.minEvidenceLevel ?? "linked";

  const draftPath = join(resolvedRunDir, "draft.findings.json");
  if (!existsSync(draftPath)) fail(`no draft.findings.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.findings.json is not valid JSON"); }
  if (!Array.isArray(draft.findings)) fail("draft must have a findings[] array");

  const { downgraded } = validateAndGate(draft.findings, minLevel);

  const document = {
    version: "1.0",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    runId: prep.runId ?? null,
    minEvidenceLevel: minLevel,
    languages: prep.languages ?? [],
    backends: prep.backends ?? null,
    findings: draft.findings
  };
  const json = `${JSON.stringify(document, null, 2)}\n`;
  atomicWrite(store.taintAnalysisPath, json);
  atomicWrite(join(resolvedRunDir, "taint-analysis.json"), json);

  // Promote into the shared findings index. evidenceAnchors (or the sink anchor)
  // become the finding's evidence; verdictToStatus maps finding/candidate/rejected.
  const newFindings = draft.findings.map((f, i) => {
    const anchors = (f.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    const evidence = anchors.length ? anchors : (f.sinkAnchor ? [{ filePath: f.sinkAnchor.filePath, startLine: f.sinkAnchor.startLine }] : []);
    return {
      source: "taint-analysis",
      refId: refLabel(f, i),
      title: f.title ?? `${f.cwe ?? "CWE-?"} ${f.taintClass ?? ""}`.trim(),
      severity: f.severity ?? "",
      cwe: f.cwe ?? "",
      verdict: f.verdict,
      status: verdictToStatus(f.verdict),
      evidenceLevel: f.evidenceLevel,
      evidence,
      rationale: String(f.rationale ?? ""),
      nextChecks: Array.isArray(f.nextChecks) ? f.nextChecks : []
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.findings.reduce((acc, f) => { acc[f.verdict] = (acc[f.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "taint-analysis-finalize");
  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    findingCount: draft.findings.length,
    verdictCounts,
    downgradedByEvidenceGate: downgraded,
    minEvidenceLevel: minLevel,
    taintAnalysisPath: store.taintAnalysisPath,
    findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("taint-analysis-assemble --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(assembleTaintAnalysis(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
