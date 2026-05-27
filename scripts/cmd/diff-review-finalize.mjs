#!/usr/bin/env node
// Finalize phase for /diff-review. Validates the per-change verdicts the agent
// drafted (same closed set + rigor as threat-hunt), persists .kuzushi/diff-review.json,
// and promotes verdicts into .kuzushi/findings.json (source "diff-review").

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set([
  "exploitable", "likely-library-noise", "reviewed-no-impact",
  "needs-more-evidence", "needs-active-agent-trace"
]);
const MIN_RATIONALE_LENGTH = 200;
const VERDICTS_REQUIRING_ANCHORS = new Set(["exploitable", "reviewed-no-impact", "needs-active-agent-trace"]);

function fail(message) {
  console.error(`diff-review-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.changeId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`change ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`change ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Cover what changed, the attacker, source→sink, regression check, and blast radius.`);
    }
    if (VERDICTS_REQUIRING_ANCHORS.has(c.verdict)) {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`change ${id}: verdict "${c.verdict}" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`change ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
    if (c.verdict === "reviewed-no-impact" && !/guard|check|valid|sanitiz|escap|param|author/i.test(rationale)) {
      fail(`change ${id}: verdict "reviewed-no-impact" must name the guard that holds.`);
    }
  }
}

export function finalizeDiffReview(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.diff-review.json");
  if (!existsSync(draftPath)) fail(`no draft.diff-review.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.diff-review.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const prep = JSON.parse(readFileSync(join(resolvedRunDir, "prep.json"), "utf8"));
  const doc = { version: "1.0", generatedAt: new Date().toISOString(), target: resolvedTarget, base: prep.base, candidates: draft.candidates };
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  atomicWrite(store.diffReviewPath, json);
  atomicWrite(join(resolvedRunDir, "diff-review.json"), json);

  const newFindings = draft.candidates.map((c, i) => {
    const anchors = (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    return {
      source: "diff-review",
      refId: c.changeId ?? c.path ?? `diff-${i + 1}`,
      title: c.title ?? c.changeId ?? `Change finding ${i + 1}`,
      severity: c.severity ?? "",
      cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
      verdict: c.verdict,
      status: verdictToStatus(c.verdict),
      evidence: anchors,
      rationale: String(c.rationale ?? ""),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : [],
      ...(c.regression ? { regression: true } : {})
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "diff-review-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget, base: prep.base,
    candidateCount: draft.candidates.length, verdictCounts,
    diffReviewPath: store.diffReviewPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("diff-review-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeDiffReview(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
