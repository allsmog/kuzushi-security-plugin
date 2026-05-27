#!/usr/bin/env node
// Finalize phase for /verify. Validates each exploitability verdict the agent
// drafted (closed verdict set, confidence range, a PoC sketch + evidence for
// confirmed-exploitable, a named guard for not-exploitable, rationale depth),
// persists .kuzushi/verify.json, and attaches a `verification` block onto each
// finding in the shared index (updating its status). Findings the agent marked
// confirmed-exploitable or inconclusive are tagged PoC-ready for /poc.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { patchFindings, verifyVerdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["confirmed-exploitable", "not-exploitable", "inconclusive"]);
const POC_READY = new Set(["confirmed-exploitable", "inconclusive"]);
const MIN_RATIONALE_LENGTH = 150;
const MIN_DEVILS_ADVOCATE = 60;

// FP-gate framing (Trail of Bits fp-check, our own wording): every decisive
// verdict is a TRUE / FALSE positive call, defended against a devil's-advocate pass.
const GATE_BY_VERDICT = {
  "confirmed-exploitable": "true-positive",
  "not-exploitable": "false-positive",
  inconclusive: "needs-runtime"
};

function fail(message) {
  console.error(`verify-assemble: ${message}`);
  process.exit(1);
}

function clampConfidence(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.min(1, Math.max(0, n));
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.findingFingerprint ?? "(missing fingerprint)";
    if (!c.findingFingerprint) fail(`a candidate is missing findingFingerprint`);
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Show the source→sink reasoning, not a one-liner.`);
    }
    if (c.verdict === "confirmed-exploitable") {
      const sketch = c.pocSketch ?? {};
      if (!sketch.payload || !sketch.howToTrigger) {
        fail(`${id}: verdict "confirmed-exploitable" requires a pocSketch with { payload, howToTrigger }.`);
      }
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`${id}: verdict "confirmed-exploitable" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
      // FP gate: a positive PoC isn't enough — show the NEGATIVE case (an input
      // that should be safely rejected), so the rule/path discriminates.
      if (!c.negativePoc || String(c.negativePoc).trim().length < 20) {
        fail(`${id}: verdict "confirmed-exploitable" requires a negativePoc — an input that should be safely handled/rejected (proves the trigger discriminates, not just fires).`);
      }
    }
    if (c.verdict === "not-exploitable" && !/guard|check|valid|sanitiz|escap|unreachable|param/i.test(rationale)) {
      fail(`${id}: verdict "not-exploitable" must name the guard that holds (or explain why the sink is unreachable) in its rationale.`);
    }
    // Devil's-advocate gate on decisive verdicts: argue the opposite, then rebut.
    if (c.verdict === "confirmed-exploitable" || c.verdict === "not-exploitable") {
      if (!c.devilsAdvocate || String(c.devilsAdvocate).trim().length < MIN_DEVILS_ADVOCATE) {
        fail(`${id}: verdict "${c.verdict}" requires a devilsAdvocate (≥${MIN_DEVILS_ADVOCATE} chars): the strongest argument for the OPPOSITE verdict, and why it fails.`);
      }
    }
  }
}

export function assembleVerify(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.verify.json");
  if (!existsSync(draftPath)) fail(`no draft.verify.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.verify.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const verifiedAt = new Date().toISOString();
  const normalized = draft.candidates.map((c) => ({
    findingFingerprint: c.findingFingerprint,
    verdict: c.verdict,
    confidence: clampConfidence(c.confidence),
    attackVector: c.attackVector ?? null,
    preconditions: Array.isArray(c.preconditions) ? c.preconditions : [],
    pocSketch: c.pocSketch ?? null,
    negativePoc: c.negativePoc ?? null,
    devilsAdvocate: c.devilsAdvocate ?? null,
    gateVerdict: GATE_BY_VERDICT[c.verdict],
    evidenceAnchors: Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [],
    rationale: String(c.rationale ?? ""),
    pocReady: POC_READY.has(c.verdict),
    verifiedAt
  }));

  const doc = { version: "1.0", generatedAt: verifiedAt, target: resolvedTarget, candidates: normalized };
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  atomicWrite(store.verifyPath, json);
  atomicWrite(join(resolvedRunDir, "verify.json"), json);

  // Attach the verification block onto each finding + update its status.
  const patches = normalized.map((c) => ({
    fingerprint: c.findingFingerprint,
    status: verifyVerdictToStatus(c.verdict),
    verification: {
      verdict: c.verdict,
      confidence: c.confidence,
      attackVector: c.attackVector,
      preconditions: c.preconditions,
      pocSketch: c.pocSketch,
      pocReady: c.pocReady,
      gateReview: {
        verdict: c.gateVerdict,
        negativePoc: c.negativePoc,
        devilsAdvocate: c.devilsAdvocate
      },
      verifiedAt
    }
  }));
  const findingsDoc = patchFindings(resolvedTarget, patches);

  const verdictCounts = normalized.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const pocReady = normalized.filter((c) => c.pocReady).map((c) => c.findingFingerprint);

  const run = openRun(resolvedTarget, "verify-assemble");
  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    candidateCount: normalized.length,
    verdictCounts,
    pocReadyCount: pocReady.length,
    pocReady,
    verifyPath: store.verifyPath,
    findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("verify-assemble --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(assembleVerify(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
