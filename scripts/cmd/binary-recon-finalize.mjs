#!/usr/bin/env node
// Finalize phase for /binary-recon. Validates the read-only binary-triage verdicts
// (closed verdict + binaryClass sets, rationale depth, evidence anchor with the
// binary's path), persists .kuzushi/binary-recon.json, and promotes verdicts into
// findings.json (source "binary-recon"). Assessment only — these findings describe
// hardening/exposure signals, not proven exploits.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const VALID_CLASSES = new Set(["dangerous-import", "rwx-segment", "suspicious-string", "hardening-gap", "embedded-secret"]);
const MIN_RATIONALE_LENGTH = 120;

const CLASS_CWE = {
  "dangerous-import": "CWE-676",   // Use of potentially dangerous function
  "rwx-segment": "CWE-1340",       // missing/weak exploit-mitigation posture
  "suspicious-string": "CWE-200",  // exposure of sensitive information
  "hardening-gap": "CWE-1340",
  "embedded-secret": "CWE-798"     // use of hard-coded credentials
};

function fail(message) {
  console.error(`binary-recon-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.binaryId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`item ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (c.binaryClass && !VALID_CLASSES.has(c.binaryClass)) {
      fail(`item ${id}: invalid binaryClass "${c.binaryClass}"; must be one of ${[...VALID_CLASSES].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`item ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Name the signal, the binary, and why it matters (or why it's benign).`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`item ${id}: verdict "finding" requires at least one evidenceAnchor { filePath }.`);
      for (const a of anchors) {
        if (!a.filePath) fail(`item ${id}: each evidenceAnchor must have a filePath (the binary's path).`);
      }
    }
  }
}

export function finalizeBinaryRecon(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.binary-recon.json");
  if (!existsSync(draftPath)) fail(`no draft.binary-recon.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.binary-recon.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.binaryReconPath, json);
  atomicWrite(join(resolvedRunDir, "binary-recon.json"), json);

  const newFindings = draft.candidates.map((c, i) => ({
    source: "binary-recon",
    refId: c.binaryId ?? `${c.binaryClass ?? "binary"}-${i + 1}`,
    title: c.title ?? `Binary: ${c.binaryClass ?? "signal"}`,
    severity: c.severity ?? "",
    cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? CLASS_CWE[c.binaryClass] ?? "CWE-1340",
    verdict: c.verdict,
    status: verdictToStatus(c.verdict),
    evidence: (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, ...(a.startLine !== undefined ? { startLine: a.startLine } : {}) })),
    rationale: String(c.rationale ?? ""),
    nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : [],
    ...(c.binaryClass ? { binaryClass: c.binaryClass } : {})
  }));
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "binary-recon-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, verdictCounts,
    binaryReconPath: store.binaryReconPath, findingsPath: store.findingsPath, findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("binary-recon-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeBinaryRecon(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
