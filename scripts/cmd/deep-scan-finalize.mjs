#!/usr/bin/env node
// Finalize phase for /deep-scan. Validates the deep reader's vulnerability
// hypotheses (closed verdict set, rationale depth, evidence anchors for a
// "finding"), persists .kuzushi/deep-scan.json, and promotes verdicts into
// findings.json (source "deep-scan"). A deep-scan "finding" is an LLM-read lead —
// strong, but it should flow through /verify (ideally the panel) before it's
// treated as confirmed, exactly because it wasn't gated by a deterministic pattern.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const MIN_RATIONALE_LENGTH = 150;

function fail(message) {
  console.error(`deep-scan-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.deepId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`item ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`item ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Show the data path / trusted assumption that breaks, not a one-liner.`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`item ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`item ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
      if (!c.cwe) fail(`item ${id}: verdict "finding" requires a cwe (e.g. "CWE-89").`);
    }
  }
}

export function finalizeDeepScan(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.deep-scan.json");
  if (!existsSync(draftPath)) fail(`no draft.deep-scan.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.deep-scan.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.deepScanPath, json);
  atomicWrite(join(resolvedRunDir, "deep-scan.json"), json);

  const newFindings = draft.candidates.map((c, i) => ({
    source: "deep-scan",
    refId: c.deepId ?? `deep-${i + 1}`,
    title: c.title ?? `Deep-read finding ${i + 1}`,
    severity: c.severity ?? "",
    cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
    verdict: c.verdict,
    status: verdictToStatus(c.verdict),
    evidence: (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
    rationale: String(c.rationale ?? ""),
    nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : ["/verify (panel) this deep-read lead before treating it as confirmed"],
    ...(c.bugClass ? { bugClass: c.bugClass } : {})
  }));
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "deep-scan-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, verdictCounts,
    deepScanPath: store.deepScanPath, findingsPath: store.findingsPath, findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("deep-scan-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeDeepScan(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
