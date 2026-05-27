#!/usr/bin/env node
// Finalize phase for /traffic-map. Persists the observed-endpoint ↔ source-handler
// correlation to .kuzushi/traffic-map.json (a context artifact threat-model /
// threat-hunt can ground on), and promotes the security gaps the agent flagged
// (shadow surface, unauthenticated mutating endpoints, params reaching sinks) into
// .kuzushi/findings.json (source "traffic-map").

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const VALID_CORR = new Set(["mapped", "shadow", "no-traffic"]);
const MIN_RATIONALE_LENGTH = 120;

function fail(message) {
  console.error(`traffic-map-finalize: ${message}`);
  process.exit(1);
}

function validate(draft) {
  for (const corr of draft.correlations ?? []) {
    if (!corr.method || !corr.path) fail("each correlation needs { method, path }");
    if (corr.status && !VALID_CORR.has(corr.status)) {
      fail(`correlation ${corr.method} ${corr.path}: status must be one of ${[...VALID_CORR].join(", ")}`);
    }
  }
  for (const c of draft.candidates ?? []) {
    const id = c.refId ?? c.path ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`candidate ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (String(c.rationale ?? "").length < MIN_RATIONALE_LENGTH) {
      fail(`candidate ${id}: rationale is too short (min ${MIN_RATIONALE_LENGTH}). Tie the observed request to the handler gap.`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`candidate ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
    }
  }
}

export function finalizeTrafficMap(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.traffic-map.json");
  if (!existsSync(draftPath)) fail(`no draft.traffic-map.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.traffic-map.json is not valid JSON"); }
  if (!Array.isArray(draft.correlations)) fail("draft must have a correlations[] array");

  validate(draft);

  const prep = readJsonIfPresent(join(resolvedRunDir, "prep.json"));
  const doc = {
    version: "1.0", schemaVersion: "traffic-map.v1", generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    captures: prep?.captures ?? [],
    endpoints: prep?.endpoints ?? [],
    correlations: draft.correlations,
    summary: {
      endpoints: (prep?.endpoints ?? []).length,
      mapped: draft.correlations.filter((c) => c.status === "mapped").length,
      shadow: draft.correlations.filter((c) => c.status === "shadow").length,
      noTraffic: draft.correlations.filter((c) => c.status === "no-traffic").length
    }
  };
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  atomicWrite(store.trafficMapPath, json);
  atomicWrite(join(resolvedRunDir, "traffic-map.json"), json);

  const newFindings = (draft.candidates ?? []).map((c, i) => ({
    source: "traffic-map",
    refId: c.refId ?? `${c.method ?? "REQ"}-${(c.path ?? `ep-${i + 1}`).replace(/[^\w/-]/g, "")}`,
    title: c.title ?? `Traffic: ${c.method ?? ""} ${c.path ?? ""}`.trim(),
    severity: c.severity ?? "",
    cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
    verdict: c.verdict,
    status: verdictToStatus(c.verdict),
    evidence: (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
    rationale: String(c.rationale ?? ""),
    nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : []
  }));
  const findingsDoc = newFindings.length ? upsertFindings(resolvedTarget, newFindings) : readJsonIfPresent(store.findingsPath);

  const run = openRun(resolvedTarget, "traffic-map-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    summary: doc.summary, promotedFindings: newFindings.length,
    trafficMapPath: store.trafficMapPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc?.summary ?? null
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("traffic-map-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeTrafficMap(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
