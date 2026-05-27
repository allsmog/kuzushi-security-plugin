#!/usr/bin/env node
// Finalize phase for /sharp-edges. Validates the footgun verdicts the agent
// drafted, persists .kuzushi/sharp-edges.json, and promotes verdicts into
// .kuzushi/findings.json (source "sharp-edges").

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const MIN_RATIONALE_LENGTH = 150;
const VALID_CATEGORIES = new Set([
  "algorithm-selection", "dangerous-defaults", "primitive-vs-semantic",
  "configuration-cliff", "silent-failures", "stringly-typed-security"
]);

function fail(message) {
  console.error(`sharp-edges-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.edgeId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`edge ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (c.category && !VALID_CATEGORIES.has(c.category)) {
      fail(`edge ${id}: invalid category "${c.category}"; must be one of ${[...VALID_CATEGORIES].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`edge ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Name the adversary (scoundrel/lazy/confused dev) and how the API lets them reach an insecure state.`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`edge ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`edge ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
  }
}

export function finalizeSharpEdges(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.sharp-edges.json");
  if (!existsSync(draftPath)) fail(`no draft.sharp-edges.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.sharp-edges.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.sharpEdgesPath, json);
  atomicWrite(join(resolvedRunDir, "sharp-edges.json"), json);

  const newFindings = draft.candidates.map((c, i) => {
    const anchors = (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    return {
      source: "sharp-edges",
      refId: c.edgeId ?? `${c.category ?? "edge"}-${i + 1}`,
      title: c.title ?? `Footgun: ${c.category ?? "API misuse"}`,
      severity: c.severity ?? "",
      cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
      verdict: c.verdict,
      status: verdictToStatus(c.verdict),
      evidence: anchors,
      rationale: String(c.rationale ?? ""),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : [],
      ...(c.category ? { category: c.category } : {})
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "sharp-edges-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    edgeCount: draft.candidates.length, verdictCounts,
    sharpEdgesPath: store.sharpEdgesPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("sharp-edges-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeSharpEdges(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
