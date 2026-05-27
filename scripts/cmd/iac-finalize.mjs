#!/usr/bin/env node
// Finalize phase for /iac. Validates the triaged misconfig verdicts, persists
// .kuzushi/iac.json, and promotes verdicts into .kuzushi/findings.json (source "iac").

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const MIN_RATIONALE_LENGTH = 120;
const VALID_SURFACES = new Set(["container", "secrets", "network", "cloud", "transport", "orchestration"]);

function fail(message) {
  console.error(`iac-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.iacId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`item ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (c.surface && !VALID_SURFACES.has(c.surface)) {
      fail(`item ${id}: invalid surface "${c.surface}"; must be one of ${[...VALID_SURFACES].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`item ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). State the misconfig, its impact, and the secure setting.`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`item ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`item ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
  }
}

export function finalizeIac(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.iac.json");
  if (!existsSync(draftPath)) fail(`no draft.iac.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.iac.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.iacPath, json);
  atomicWrite(join(resolvedRunDir, "iac.json"), json);

  const newFindings = draft.candidates.map((c, i) => ({
    source: "iac",
    refId: c.iacId ?? `${c.surface ?? "iac"}-${i + 1}`,
    title: c.title ?? `IaC misconfig: ${c.surface ?? "config"}`,
    severity: c.severity ?? "",
    cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
    verdict: c.verdict,
    status: verdictToStatus(c.verdict),
    evidence: (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
    rationale: String(c.rationale ?? ""),
    nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : [],
    ...(c.surface ? { surface: c.surface } : {})
  }));
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "iac-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, verdictCounts,
    iacPath: store.iacPath, findingsPath: store.findingsPath, findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("iac-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeIac(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
