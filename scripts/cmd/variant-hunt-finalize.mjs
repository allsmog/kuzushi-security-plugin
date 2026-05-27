#!/usr/bin/env node
// Finalize phase for /variant-hunt. Validates each variant the agent drafted
// (same closed verdict set + rigor as the other hunters), persists
// .kuzushi/variant-hunt.json, and promotes verdicts into .kuzushi/findings.json
// with source "variant-hunt" and refId "variant-of:<seed fingerprint>" so every
// variant traces back to the confirmed bug it was found from.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set([
  "exploitable", "likely-library-noise", "reviewed-no-impact",
  "needs-more-evidence", "needs-active-agent-trace"
]);
const MIN_RATIONALE_LENGTH = 200;
const VERDICTS_REQUIRING_ANCHORS = new Set(["exploitable", "reviewed-no-impact", "needs-active-agent-trace"]);

function fail(message) {
  console.error(`variant-hunt-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.variantId ?? c.id;
    if (!c.seedFingerprint) {
      fail(`variant ${id}: seedFingerprint is required (which confirmed finding is this a variant of?)`);
    }
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`variant ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`variant ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Explain how it matches the seed's bug class and whether a guard differs here.`);
    }
    if (VERDICTS_REQUIRING_ANCHORS.has(c.verdict)) {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`variant ${id}: verdict "${c.verdict}" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`variant ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
    if (c.verdict === "reviewed-no-impact" && !/guard|bounds|check|sanitiz|validat|escap|paramet/i.test(rationale)) {
      fail(`variant ${id}: verdict "reviewed-no-impact" must name the guard that makes this site safe where the seed was not.`);
    }
  }
}

export function finalizeVariantHunt(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.variant-hunt.json");
  if (!existsSync(draftPath)) fail(`no draft.variant-hunt.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.variant-hunt.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.variantHuntPath, json);
  atomicWrite(join(resolvedRunDir, "variant-hunt.json"), json);

  // Enrich from the prep seeds (title/cwe/taintClass per seedFingerprint).
  const prep = readJsonIfPresent(join(resolvedRunDir, "prep.json"));
  const seedMeta = new Map((prep?.seeds ?? []).map((s) => [s.seedFingerprint, s]));
  const newFindings = draft.candidates.map((c, i) => {
    const seed = seedMeta.get(c.seedFingerprint) ?? {};
    const cwe = (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? seed.cwe ?? "";
    const evidence = (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    const shortSeed = String(c.seedFingerprint).slice(0, 8);
    return {
      source: "variant-hunt",
      refId: `variant-of:${c.seedFingerprint}`,
      title: c.title ?? `Variant of ${seed.title ?? shortSeed} (${cwe})`,
      severity: c.severity ?? seed.severity ?? "",
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
  const run = openRun(resolvedTarget, "variant-hunt-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    variantCount: draft.candidates.length, verdictCounts,
    variantHuntPath: store.variantHuntPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("variant-hunt-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeVariantHunt(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
