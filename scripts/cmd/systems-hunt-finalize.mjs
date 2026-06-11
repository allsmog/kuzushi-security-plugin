#!/usr/bin/env node
// Finalize phase for /systems-hunt. Validates each per-candidate verdict the
// agent drafted (same closed verdict set + rigor as threat-hunt), persists
// .kuzushi/systems-hunt.json, and promotes verdicts into .kuzushi/findings.json
// (source "systems-hunt"), enriched from the prep candidate metadata.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";
import { severityFieldsFor } from "../lib/severity.mjs";
import { remediationFor } from "../lib/remediation.mjs";

// Statuses that represent live, fixable work — only these carry remediation.
const ACTIONABLE = new Set(["open", "confirmed", "proven", "needs-evidence", "needs-trace"]);

const VALID_VERDICTS = new Set([
  "exploitable", "likely-library-noise", "reviewed-no-impact",
  "needs-more-evidence", "needs-active-agent-trace"
]);
const MIN_RATIONALE_LENGTH = 200;
const VERDICTS_REQUIRING_ANCHORS = new Set(["exploitable", "reviewed-no-impact", "needs-active-agent-trace"]);

function fail(message) {
  console.error(`systems-hunt-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.candidateId ?? c.id;
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`candidate ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`candidate ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Walk attacker reachability → the native/memory boundary → impact, not a one-liner.`);
    }
    if (VERDICTS_REQUIRING_ANCHORS.has(c.verdict)) {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`candidate ${id}: verdict "${c.verdict}" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`candidate ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
    if (c.verdict === "reviewed-no-impact" && !/guard|bounds|check|sanitiz|validat/i.test(rationale)) {
      fail(`candidate ${id}: verdict "reviewed-no-impact" must name the guard / bounds-check that closes the path.`);
    }
  }
}

export function finalizeSystemsHunt(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.systems-hunt.json");
  if (!existsSync(draftPath)) fail(`no draft.systems-hunt.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.systems-hunt.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.systemsHuntPath, json);
  atomicWrite(join(resolvedRunDir, "systems-hunt.json"), json);

  // Enrich findings from the prep candidate metadata (concern/cwe/file).
  const prep = readJsonIfPresent(join(resolvedRunDir, "prep.json"));
  const meta = new Map((prep?.candidates ?? []).map((c) => [c.id, c]));
  const newFindings = draft.candidates.map((c) => {
    const id = c.candidateId ?? c.id;
    const m = meta.get(id) ?? {};
    const cwe = (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? (Array.isArray(m.cwe) ? m.cwe[0] : "") ?? "";
    const evidence = (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    if (!evidence.length && m.filePath) evidence.push({ filePath: m.filePath, startLine: m.line ?? 1 });
    const status = verdictToStatus(c.verdict);
    return {
      source: "systems-hunt",
      refId: id,
      title: m.concern ?? id,
      ...severityFieldsFor(c),
      cwe,
      verdict: c.verdict,
      status,
      evidence,
      rationale: String(c.rationale ?? ""),
      // Actionable findings carry a concrete fix: the agent's if given, else the
      // deterministic CWE floor so "now what?" is always answered.
      ...(ACTIONABLE.has(status) ? { remediation: String(c.remediation ?? "").trim() || remediationFor(cwe) } : {}),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : []
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "systems-hunt-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    candidateCount: draft.candidates.length, verdictCounts,
    systemsHuntPath: store.systemsHuntPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("systems-hunt-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeSystemsHunt(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
