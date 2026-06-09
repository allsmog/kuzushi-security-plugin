#!/usr/bin/env node
// Finalize phase for /threat-hunt. Validates each per-threat verdict the agent
// drafted (closed verdict set, rationale depth, evidence anchors, guard mention
// for reviewed-no-impact), persists .kuzushi/threat-hunt.json, and promotes the
// verdicts into the shared .kuzushi/findings.json index.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";
import { remediationFor } from "../lib/remediation.mjs";

const ACTIONABLE = new Set(["open", "confirmed", "proven", "needs-evidence", "needs-trace"]);

const VALID_VERDICTS = new Set([
  "exploitable", "likely-library-noise", "reviewed-no-impact",
  "needs-more-evidence", "needs-active-agent-trace"
]);
const MIN_RATIONALE_LENGTH = 200;
const VERDICTS_REQUIRING_ANCHORS = new Set(["exploitable", "reviewed-no-impact", "needs-active-agent-trace"]);

function fail(message) {
  console.error(`threat-hunt-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`threat ${c.threatId}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`threat ${c.threatId}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). The 6-step walk must produce concrete reasoning, not a one-liner.`);
    }
    if (VERDICTS_REQUIRING_ANCHORS.has(c.verdict)) {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`threat ${c.threatId}: verdict "${c.verdict}" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`threat ${c.threatId}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
    if (c.verdict === "reviewed-no-impact" && !/guard/i.test(rationale)) {
      fail(`threat ${c.threatId}: verdict "reviewed-no-impact" must name at least one guard in its rationale. If no guard exists, the verdict is wrong.`);
    }
  }
}

// Look up title/severity/cwe from the threat model so promoted findings are rich.
function threatLookup(store) {
  const tm = readJsonIfPresent(store.threatModelPath);
  const map = new Map();
  for (const t of tm?.threats ?? []) {
    map.set(t.id, { title: t.title, severity: t.impact, cwe: (t.relatedCwe ?? [])[0] ?? "" });
  }
  return map;
}

export function finalizeThreatHunt(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.threat-hunt.json");
  if (!existsSync(draftPath)) fail(`no draft.threat-hunt.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.threat-hunt.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.threatHuntPath, json);
  atomicWrite(join(resolvedRunDir, "threat-hunt.json"), json);

  // Promote every verdict into the shared findings index.
  const lookup = threatLookup(store);
  const newFindings = draft.candidates.map((c) => {
    const meta = lookup.get(c.threatId) ?? {};
    return {
      source: "threat-hunt",
      refId: c.threatId,
      title: meta.title ?? c.threatId,
      severity: meta.severity ?? "",
      cwe: meta.cwe ?? "",
      verdict: c.verdict,
      status: verdictToStatus(c.verdict),
      // Attacker reachability class drives priority ranking (unauth > authed >
      // local). The hunter already establishes attacker capabilities per threat.
      ...(c.exposure ? { exposure: String(c.exposure) } : {}),
      // Actionable findings carry a concrete fix (agent's, else the CWE floor).
      ...(ACTIONABLE.has(verdictToStatus(c.verdict)) ? { remediation: String(c.remediation ?? "").trim() || remediationFor(meta.cwe) } : {}),
      evidence: (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
      rationale: String(c.rationale ?? ""),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : []
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "threat-hunt-finalize");
  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    candidateCount: draft.candidates.length,
    verdictCounts,
    threatHuntPath: store.threatHuntPath,
    findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("threat-hunt-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeThreatHunt(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
