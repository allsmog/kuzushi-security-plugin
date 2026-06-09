#!/usr/bin/env node
// Finalize phase for /logic-hunt. Validates the logic-hunter's verdicts against a
// closed set, enforces the anti-rationalization gates (a "holds" must name the
// enforcement; a "violation" must carry a concrete break sequence + evidence),
// persists .kuzushi/logic-hunt.json, and promotes verdicts into findings.json
// (source "logic-hunt"). The verdict whitelist lives HERE, not in the prose, so
// it can't be reasoned around.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings } from "../lib/findings.mjs";

// Closed verdict set for logic hunting. Distinct from the taint triage set: a
// logic finding is about a property being violable, not a tainted flow.
const VALID_VERDICTS = new Set(["violation", "holds", "not-an-invariant", "needs-more-evidence"]);
const VALID_CLASSES = new Set(["atomicity", "ordering", "state-machine", "authz-omission", "business-rule", "replay", "invariant"]);
const MIN_RATIONALE_LENGTH = 200;

// verdict → finding status. Only a "violation" is actionable; "holds" /
// "not-an-invariant" are reviewed (the property is enforced or wasn't required);
// "needs-more-evidence" parks for follow-up.
const VERDICT_STATUS = {
  violation: "open",
  holds: "reviewed",
  "not-an-invariant": "reviewed",
  "needs-more-evidence": "needs-evidence"
};

function fail(message) {
  console.error(`logic-hunt-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.logicId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`item ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (c.logicClass && !VALID_CLASSES.has(c.logicClass)) {
      fail(`item ${id}: invalid logicClass "${c.logicClass}"; must be one of ${[...VALID_CLASSES].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`item ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). State the intended property, the operation sequence that breaks it, and what an attacker gains.`);
    }
    // Anti-rationalization gates, mirroring threat-hunt's "name the guard":
    if (c.verdict === "holds" && !/enforc|guard|check|lock|transaction|constraint|atomic|validate/i.test(rationale)) {
      fail(`item ${id}: verdict "holds" must name the concrete enforcement (the lock / constraint / check that makes the invariant unbreakable) in the rationale.`);
    }
    if (c.verdict === "violation") {
      if (!c.violationScenario || String(c.violationScenario).trim().length < 20) {
        fail(`item ${id}: verdict "violation" requires a concrete violationScenario — the ordered operations that break the property.`);
      }
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`item ${id}: verdict "violation" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`item ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
  }
}

export function finalizeLogicHunt(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.logic-hunt.json");
  if (!existsSync(draftPath)) fail(`no draft.logic-hunt.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.logic-hunt.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const logicHuntPath = join(store.root, "logic-hunt.json");
  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(logicHuntPath, json);
  atomicWrite(join(resolvedRunDir, "logic-hunt.json"), json);

  const newFindings = draft.candidates.map((c, i) => {
    const anchors = (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    return {
      source: "logic-hunt",
      refId: c.logicId ?? c.id ?? `${c.logicClass ?? "logic"}-${i + 1}`,
      title: c.title ?? `Logic flaw: ${c.logicClass ?? "invariant violation"}`,
      severity: c.severity ?? "medium",
      cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "CWE-840",
      verdict: c.verdict,
      status: VERDICT_STATUS[c.verdict],
      ...(c.exposure ? { exposure: String(c.exposure) } : {}),
      ...(c.logicClass ? { logicClass: c.logicClass } : {}),
      evidence: anchors.length ? anchors : [{ filePath: c.filePath ?? ".", startLine: c.line ?? 1 }],
      rationale: String(c.rationale ?? ""),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : []
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "logic-hunt-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, verdictCounts,
    logicHuntPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("logic-hunt-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeLogicHunt(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
