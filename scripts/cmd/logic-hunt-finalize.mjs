#!/usr/bin/env node
// Finalize phase for /logic-hunt. Validates the business-logic verdicts (closed
// verdict + logicClass sets, rationale depth, evidence anchors, and — for a
// "rejected" verdict — proof that the protecting invariant was actually named),
// persists .kuzushi/logic-hunt.json, and promotes verdicts into findings.json
// (source "logic-hunt").

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const VALID_CLASSES = new Set(["idempotency", "toctou-race", "transaction-atomicity", "price-quantity", "state-machine"]);
const MIN_RATIONALE_LENGTH = 150;

// Default CWE per business-logic class. CWE-840 (Business Logic Errors) is the
// catch-all; the others map to the closest specific weakness.
const CLASS_CWE = {
  idempotency: "CWE-837",            // Improper Enforcement of a Single, Unique Action
  "toctou-race": "CWE-367",          // TOCTOU race condition
  "transaction-atomicity": "CWE-362", // Concurrent execution / improper synchronization
  "price-quantity": "CWE-840",       // Business logic errors
  "state-machine": "CWE-841"         // Improper enforcement of behavioral workflow
};

// A "rejected" verdict must name the invariant that actually protects the action,
// not just assert safety — the logic-hunt version of the Carlini doctrine.
const INVARIANT_RE = /idempoten|lock|mutex|transaction|atomic|for update|serializable|unique constraint|compare-and-swap|cas\b|ownership|tenant|limit|guard|invariant|check/i;

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
      fail(`item ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Name the multi-step sequence, the attacker's manipulation, and the missing/broken invariant.`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`item ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`item ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
    if (c.verdict === "rejected" && !INVARIANT_RE.test(rationale)) {
      fail(`item ${id}: verdict "rejected" must name the invariant (idempotency key, lock, transaction, ownership/limit check) that protects this action. If none exists, the verdict is wrong.`);
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

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.logicHuntPath, json);
  atomicWrite(join(resolvedRunDir, "logic-hunt.json"), json);

  const newFindings = draft.candidates.map((c, i) => ({
    source: "logic-hunt",
    refId: c.logicId ?? `${c.logicClass ?? "logic"}-${i + 1}`,
    title: c.title ?? `Business logic: ${c.logicClass ?? "issue"}`,
    severity: c.severity ?? "",
    cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? CLASS_CWE[c.logicClass] ?? "CWE-840",
    verdict: c.verdict,
    status: verdictToStatus(c.verdict),
    evidence: (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
    rationale: String(c.rationale ?? ""),
    nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : [],
    ...(c.logicClass ? { logicClass: c.logicClass } : {})
  }));
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "logic-hunt-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, verdictCounts,
    logicHuntPath: store.logicHuntPath, findingsPath: store.findingsPath, findingsSummary: findingsDoc.summary
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
