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
import { severityFieldsFor } from "../lib/severity.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const MIN_RATIONALE_LENGTH = 150;

function fail(message) {
  console.error(`deep-scan-finalize: ${message}`);
  process.exit(1);
}

// Why an item is invalid, or null if it passes. The trust gates are unchanged (verdict
// whitelist, min-rationale depth, finding requires anchors/cwe/selfCheck) — what changed is
// the BLAST RADIUS: a bad item is DROPPED, not fatal to the whole draft. A real agent draft
// is a batch of 19 candidates; one item with a 136-char rationale used to discard the other
// 18 (including a legit CWE-787 finding). Dropping the offending item keeps the trust
// boundary intact (an invalid item still never promotes) while not losing the good ones.
function invalidReason(c) {
  if (!VALID_VERDICTS.has(c.verdict)) return `invalid verdict "${c.verdict}" (must be ${[...VALID_VERDICTS].join("/")})`;
  const rationale = String(c.rationale ?? "");
  if (rationale.length < MIN_RATIONALE_LENGTH) return `rationale ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH})`;
  if (c.verdict === "finding") {
    const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
    if (!anchors.length) return `finding requires an evidenceAnchor { filePath, startLine }`;
    for (const a of anchors) {
      if (!a.filePath || a.startLine === undefined) return `evidenceAnchor must be { filePath, startLine }`;
    }
    if (!c.cwe) return `finding requires a cwe`;
    if (String(c.selfCheck ?? "").length < 40) return `finding requires a selfCheck (≥40 chars)`;
  }
  return null;
}

// Partition into promotable + dropped (with reasons), so one malformed item can't sink the batch.
function partition(candidates) {
  const valid = [];
  const dropped = [];
  for (const c of candidates) {
    const reason = invalidReason(c);
    if (reason) dropped.push({ id: c.deepId ?? c.id ?? "(unknown)", verdict: c.verdict, reason });
    else valid.push(c);
  }
  return { valid, dropped };
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

  // Drop malformed items; promote the valid ones. (Structural problems above — no draft, bad
  // JSON, no candidates array — remain fatal; only PER-ITEM validation is now non-fatal.)
  const { valid, dropped } = partition(draft.candidates);
  if (dropped.length) {
    for (const d of dropped) console.error(`deep-scan-finalize: dropped item ${d.id} (${d.verdict}): ${d.reason}`);
  }

  const persisted = { ...draft, candidates: valid, droppedCandidates: dropped };
  const json = `${JSON.stringify(persisted, null, 2)}\n`;
  atomicWrite(store.deepScanPath, json);
  atomicWrite(join(resolvedRunDir, "deep-scan.json"), json);

  const newFindings = valid.map((c, i) => ({
    source: "deep-scan",
    refId: c.deepId ?? `deep-${i + 1}`,
    title: c.title ?? `Deep-read finding ${i + 1}`,
    ...severityFieldsFor(c),
    cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
    verdict: c.verdict,
    status: verdictToStatus(c.verdict),
    evidence: (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
    rationale: String(c.rationale ?? ""),
    nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : ["/verify (panel) this deep-read lead before treating it as confirmed"],
    ...(c.bugClass ? { bugClass: c.bugClass } : {}),
    ...(c.selfCheck ? { selfCheck: String(c.selfCheck) } : {})
  }));
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = valid.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "deep-scan-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, promotedCount: valid.length, droppedCount: dropped.length,
    dropped, verdictCounts,
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
