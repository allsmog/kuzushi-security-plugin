// Shared findings index: .kuzushi/findings.json.
//
// This is the canonical contract downstream modules (verify, poc-builder,
// chain-finder) consume. Producers (threat-hunt today; invariant-test and others
// later) call upsertFindings() with normalized findings; this dedupes by a stable
// fingerprint and rewrites the index with a status/verdict summary.
//
// Finding shape:
//   { fingerprint, source, refId, title, severity, cwe, verdict, status,
//     evidence:[{filePath,startLine}], rationale, nextChecks:[], updatedAt }

import { createHash } from "node:crypto";
import { storeFor, atomicWrite, readJsonIfPresent } from "./artifact-store.mjs";

// Closed verdict set (shared with threat-hunt-finalize) → finding status.
// taint-analysis adds the IRIS triage verdicts (finding/candidate/rejected).
const VERDICT_STATUS = {
  exploitable: "open",
  "reviewed-no-impact": "reviewed",
  "likely-library-noise": "noise",
  "needs-more-evidence": "needs-evidence",
  "needs-active-agent-trace": "needs-trace",
  // taint-analysis triage verdicts:
  finding: "open",
  candidate: "needs-evidence",
  rejected: "reviewed"
};

export function verdictToStatus(verdict) {
  return VERDICT_STATUS[verdict] ?? "needs-evidence";
}

// /verify proof verdicts → status. verify reasons about exploitability without
// running anything; "confirmed" means a concrete trigger was reconstructed.
const VERIFY_STATUS = {
  "confirmed-exploitable": "confirmed",
  "not-exploitable": "reviewed",
  inconclusive: "needs-trace"
};

// /poc empirical proof verdicts → status. "proven" means the harness actually
// triggered the bug in the sandbox.
const POC_STATUS = {
  exploited: "proven",
  "not-reproduced": "reviewed",
  "harness-failed-build": "needs-trace",
  timeout: "needs-trace",
  error: "needs-trace"
};

export function verifyVerdictToStatus(verdict) {
  return VERIFY_STATUS[verdict] ?? "needs-trace";
}

export function pocVerdictToStatus(verdict) {
  return POC_STATUS[verdict] ?? "needs-trace";
}

// Stable id for dedupe across runs: source + refId + the primary evidence anchor.
export function fingerprint(finding) {
  const anchor = finding.evidence?.[0];
  const key = [
    finding.source ?? "",
    finding.refId ?? "",
    anchor?.filePath ?? "",
    anchor?.startLine ?? ""
  ].join("|");
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

function buildSummary(findings) {
  const byStatus = {};
  const byVerdict = {};
  for (const f of findings) {
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
    if (f.verdict) byVerdict[f.verdict] = (byVerdict[f.verdict] ?? 0) + 1;
  }
  return { total: findings.length, byStatus, byVerdict };
}

// Merge `newFindings` into <target>/.kuzushi/findings.json, deduping by
// fingerprint (latest wins). Returns the written document.
export function upsertFindings(target, newFindings) {
  const store = storeFor(target);
  const existing = readJsonIfPresent(store.findingsPath);
  const byFp = new Map();
  for (const f of existing?.findings ?? []) {
    if (f.fingerprint) byFp.set(f.fingerprint, f);
  }
  const now = new Date().toISOString();
  for (const raw of newFindings) {
    const fp = raw.fingerprint ?? fingerprint(raw);
    byFp.set(fp, { ...raw, fingerprint: fp, updatedAt: now });
  }
  const findings = [...byFp.values()];
  const document = { version: "1.0", generatedAt: now, target, findings, summary: buildSummary(findings) };
  atomicWrite(store.findingsPath, `${JSON.stringify(document, null, 2)}\n`);
  return document;
}

// Merge-aware update for downstream modules (verify, poc) that attach a result
// onto an *existing* finding rather than owning the whole record. Each patch is
// { fingerprint, ...fieldsToMerge } (e.g. { fingerprint, verification, status });
// fields are shallow-merged into the matching finding (latest wins), every other
// finding is left untouched. Throws if a patch names an unknown fingerprint so a
// stale/typo'd id surfaces loudly instead of silently no-op'ing. Returns the doc.
export function patchFindings(target, patches) {
  const store = storeFor(target);
  const existing = readJsonIfPresent(store.findingsPath);
  if (!existing) throw new Error(`${store.findingsPath} not found — nothing to patch`);
  const byFp = new Map();
  for (const f of existing.findings ?? []) {
    if (f.fingerprint) byFp.set(f.fingerprint, f);
  }
  const now = new Date().toISOString();
  for (const patch of patches) {
    const fp = patch.fingerprint;
    const current = fp ? byFp.get(fp) : undefined;
    if (!current) throw new Error(`patchFindings: unknown fingerprint "${fp}"`);
    byFp.set(fp, { ...current, ...patch, fingerprint: fp, updatedAt: now });
  }
  const findings = [...byFp.values()];
  const document = { version: "1.0", generatedAt: now, target, findings, summary: buildSummary(findings) };
  atomicWrite(store.findingsPath, `${JSON.stringify(document, null, 2)}\n`);
  return document;
}
