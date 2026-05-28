// Shared findings index: .kuzushi/findings.json.
//
// This is the canonical contract downstream modules (verify, poc-builder,
// chain-finder) consume. Producers (threat-hunt today; invariant-test and others
// later) call upsertFindings() with normalized findings; this dedupes by a stable
// fingerprint and rewrites the index with a status/verdict summary.
//
// Finding shape:
//   { schemaVersion:"finding.v1", fingerprint, source, refId, title, severity,
//     cwe, verdict, status, proofState, evidence:[{filePath,startLine}],
//     rationale, nextChecks:[], updatedAt }

import { createHash } from "node:crypto";
import { mkdirSync, rmSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import { storeFor, atomicWrite, readJsonIfPresent } from "./artifact-store.mjs";
import { assertFindingsDocument } from "./schemas.mjs";

// Cross-process mutex around the read-modify-write of findings.json. /sweep fans
// producers out in parallel; without this, two finalizes racing on the same index
// would lose-update each other. mkdir is atomic on every real filesystem, so a
// lock *directory* is a portable mutex. We spin with a short synchronous sleep and
// take over a lock older than STALE_MS so a crashed holder can't wedge the index.
const LOCK_STALE_MS = 30_000;
const LOCK_TIMEOUT_MS = 15_000;

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function withFindingsLock(store, fn) {
  const lockDir = `${store.findingsPath}.lock`;
  // The store dir may not exist yet on a first write — the lock dir's parent must.
  mkdirSync(store.root, { recursive: true });
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (;;) {
    try {
      mkdirSync(lockDir);
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let age = 0;
      try { age = Date.now() - statSync(lockDir).mtimeMs; } catch { age = 0; }
      if (age > LOCK_STALE_MS) {
        try { rmSync(lockDir, { recursive: true, force: true }); continue; } catch { /* lost the race */ }
      }
      if (Date.now() > deadline) throw new Error(`findings lock timeout: ${lockDir} held >${LOCK_TIMEOUT_MS}ms`);
      sleepSync(25);
    }
  }
  try {
    return fn();
  } finally {
    try { rmSync(lockDir, { recursive: true, force: true }); } catch { /* already gone */ }
  }
}

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

// /fix patch verdicts → status. A patch is "validated" (PoC⁺: stops the exploit
// AND preserves function) → "patched". Other verdicts attach a `fix` block but
// do NOT transition status (the bug is unchanged until a real fix lands) — they
// map to null so fix-finalize leaves the existing status alone. A working-tree
// apply (fix-apply) advances "patched" → "remediated".
const FIX_STATUS = {
  validated: "patched"
};

export function fixVerdictToStatus(verdict) {
  return FIX_STATUS[verdict] ?? null;
}

export function proofStateFor(finding) {
  if (finding.status === "noise") return "noise";
  if (finding.status === "reviewed") return "reviewed";
  if (finding.status === "remediated") return "remediated";
  if (finding.status === "patched") return "patch-validated";
  if (finding.fix) return finding.fix.verdict === "validated" ? "patch-validated" : "patch-planned";
  if (finding.status === "proven" || finding.poc?.proofVerdict === "exploited") return "proven";
  if (finding.status === "confirmed" || finding.verification?.verdict === "confirmed-exploitable") return "confirmed";
  if (finding.verification?.pocReady || finding.verification?.pocSketch) return "trigger-built";
  if (finding.verification) return "reachable";
  if (finding.status === "open") return "open";
  if (finding.status === "lead") return "lead";
  return "candidate";
}

// Evidence filePaths should be relative to the target. Agents handed an absolute
// target dir sometimes echo absolute anchors (observed on a real run: 6/31
// threat-hunt findings had /Users/.../jadx_out/... paths), which leaks the local
// FS layout into findings.json / SARIF / chains and is inconsistent with the rest.
// When a target is known, relativize any absolute filePath that sits under it.
function relativizeFilePath(filePath, target) {
  if (!target || !filePath || !isAbsolute(filePath)) return filePath;
  const rel = relative(resolve(target), filePath);
  return rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel : filePath;
}

function normalizeEvidence(evidence, target) {
  return Array.isArray(evidence)
    ? evidence.map((a) => ({
        filePath: relativizeFilePath(String(a?.filePath ?? "."), target),
        ...(a?.startLine !== undefined ? { startLine: Math.max(1, Number(a.startLine) || 1) } : {}),
        ...(a?.endLine !== undefined ? { endLine: Math.max(1, Number(a.endLine) || 1) } : {})
      }))
    : [];
}

export function normalizeFinding(raw, now = new Date().toISOString(), target = null) {
  const status = raw.status ?? verdictToStatus(raw.verdict);
  const normalized = {
    ...raw,
    schemaVersion: raw.schemaVersion ?? "finding.v1",
    source: raw.source ? String(raw.source) : "unknown",
    refId: raw.refId ? String(raw.refId) : String(raw.fingerprint ?? "finding"),
    title: raw.title ? String(raw.title) : String(raw.refId ?? "Untitled finding"),
    severity: raw.severity ? String(raw.severity) : "medium",
    status,
    evidence: normalizeEvidence(raw.evidence, target),
    nextChecks: Array.isArray(raw.nextChecks) ? raw.nextChecks : [],
    updatedAt: raw.updatedAt ?? now
  };
  normalized.proofState = proofStateFor(normalized);
  return normalized;
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
  return withFindingsLock(store, () => {
    const existing = readJsonIfPresent(store.findingsPath);
    const byFp = new Map();
    for (const f of existing?.findings ?? []) {
      if (f.fingerprint) byFp.set(f.fingerprint, f);
    }
    const now = new Date().toISOString();
    for (const raw of newFindings) {
      // Relativize evidence BEFORE fingerprinting so the stable id is computed on
      // the relative path — otherwise the same bug emitted absolute on one run and
      // relative on another would dedupe-miss.
      const withRel = { ...raw, evidence: normalizeEvidence(raw.evidence, target), updatedAt: now };
      const fp = withRel.fingerprint ?? fingerprint(withRel);
      byFp.set(fp, normalizeFinding({ ...withRel, fingerprint: fp }, now, target));
    }
    const findings = [...byFp.values()].map((f) => normalizeFinding(f, now, target));
    const document = { version: "1.0", schemaVersion: "findings.v1", generatedAt: now, target, findings, summary: buildSummary(findings) };
    assertFindingsDocument(document);
    atomicWrite(store.findingsPath, `${JSON.stringify(document, null, 2)}\n`);
    return document;
  });
}

// Merge-aware update for downstream modules (verify, poc) that attach a result
// onto an *existing* finding rather than owning the whole record. Each patch is
// { fingerprint, ...fieldsToMerge } (e.g. { fingerprint, verification, status });
// fields are shallow-merged into the matching finding (latest wins), every other
// finding is left untouched. Throws if a patch names an unknown fingerprint so a
// stale/typo'd id surfaces loudly instead of silently no-op'ing. Returns the doc.
export function patchFindings(target, patches) {
  const store = storeFor(target);
  return withFindingsLock(store, () => {
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
      byFp.set(fp, normalizeFinding({ ...current, ...patch, fingerprint: fp, updatedAt: now }, now, target));
    }
    const findings = [...byFp.values()].map((f) => normalizeFinding(f, now, target));
    const document = { version: "1.0", schemaVersion: "findings.v1", generatedAt: now, target, findings, summary: buildSummary(findings) };
    assertFindingsDocument(document);
    atomicWrite(store.findingsPath, `${JSON.stringify(document, null, 2)}\n`);
    return document;
  });
}
