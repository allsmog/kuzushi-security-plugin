import { existsSync, readFileSync } from "node:fs";
import { atomicWrite, storeFor } from "./artifact-store.mjs";

export function appendDroppedCandidates(target, records, { source = null, runDir = null, generatedAt = new Date().toISOString() } = {}) {
  const normalized = (records ?? []).filter(Boolean).map((record, i) => ({
    schemaVersion: "dropped-candidate.v1",
    generatedAt,
    source: record.source ?? source ?? "unknown",
    stage: record.stage ?? null,
    runDir,
    id: record.id ?? record.candidateId ?? `drop-${i + 1}`,
    status: record.status ?? "dropped",
    verdict: record.verdict ?? record.candidateVerdict ?? null,
    proofVerdict: record.proofVerdict ?? null,
    proofLevel: record.proofLevel ?? null,
    reason: record.reason ?? record.gate ?? null,
    exclusionRule: record.exclusionRule ?? null,
    refuteReason: record.refuteReason ?? null,
    title: record.title ?? null
  }));
  if (!normalized.length) {
    return { path: storeFor(target).droppedCandidatesPath, appended: 0 };
  }

  const path = storeFor(target).droppedCandidatesPath;
  const existing = existsSync(path) ? readFileSync(path, "utf8").trimEnd() : "";
  const added = normalized.map((r) => JSON.stringify(r)).join("\n");
  atomicWrite(path, `${existing ? `${existing}\n` : ""}${added}\n`);
  return { path, appended: normalized.length };
}
