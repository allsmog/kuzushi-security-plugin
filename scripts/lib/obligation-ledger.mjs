import { readFileSync } from "node:fs";
import { atomicWrite, storeFor } from "./artifact-store.mjs";

export function obligationId(prefix, index, filePath, line, kind) {
  const safeKind = String(kind ?? "unknown").replace(/[^a-zA-Z0-9_.-]+/g, "-");
  return `${prefix}:${String(index + 1).padStart(4, "0")}:${filePath}:${line ?? "?"}:${safeKind}`;
}

function fromFileBudget(prep) {
  const out = [];
  let i = 0;
  for (const file of prep.files ?? []) {
    for (const o of file.obligations ?? []) {
      out.push({
        id: obligationId("file", i++, file.filePath, o.line, o.kind),
        lane: "file-read-budget",
        status: "routed",
        class: o.kind,
        target: { filePath: file.filePath, line: o.line },
        obligation: o.obligation,
        text: o.text ?? null,
        reason: "included in deep-scan file budget"
      });
    }
  }
  return out;
}

function fromOverlay(prep) {
  const out = [];
  let i = 0;
  for (const o of prep.obligationOverlay?.obligations ?? []) {
    out.push({
      id: obligationId("overlay", i++, o.filePath, o.line, o.kind),
      lane: "obligation-overlay",
      status: "routed",
      class: o.kind,
      target: { filePath: o.filePath, line: o.line },
      obligation: o.obligation,
      text: o.text ?? null,
      priority: o.priority ?? null,
      reasons: Array.isArray(o.reasons) ? o.reasons : [],
      reason: "included in long-tail obligation overlay"
    });
  }
  return out;
}

function fromCpgLeads(prep) {
  return (prep.cpgLeads ?? []).map((lead, i) => ({
    id: obligationId("cpg", i, lead.filePath, lead.sinkLine, lead.cwe),
    lane: "scoped-cpg",
    status: "routed",
    class: lead.cwe ?? "memory-dataflow",
    target: { filePath: lead.filePath, line: lead.sinkLine ?? null },
    source: lead.sourceLine == null ? null : { filePath: lead.filePath, line: lead.sourceLine },
    scopeDir: lead.scopeDir ?? null,
    obligation: "discharge scoped CPG memory/dataflow lead",
    reason: "included as scoped CPG lead"
  }));
}

export function buildObligationLedgerFromDeepScanPrep(prep, { generatedAt = new Date().toISOString() } = {}) {
  const records = [...fromFileBudget(prep), ...fromOverlay(prep), ...fromCpgLeads(prep)];
  const overlay = prep.obligationOverlay ?? null;
  const deferredCount = Number(overlay?.unbudgeted ?? 0);
  const states = records.reduce((acc, r) => {
    acc[r.status] = (acc[r.status] ?? 0) + 1;
    return acc;
  }, {});
  if (deferredCount) states.deferred = (states.deferred ?? 0) + deferredCount;

  return {
    schemaVersion: "obligation-ledger.v1",
    generatedAt,
    runId: prep.runId ?? null,
    target: prep.target ?? null,
    source: "deep-scan-prepare",
    summary: {
      fileBudgetRecords: records.filter((r) => r.lane === "file-read-budget").length,
      overlayRecords: records.filter((r) => r.lane === "obligation-overlay").length,
      cpgLeadRecords: records.filter((r) => r.lane === "scoped-cpg").length,
      routedRecords: records.filter((r) => r.status === "routed").length,
      deferredRecords: deferredCount,
      unreadFiles: Number(prep.unreadCount ?? 0),
      overlayTotalSites: overlay?.totalSites ?? null,
      overlayUnbudgeted: overlay?.unbudgeted ?? null,
      terminalStates: states
    },
    records,
    deferred: deferredCount ? [{
      lane: "obligation-overlay",
      status: "deferred",
      count: deferredCount,
      reason: "outside maxObligations budget"
    }] : []
  };
}

export function writeObligationLedger(target, ledger) {
  const store = storeFor(target);
  const jsonl = [
    ...ledger.records,
    ...ledger.deferred
  ].map((r) => JSON.stringify(r)).join("\n");
  atomicWrite(store.obligationLedgerPath, `${JSON.stringify(ledger, null, 2)}\n`);
  atomicWrite(store.obligationsJsonlPath, jsonl ? `${jsonl}\n` : "");
  return {
    ledgerPath: store.obligationLedgerPath,
    jsonlPath: store.obligationsJsonlPath,
    recordCount: ledger.records.length,
    deferredCount: ledger.summary.deferredRecords
  };
}

export function writeObligationLedgerFromPrepPath(target, prepPath, options = {}) {
  const prep = JSON.parse(readFileSync(prepPath, "utf8"));
  const ledger = buildObligationLedgerFromDeepScanPrep(prep, options);
  return writeObligationLedger(target, ledger);
}
