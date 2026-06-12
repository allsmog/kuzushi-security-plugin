import { join } from "node:path";
import { atomicWrite, storeFor } from "./artifact-store.mjs";
import { enclosingExcerpt } from "./excerpt.mjs";
import { obligationId } from "./obligation-ledger.mjs";

function capExcerpt(lines, anchorLine, maxLines) {
  if (!Array.isArray(lines) || lines.length <= maxLines) {
    return { lines: lines ?? [], truncated: false };
  }
  const anchor = Number(anchorLine ?? lines[0]?.line ?? 1);
  const half = Math.floor(maxLines / 2);
  let startIdx = lines.findIndex((l) => Number(l.line) >= anchor - half);
  if (startIdx < 0) startIdx = 0;
  startIdx = Math.max(0, Math.min(startIdx, lines.length - maxLines));
  return { lines: lines.slice(startIdx, startIdx + maxLines), truncated: true };
}

function sliceFor(target, { id, lane, cls, filePath, line, source = null, maxLines }) {
  const excerpt = enclosingExcerpt(target, filePath, line) ?? [];
  const capped = capExcerpt(excerpt, line, maxLines);
  const startLine = capped.lines[0]?.line ?? line ?? null;
  const endLine = capped.lines[capped.lines.length - 1]?.line ?? line ?? null;
  return {
    id,
    lane,
    class: cls,
    target: { filePath, line: line ?? null },
    source,
    excerpt: {
      filePath,
      startLine,
      endLine,
      lineCount: capped.lines.length,
      truncated: capped.truncated,
      lines: capped.lines
    }
  };
}

export function buildObligationSlicesFromDeepScanPrep(prep, { maxLines = 80 } = {}) {
  const target = prep.target;
  const slices = [];
  let i = 0;
  for (const file of prep.files ?? []) {
    for (const o of file.obligations ?? []) {
      slices.push(sliceFor(target, {
        id: obligationId("file", i++, file.filePath, o.line, o.kind),
        lane: "file-read-budget",
        cls: o.kind,
        filePath: file.filePath,
        line: o.line,
        maxLines
      }));
    }
  }
  i = 0;
  for (const o of prep.obligationOverlay?.obligations ?? []) {
    slices.push(sliceFor(target, {
      id: obligationId("overlay", i++, o.filePath, o.line, o.kind),
      lane: "obligation-overlay",
      cls: o.kind,
      filePath: o.filePath,
      line: o.line,
      maxLines
    }));
  }
  i = 0;
  for (const lead of prep.cpgLeads ?? []) {
    slices.push(sliceFor(target, {
      id: obligationId("cpg", i++, lead.filePath, lead.sinkLine, lead.cwe),
      lane: "scoped-cpg",
      cls: lead.cwe ?? "memory-dataflow",
      filePath: lead.filePath,
      line: lead.sinkLine,
      source: lead.sourceLine == null ? null : { filePath: lead.filePath, line: lead.sourceLine },
      maxLines
    }));
  }

  return {
    schemaVersion: "obligation-slices.v1",
    generatedAt: new Date().toISOString(),
    runId: prep.runId ?? null,
    target,
    maxLines,
    sliceCount: slices.length,
    slices
  };
}

export function writeObligationSlices(target, runDir, runId, slicesDoc) {
  const store = storeFor(target);
  const globalPath = join(store.slicesDir, `${runId}-obligation-slices.json`);
  const runPath = join(runDir, "obligation-slices.json");
  const json = `${JSON.stringify(slicesDoc, null, 2)}\n`;
  atomicWrite(globalPath, json);
  atomicWrite(runPath, json);
  return { globalPath, runPath, sliceCount: slicesDoc.sliceCount ?? 0 };
}
