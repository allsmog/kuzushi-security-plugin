#!/usr/bin/env node
// Prepare phase for /binary-recon (read-only static binary triage). Source-only
// review never opens the shipped artifacts; this detects ELF/PE/Mach-O by magic
// bytes and gathers read-only signals (dangerous imported symbols, writable+
// executable segments) via whatever binutils are on PATH, so the binary-recon
// agent can judge which signals matter and tie them back to source. Assessment
// only — no execution, no exploit-oriented disassembly.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { findBinaries, triageBinary } from "../lib/binaries.mjs";

export function prepareBinaryRecon(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxBinaries = Number(input.maxBinaries ?? 40);
  const binaries = findBinaries(resolvedTarget, { limit: maxBinaries });

  const candidates = binaries.map((b, i) => {
    const triage = triageBinary(resolvedTarget, b.path);
    return {
      id: `binrec-${i + 1}`,
      filePath: b.path,
      format: b.format,
      bytes: b.bytes,
      analyzed: triage.analyzed,
      toolsUsed: triage.toolsUsed,
      signals: triage.signals
    };
  });

  const run = openRun(resolvedTarget, "binary-recon");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    references: artifactSnapshot(resolvedTarget),
    binaryCount: binaries.length,
    candidateCount: candidates.length, candidates, input
  });

  return {
    ok: true,
    status: candidates.length ? "prepared" : "no-candidates",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.binary-recon.json"),
    candidateCount: candidates.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "binary-recon-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("binary-recon-prepare --target <path> [--input '{\"maxBinaries\":40}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("binary-recon-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareBinaryRecon(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
