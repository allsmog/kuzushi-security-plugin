#!/usr/bin/env node
// Prepare phase for /sanitize-pov — prove a memory finding by RUNNING it under
// AddressSanitizer/UBSan (the AIxCC "find-by-execution" core). Static reading misses
// subtle memory bugs; a sanitizer abort is ground truth. This gathers the finding, the
// suspect function, the build system, and the toolchain, and hands the author agent
// everything it needs to write a harness that drives the bug. Deterministic, read-only.

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { enclosingExcerpt } from "../lib/excerpt.mjs";
import { detectToolchain, SANITIZE_CFLAGS, SANITIZE_ENV, isMemoryFinding } from "../lib/sanitizers.mjs";
import { detectBackend } from "../lib/sandbox.mjs";

// Memory-class detection is shared (scripts/lib/sanitizers.mjs) so sanitize-pov,
// mem-exploitability, and the verify proof-lane router all key off one set.

const BUILD_FILES = ["Makefile", "makefile", "CMakeLists.txt", "configure", "configure.ac", "Cargo.toml", "meson.build", "BUILD.bazel", "build.zig"];
function detectBuildSystem(target) {
  return BUILD_FILES.filter((f) => existsSync(join(target, f)));
}

export function prepareSanitizePov(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) throw new Error(`${store.findingsPath} not found — run a hunt (e.g. /sweep) first`);

  const all = findingsDoc.findings ?? [];
  const want = input.findingFingerprint;
  // Target: a specific finding, else the memory-class findings not yet proven.
  const candidates = (want ? all.filter((f) => f.fingerprint === want) : all.filter(isMemoryFinding))
    .filter((f) => f.poc?.proofVerdict !== "exploited")
    .slice(0, Number(input.maxFindings ?? 6))
    .map((f) => {
      const anchor = (f.evidence ?? [])[0] ?? {};
      return {
        findingFingerprint: f.fingerprint,
        title: f.title, cwe: f.cwe, source: f.source,
        evidence: f.evidence ?? [],
        rationale: f.rationale,
        suspect: anchor.filePath ? { filePath: anchor.filePath, startLine: anchor.startLine, function: enclosingExcerpt(resolvedTarget, anchor.filePath, anchor.startLine) ?? [] } : null
      };
    });

  const toolchain = detectToolchain();
  const backend = detectBackend();
  const buildSystem = detectBuildSystem(resolvedTarget);

  const run = openRun(resolvedTarget, "sanitize-pov");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    toolchain, backend, buildSystem,
    sanitizeCflags: SANITIZE_CFLAGS, sanitizeEnv: SANITIZE_ENV,
    candidateCount: candidates.length, candidates, input
  });

  const status = !candidates.length ? "no-findings" : (!toolchain.cc && !toolchain.rust ? "no-toolchain" : "prepared");
  return {
    ok: true,
    status,
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.sanitize-pov.json"),
    candidateCount: candidates.length,
    toolchain,
    backend: backend.backend,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "sanitize-pov-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('sanitize-pov-prepare --target <path> [--input \'{"findingFingerprint":"...","maxFindings":6}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) { console.error("sanitize-pov-prepare: --target is required"); process.exit(1); }
  emitResult(prepareSanitizePov(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
