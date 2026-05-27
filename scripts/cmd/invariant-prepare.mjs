#!/usr/bin/env node
// Prepare an invariant-test run: read the invariants from .kuzushi/threat-intel.json,
// ripgrep candidate files per invariant (using its source/sink signals scoped to its
// languages), open a run, and emit a worklist for the invariant-tester agent.

import { resolve, join } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { runRg } from "../lib/ripgrep.mjs";

// Detected-language display name → ripgrep include globs.
const LANG_GLOBS = {
  Java: ["*.java"], Kotlin: ["*.kt", "*.kts"], JavaScript: ["*.js", "*.jsx", "*.mjs", "*.cjs"],
  TypeScript: ["*.ts", "*.tsx"], Python: ["*.py"], Go: ["*.go"], Ruby: ["*.rb", "*.erb"],
  Rust: ["*.rs"], C: ["*.c", "*.h"], "C++": ["*.cc", "*.cpp", "*.hpp"], PHP: ["*.php"], Scala: ["*.scala"]
};

function globsFor(languages) {
  const globs = (languages ?? []).flatMap((l) => LANG_GLOBS[l] ?? []);
  return globs.length ? globs : Object.values(LANG_GLOBS).flat();
}

// Files containing any of the invariant's signals (fixed-string match), scoped to
// its languages. Capped so the agent gets a bounded worklist.
function candidateFiles(target, invariant, limit = 25) {
  const signals = [...(invariant.sinkSignals ?? []), ...(invariant.sourceSignals ?? [])].filter(Boolean);
  if (!signals.length) return [];
  const args = ["-l", "-F"];
  for (const sig of signals) args.push("-e", sig);
  for (const glob of globsFor(invariant.languages)) args.push("-g", glob);
  args.push("-g", "!**/.kuzushi/**", "-g", "!**/node_modules/**", ".");
  const result = runRg(target, args);
  if (!result.ok) return [];
  return result.stdout.split(/\r?\n/).filter(Boolean).slice(0, limit);
}

export function prepareInvariantTest(target) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const intel = readJsonIfPresent(store.threatIntelPath);
  if (!intel) {
    throw new Error(`no .kuzushi/threat-intel.json — run /threat-intel first`);
  }
  const invariants = Array.isArray(intel.invariants) ? intel.invariants : [];
  const run = openRun(resolvedTarget, "invariant-test");

  const worklist = invariants.map((inv) => ({
    invariantId: inv.id,
    statement: inv.statement,
    cwe: inv.cwe,
    severity: inv.severity,
    languages: inv.languages ?? [],
    sourceSignals: inv.sourceSignals ?? [],
    sinkSignals: inv.sinkSignals ?? [],
    sanitizerSignals: inv.sanitizerSignals ?? [],
    taintClass: inv.taintClass ?? "",
    checkHint: inv.checkHint ?? "",
    candidateFiles: candidateFiles(resolvedTarget, inv)
  }));

  return {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    invariantCount: worklist.length,
    resultsStageFile: join(run.runDir, "invariant-findings.json"),
    worklist,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "invariant-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("invariant-prepare --target <path>: build a per-invariant worklist (candidate files) from threat-intel.json.");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target"] });
  if (!flags.target) {
    console.error("invariant-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareInvariantTest(flags.target));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
