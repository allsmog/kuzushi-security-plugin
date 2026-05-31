#!/usr/bin/env node
// Prepare phase for the discovery-by-execution lane. Deterministic recon that hands the
// discoverer agent everything it needs to FIND memory bugs by running malformed inputs —
// with NO pre-existing finding required (the routing-independent gap-closer). It detects
// native source + a sanitizer-capable toolchain + a sandbox backend + the build system,
// and partitions the attacker-reachable surface into independent subsystem seeds (reusing
// attack-surface.mjs). It self-skips honestly with a structured status when the target
// can't support the lane — like the self-gating MCP, it reports the skip, never fails.
// Read-only + deterministic (same repo → same seeds).

import { existsSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult } from "../lib/artifact-store.mjs";
import { inventory } from "../lib/sharding.mjs";
import { detectToolchain, SANITIZE_CFLAGS, SANITIZE_ENV } from "../lib/sanitizers.mjs";
import { detectBackend } from "../lib/sandbox.mjs";
import { partitionAttackSurface } from "../lib/attack-surface.mjs";
import { classifyProgramKind, harnessStrategyFor, detectSanitizerBuild, dispatchVocabulary } from "../lib/dispatch.mjs";

const NATIVE_LANGS = new Set(["C", "C++", "Rust", "Objective-C"]);
const BUILD_FILES = ["Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "configure", "configure.ac", "Cargo.toml", "meson.build", "BUILD.bazel", "build.zig"];

function detectBuildSystem(target) {
  return BUILD_FILES.filter((f) => existsSync(join(target, f)));
}

function hasNativeSource(inv) {
  return Object.keys(inv.byLanguage ?? {}).some((l) => NATIVE_LANGS.has(l));
}

// Non-crash classes need an INVARIANT oracle, not a sanitizer. Detect targets a framework-owned
// oracle can drive — a JS/TS package's entry export is drivable by the prototype-pollution oracle
// (CWE-1321). General (any JS parser/merger/setter), and it means a JS target is no longer a hard
// "no-native-source" skip. (Python class-pollution / authz-differential oracles slot in here next.)
function detectOracleTargets(target, inv) {
  const out = [];
  const langs = Object.keys(inv.byLanguage ?? {});
  const pkgPath = join(target, "package.json");
  if ((langs.includes("JavaScript") || langs.includes("TypeScript")) && existsSync(pkgPath)) {
    let main = "index.js";
    try { main = JSON.parse(readFileSync(pkgPath, "utf8")).main || "index.js"; } catch { /* default */ }
    out.push({ oracle: "prototype-pollution", cwe: "CWE-1321", targetModule: main, inputShape: "auto", language: "javascript" });
  }
  return out;
}

export function prepareFuzzDiscover(target, input = {}) {
  const resolvedTarget = resolve(target);
  const inv = inventory(resolvedTarget);
  const toolchain = detectToolchain();
  const backend = detectBackend();
  const buildSystem = detectBuildSystem(resolvedTarget);

  // Seeds: the attacker-reachable surface, narrowed to subsystems that actually contain
  // native source (the discoverer drives C/C++/Rust under ASan/UBSan). Deterministic.
  const maxFilesPerShard = Number(input.maxFilesPerShard ?? 40);
  const maxSubsystems = Number(input.maxSubsystems ?? 15);
  const part = partitionAttackSurface(resolvedTarget, { maxFilesPerShard, maxSubsystems });
  const NATIVE_EXT = /\.(c|h|cc|cpp|cxx|hpp|hh|m|rs)$/i;
  const subsystems = part.subsystems
    .map((s) => ({ ...s, files: s.files.filter((f) => NATIVE_EXT.test(f)) }))
    .filter((s) => s.files.length);

  // The decisive additions (from the eval forensics): the agent retreated to a standalone
  // vendored leaf because building the whole project "looked hard" and nothing pinned it
  // to the real entry point. So: classify the program KIND (drives how to harness it),
  // name the project's OWN sanitizer build (amortize the expensive build once), and hand
  // over the dispatch VOCABULARY (the command/method grammar) so a daemon/CLI is driven
  // through its real protocol — reaching stateful bugs a leaf harness never can.
  const programKind = classifyProgramKind(resolvedTarget);
  const sanitizerBuild = detectSanitizerBuild(resolvedTarget);
  const vocabulary = (() => { try { return dispatchVocabulary(resolvedTarget, { cap: 220 }); } catch { return []; } })();
  // Non-crash classes: invariant oracles (a framework-owned check, not a sanitizer crash).
  const oracleTargets = detectOracleTargets(resolvedTarget, inv);

  // Honest self-skip ladder (mirrors sanitize-pov-prepare's structured status). A daemon/CLI
  // with a buildable project + a dispatch vocabulary is fuzzable through its real entry even
  // when no single file forms a tidy standalone subsystem; and a non-native target with an
  // invariant-oracle surface (e.g. a JS package) is in scope via that oracle. Neither counts as
  // no-target. The native toolchain is only required when there IS native source to build.
  const drivableEntry = (programKind.kind === "daemon" || programKind.kind === "cli") && Boolean(sanitizerBuild) && vocabulary.length > 0;
  let status = "prepared";
  if (!hasNativeSource(inv) && !oracleTargets.length) status = "no-native-source";
  else if (hasNativeSource(inv) && !toolchain.cc && !toolchain.rust) status = "no-toolchain";
  else if (!subsystems.length && !drivableEntry && !oracleTargets.length) status = "no-fuzzable-target";
  else if (backend.backend !== "docker" && backend.backend !== "local") status = "no-sandbox";

  const run = openRun(resolvedTarget, "fuzz-discover");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    status, toolchain, backend, buildSystem,
    programKind, harnessStrategy: harnessStrategyFor(programKind.kind), sanitizerBuild,
    vocabularyCount: vocabulary.length, vocabulary,
    oracleTargets,
    sanitizeCflags: SANITIZE_CFLAGS, sanitizeEnv: SANITIZE_ENV,
    subsystemCount: subsystems.length, subsystems, input
  });

  return {
    ok: true,
    status,
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.fuzz-discover.json"),
    subsystemCount: subsystems.length,
    programKind: programKind.kind,
    vocabularyCount: vocabulary.length,
    oracleTargets,
    sanitizerBuild: sanitizerBuild?.command ?? null,
    toolchain,
    backend: backend.backend,
    buildSystem,
    note: status === "prepared"
      ? `Spawn the fuzz-discoverer against prepPath. programKind=${programKind.kind}: ${harnessStrategyFor(programKind.kind)} Then run the assembleCommand.`
      : `discovery lane self-skipped: ${status}`,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "fuzz-discover-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('fuzz-discover-prepare --target <path> [--input \'{"maxSubsystems":15,"maxFilesPerShard":40}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) { console.error("fuzz-discover-prepare: --target is required"); process.exit(1); }
  emitResult(prepareFuzzDiscover(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
