#!/usr/bin/env node
// Initialize a fuzzing campaign plan from confirmed/proven findings. This does
// not claim execution evidence; it creates a deterministic, reviewable harness
// workspace and per-finding engine recommendation that /fuzz --stage replay can
// execute once a harness runCommand is present.

import { existsSync, mkdirSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { oracleSummaryForFinding } from "../lib/oracles.mjs";
import { SANITIZE_CFLAGS, SANITIZE_ENV, FUZZ_DRIVER, FUZZ_IMAGE, hasLibFuzzer, hasDockerLibFuzzer, detectToolchain } from "../lib/sanitizers.mjs";

// For native targets the find-by-execution oracle is sanitizers: build the harness with
// ASan/UBSan so a memory bug ABORTS during fuzzing (fuzz-triage reads the report → exact
// CWE). Two engines from one libFuzzer-API harness: coverage-guided libFuzzer when the
// runtime links here, else the portable ASan dumb-fuzz driver (works on Apple clang etc.).
function sanitizeFor(language) {
  if (language !== "c" && language !== "cpp") return null;
  const cc = detectToolchain().cc ?? "cc";
  if (hasLibFuzzer(cc)) {
    return {
      engine: "libfuzzer",
      cflags: `${SANITIZE_CFLAGS} -fsanitize=fuzzer`,
      env: SANITIZE_ENV,
      buildRunCommand: `${cc} ${SANITIZE_CFLAGS} -fsanitize=fuzzer harness.c -o fuzz && ./fuzz -max_total_time=60 corpus`,
      note: "coverage-guided libFuzzer; harness defines LLVMFuzzerTestOneInput. Memory bugs abort under ASan; fuzz-triage maps the report to a CWE."
    };
  }
  if (hasDockerLibFuzzer()) {
    return {
      engine: "libfuzzer-docker", coverageGuided: true, experimental: true, image: FUZZ_IMAGE,
      cflags: `${SANITIZE_CFLAGS} -fsanitize=fuzzer`, env: SANITIZE_ENV,
      buildRunCommand: `clang ${SANITIZE_CFLAGS} -fsanitize=fuzzer harness.c -o fuzz && ./fuzz -max_total_time=60 corpus`,
      note: `coverage-guided libFuzzer in the ${FUZZ_IMAGE} container (run via the docker sandbox backend). EXPERIMENTAL: coverage feedback depends on the image LLVM (the bundled ubuntu-clang-14 image linked + ran but showed cov:1/no-feedback on trivial harnesses in testing) — falls back to asan-dumbfuzz if coverage stays flat.`
    };
  }
  return {
    engine: "asan-dumbfuzz",
    cflags: SANITIZE_CFLAGS,
    env: SANITIZE_ENV,
    driver: FUZZ_DRIVER,
    buildRunCommand: `${cc} ${SANITIZE_CFLAGS} harness.c "${FUZZ_DRIVER}" -o fuzz && ./fuzz 500000 0 4096 corpus`,
    note: "libFuzzer runtime unavailable → portable ASan dumb-fuzz driver (same LLVMFuzzerTestOneInput harness). Random/mutation loop under ASan; weaker than coverage-guided but dependency-free."
  };
}

const MEMORY_CWES = new Set(["119","120","121","122","124","125","126","127","131","190","191","415","416","476","787","824"]);
const EXT_LANGUAGE = {
  ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
  ".java": "java", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust"
};

function cweNumber(cwe) {
  return String(Array.isArray(cwe) ? cwe[0] : (cwe ?? "")).replace(/^CWE-/i, "").trim();
}

function languageFor(filePath) {
  return EXT_LANGUAGE[extname(filePath ?? "").toLowerCase()] ?? "unknown";
}

function engineFor(language, cwe) {
  if (language === "c" || language === "cpp") return "libfuzzer";
  if (language === "java") return "jazzer";
  if (language === "javascript" || language === "typescript") return "node-property";
  if (language === "go") return "go-fuzz";
  if (language === "rust") return "cargo-fuzz";
  if (MEMORY_CWES.has(cweNumber(cwe))) return "libfuzzer";
  return "custom";
}

function defaultCommand(engine) {
  return {
    libfuzzer: "./fuzz_target -max_total_time=60 corpus",
    jazzer: "jazzer --cp target/classes --target_class FuzzTarget",
    "node-property": "npm test -- --runInBand fuzz",
    "go-fuzz": "go test ./... -run=^$ -fuzz=. -fuzztime=60s",
    "cargo-fuzz": "cargo fuzz run fuzz_target -- -max_total_time=60",
    custom: null
  }[engine] ?? null;
}

function excerptFor(target, anchor) {
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return null;
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  const start = Math.max(1, anchorLine - 15);
  const end = Math.min(lines.length, anchorLine + 15);
  return { filePath: anchor.filePath, startLine: anchorLine, lines: lines.slice(start - 1, end).map((text, i) => ({ line: start + i, text })) };
}

function seedable(finding) {
  return finding.status === "confirmed" || finding.status === "proven";
}

// Gate-clearing seeds for the fuzz corpus: concrete inputs already attached to the
// finding by the earlier phases — /path-solve's solved reaching input and /verify's PoC
// sketch payload (plus the negative PoC, whose STRUCTURE clears the same gates). Seeding
// the dumb-fuzzer with these lets mutation explore PAST a magic-byte/length gate instead
// of re-rolling it 1/256 per iteration — the floor-lifter for laptop-scale fuzzing.
function harvestSeeds(finding) {
  const out = [];
  const push = (name, v) => { const s = typeof v === "string" ? v : (v && typeof v === "object" ? JSON.stringify(v) : null); if (s && s.length) out.push({ name, content: s.slice(0, 8192) }); };
  push("pathsolve", finding.pathSolution?.solvedInput?.payload);
  push("pocsketch", finding.verification?.pocSketch?.payload);
  push("negative", finding.verification?.gateReview?.negativePoc);
  // dedup by content
  const seen = new Set();
  return out.filter((s) => (seen.has(s.content) ? false : (seen.add(s.content), true)))
    .map((s, i) => ({ name: `seed-${i}-${s.name}`, content: s.content }));
}

export function fuzzInit(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) throw new Error(`${store.findingsPath} not found — run /verify first`);

  const maxSeeds = Number(input.maxSeeds ?? 8);
  const seeds = (findingsDoc.findings ?? []).filter(seedable).slice(0, maxSeeds);
  mkdirSync(store.fuzzDir, { recursive: true });
  const run = openRun(resolvedTarget, "fuzz-init");
  const harnessRoot = join(store.fuzzDir, "harnesses");
  mkdirSync(harnessRoot, { recursive: true });

  const candidates = seeds.map((finding) => {
    const anchor = (finding.evidence ?? [])[0] ?? {};
    const language = languageFor(anchor.filePath);
    const engine = engineFor(language, finding.cwe);
    const harnessDir = join(harnessRoot, finding.fingerprint);
    mkdirSync(harnessDir, { recursive: true });
    // Seed the corpus from gate-clearing inputs the earlier phases already found.
    const corpusDir = join(harnessDir, "corpus");
    mkdirSync(corpusDir, { recursive: true });
    const corpusSeeds = harvestSeeds(finding);
    for (const s of corpusSeeds) writeFileSync(join(corpusDir, s.name), s.content);
    return {
      findingFingerprint: finding.fingerprint,
      title: finding.title,
      cwe: finding.cwe,
      severity: finding.severity,
      status: finding.status,
      evidence: finding.evidence ?? [],
      excerpt: excerptFor(resolvedTarget, anchor),
      language,
      engine,
      sanitize: sanitizeFor(language),
      harnessDir,
      runCommand: input.runCommand ?? defaultCommand(engine),
      corpusDir,
      seedCorpusCount: corpusSeeds.length,
      timeoutMs: Number(input.timeoutMs ?? 120000),
      semanticOracle: oracleSummaryForFinding(finding),
      notes: corpusSeeds.length
        ? `Seeded ${corpusSeeds.length} gate-clearing input(s) from path-solve/verify into corpus/; the dumb-fuzzer mutates from them. Review the harness, then /fuzz --stage replay.`
        : "No seed inputs on the finding (run /path-solve or /verify first to seed the corpus past shallow gates). Review/replace runCommand; /fuzz --stage replay executes candidates with a harness + runCommand."
    };
  });

  const doc = {
    version: "1.0",
    schemaVersion: "fuzz-plan.v1",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    runId: run.runId,
    candidates,
    summary: { seedCount: seeds.length, candidateCount: candidates.length }
  };
  atomicWrite(store.fuzzPlanPath, `${JSON.stringify(doc, null, 2)}\n`);
  run.writeJson("fuzz-plan.json", doc);
  const result = {
    ok: true,
    status: candidates.length ? "prepared" : "no-seeds",
    target: resolvedTarget,
    runId: run.runId,
    fuzzPlanPath: store.fuzzPlanPath,
    candidateCount: candidates.length,
    next: candidates.length ? "write or review harnesses, then run /fuzz --stage replay" : "run /verify first; fuzzing requires confirmed/proven seeds"
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-init --target <path> [--input '{\"maxSeeds\":8,\"timeoutMs\":120000}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("fuzz-init: --target is required");
    process.exit(1);
  }
  emitResult(fuzzInit(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
