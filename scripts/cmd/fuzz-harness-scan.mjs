#!/usr/bin/env node
// Detect EXISTING fuzz harnesses (and OSS-Fuzz build glue) already in a repo, so
// /fuzz can reuse a maintained harness instead of authoring one from scratch.
// Read-only, deterministic; prints JSON to stdout. Used by the fuzz-harness-author
// agent (step 0) before it decides to author.

import { resolve, extname } from "node:path";
import { existsSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { runRg, parseJsonMatches, buildGlobs, listFiles } from "../lib/ripgrep.mjs";

const EXT_LANG = { ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
  ".rs": "rust", ".go": "go", ".java": "java", ".js": "javascript", ".mjs": "javascript",
  ".ts": "typescript", ".py": "python" };

// Content signals: a regex that marks a real harness entry point, mapped to the
// engine it implies + a build hint the agent can turn into a runCommand.
const SIGNALS = [
  { engine: "libfuzzer", re: "LLVMFuzzerTestOneInput",
    buildHint: "clang -g -fsanitize=address,fuzzer <this-file> <target-srcs> -o fuzz_target && ./fuzz_target -max_total_time=60 corpus" },
  { engine: "cargo-fuzz", re: "fuzz_target!\\s*\\(",
    buildHint: "cargo fuzz run <target> -- -max_total_time=60   (target name = the fuzz_targets/*.rs file stem)" },
  { engine: "go-fuzz", re: "func\\s+Fuzz\\w*\\s*\\(\\s*\\w+\\s+\\*testing\\.F",
    buildHint: "go test <pkg> -run=^$ -fuzz=^<FuzzFuncName>$ -fuzztime=60s" },
  { engine: "jazzer", re: "fuzzerTestOneInput|FuzzedDataProvider|@FuzzTest",
    buildHint: "jazzer --cp <classpath> --target_class <FuzzClass>" },
  { engine: "node-property", re: "@jazzer\\.js/core|require\\(['\"]@jazzer",
    buildHint: "npx jazzer <this-file>" }
];

export function scanHarnesses(target) {
  const resolvedTarget = resolve(target);
  const globs = buildGlobs();
  const byPath = new Map();
  for (const sig of SIGNALS) {
    const r = runRg(resolvedTarget, ["--json", "-n", "--max-count", "3", "-e", sig.re, ...globs, "."]);
    if (!r.ok) continue;
    for (const hit of parseJsonMatches(r.stdout, 100)) {
      if (!hit.filePath) continue;
      const language = EXT_LANG[extname(hit.filePath).toLowerCase()] ?? "unknown";
      // First signal to claim a path wins; keep the highest-signal hit per file.
      if (byPath.has(hit.filePath)) continue;
      byPath.set(hit.filePath, {
        engine: sig.engine, language, harnessPath: hit.filePath, line: hit.line,
        buildHint: sig.buildHint, signal: sig.re
      });
    }
  }

  // OSS-Fuzz layout signal: a build.sh and/or a projects/*/ tree raises confidence
  // and usually means a maintained build is available.
  const buildFiles = listFiles(resolvedTarget, { includeGlobs: ["build.sh", "**/build.sh", "fuzz/Cargo.toml"] }).slice(0, 20);
  const ossFuzz = buildFiles.some((f) => /(^|\/)build\.sh$/.test(f)) || existsSync(resolve(resolvedTarget, "projects"));

  const harnesses = [...byPath.values()].map((h) => ({
    ...h,
    // high = harness fn + a build file present; medium = harness fn only.
    confidence: ossFuzz || h.engine === "cargo-fuzz" ? "high" : "medium"
  }));

  return {
    ok: true,
    target: resolvedTarget,
    ossFuzz,
    buildFiles,
    harnessCount: harnesses.length,
    harnesses
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-harness-scan --target <path>: detect existing in-repo / OSS-Fuzz harnesses (JSON to stdout)");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target"] });
  if (!flags.target) {
    console.error("fuzz-harness-scan: --target is required");
    process.exit(1);
  }
  process.stdout.write(`${JSON.stringify(scanHarnesses(flags.target), null, 2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
