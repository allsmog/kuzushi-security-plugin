// Framework-owned runner for the portable coverage-guided engine (cov-fuzz.c). The finalize copies
// this + cov-fuzz.c into the harness dir, writes the agent-declared entry harness as harness.c, and
// runs `node coverage-fuzz.mjs config.json` in the sandbox. This script compiles the engine + harness
// + the target's own sources under ASan + trace-pc-guard, seeds from the target's bundled corpus, runs
// the time-boxed search, and re-emits the sanitizer report to stdout — where the finalize's
// parseSanitizerReport (the ONLY verdict) reads it. This script owns build+run, never the verdict.
//
// config.json: {
//   repo, cc?, compileSources[ (paths rel to repo) ], includeDirs[], extraCflags[], libs[],
//   harnessFile (default "harness.c"), seeds[ (inline strings) ]?, seedDir?, secs?, runSeed?, sanitizeEnv?
// }
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, copyFileSync } from "node:fs";
import { resolve, join } from "node:path";

function log(s) { process.stdout.write(String(s) + "\n"); }

function main() {
  const cfgPath = process.argv[2];
  if (!cfgPath) { log("BUILD-FAILED: no config"); process.exit(0); }
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  const here = process.cwd();                                   // the harness dir (cov-fuzz.c + harness.c live here)
  const repo = resolve(cfg.repo);
  const cc = cfg.cc || "clang";
  const harnessFile = cfg.harnessFile || "harness.c";
  const secs = Math.max(1, Math.min(900, cfg.secs ?? 60));
  const runSeed = String(cfg.runSeed ?? 1);

  // --- assemble the seed corpus dir (the target's own grammar; never a hand-written trigger) ---
  const seedDir = join(here, "seeds");
  mkdirSync(seedDir, { recursive: true });
  let nseed = 0;
  if (cfg.seedDir && existsSync(resolve(cfg.seedDir))) {
    for (const f of readdirSync(resolve(cfg.seedDir)).slice(0, 200)) {
      try { copyFileSync(join(resolve(cfg.seedDir), f), join(seedDir, `s_${nseed}`)); nseed++; } catch {}
    }
  }
  for (const s of cfg.seeds ?? []) { try { writeFileSync(join(seedDir, `s_${nseed}`), String(s)); nseed++; } catch {} }
  log(`[coverage-fuzz] seeds=${nseed}`);

  // --- compile: engine + harness + the target's own sources, under ASan + trace-pc-guard ---
  const srcs = (cfg.compileSources ?? []).map((s) => resolve(repo, s));
  const incs = (cfg.includeDirs ?? []).map((d) => `-I${resolve(repo, d)}`);
  const args = [
    "-O1", "-g", "-fsanitize=address", "-fsanitize-coverage=trace-pc-guard",
    "-Wno-implicit-function-declaration", "-Wno-deprecated-declarations",
    ...incs, ...(cfg.extraCflags ?? []),
    join(here, "cov-fuzz.c"), join(here, harnessFile), ...srcs,
    ...(cfg.libs ?? ["-lm"]), "-o", join(here, "fuzzer"),
  ];
  try {
    execFileSync(cc, args, { cwd: here, stdio: ["ignore", "pipe", "pipe"], timeout: 300000 });
  } catch (e) {
    // A build failure must never read as a clean (safe) run — surface it explicitly; parseSanitizerReport
    // returns null on this, so nothing is promoted. (No sanitizer text == not proven == correct.)
    log("BUILD-FAILED: coverage-fuzz harness did not compile");
    log(String(e.stderr || e.stdout || e.message).slice(0, 2000));
    process.exit(0);
  }

  // --- run the time-boxed coverage-guided search; re-emit its output (the ASan report on a crash) ---
  const env = { ...process.env, ...(cfg.sanitizeEnv || {}) };
  if (!env.ASAN_OPTIONS) env.ASAN_OPTIONS = "abort_on_error=0:halt_on_error=1:detect_leaks=0:allocator_may_return_null=1";
  const r = spawnSync(join(here, "fuzzer"), [String(secs), seedDir, runSeed],
    { cwd: here, env, encoding: "utf8", timeout: (secs + 60) * 1000, maxBuffer: 64 * 1024 * 1024 });
  const out = `${r.stdout || ""}\n${r.stderr || ""}`;
  log(out);                                  // the sanitizer report (if any) flows to the finalize's parser
  if (existsSync(join(here, "crash-input"))) log(`[coverage-fuzz] crash-input dumped (reproducible @ runSeed=${runSeed})`);
}

main();
