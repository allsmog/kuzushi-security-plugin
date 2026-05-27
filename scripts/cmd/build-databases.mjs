#!/usr/bin/env node
// Build the heavy semantic indexes the codeql/joern MCP backends query:
//   - joern CPG  → <target>/.kuzushi/joern/cpg.bin.zip   (language-agnostic)
//   - codeql DB  → <target>/.kuzushi/codeql-db/<lang>     (per detected language)
//
//   node build-databases.mjs --target <repo> [--which codeql|joern|both]
//        [--include-install] [--background] [--force]
//
// These are slow (minutes → tens of minutes). Use --background to spawn the work
// detached (the launching call returns immediately; output → .kuzushi/db-build.log).
// Language-gated, idempotent, best-effort: a failure on one tool/language doesn't
// abort the rest. --include-install vendors a missing CLI first (~1–3 GB).
//
// All tool/progress output is appended to .kuzushi/db-build.log; only the result
// envelope is written to stdout (so callers can parse it).

import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync, appendFileSync, openSync, realpathSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { commandInstalled } from "../lib/capabilities.mjs";

const SELF = fileURLToPath(import.meta.url);
const INSTALL_TOOLING = join(dirname(SELF), "install-tooling.mjs");

const CODEQL_LANG = {
  Go: "go", Java: "java", Kotlin: "java", JavaScript: "javascript", TypeScript: "javascript",
  Python: "python", Ruby: "ruby", C: "cpp", "C++": "cpp"
};
const BUILD_MODE_NONE = new Set(["java", "csharp"]); // buildless extraction support

function logPathFor(store) {
  return join(store.root, "db-build.log");
}

function log(store, line) {
  try {
    mkdirSync(store.root, { recursive: true });
    appendFileSync(logPathFor(store), `[${new Date().toISOString()}] ${line}\n`);
  } catch {}
}

function which(cmd) {
  const r = spawnSync("which", [cmd], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

// joern's jssrc2cpg frontend needs a version-matched `astgen`. Some installs
// (e.g. Homebrew) look in the wrong dir and ship a usable copy under the
// frontend bundle; a PATH `astgen` is often a mismatched version. Resolve the
// bundled, version-matched binary from the joern install and hand it to
// joern-parse via ASTGEN_BIN. Returns null if none found (caller proceeds).
function resolveAstgen() {
  if (process.env.ASTGEN_BIN && existsSync(process.env.ASTGEN_BIN)) return process.env.ASTGEN_BIN;
  const jp = which("joern-parse") ?? which("joern");
  if (!jp) return null;
  let real = jp;
  try { real = realpathSync(jp); } catch {}
  const prefix = resolve(dirname(real), ".."); // <root>/bin/joern-parse → <root>
  const rel = join("frontends", "jssrc2cpg", "bin", "astgen");
  for (const dir of [join(prefix, "libexec", rel), join(prefix, rel), join(prefix, "joern-cli", rel)]) {
    if (!existsSync(dir)) continue;
    try {
      const bin = readdirSync(dir).find((f) => f.startsWith("astgen") && !f.endsWith(".json"));
      if (bin) return join(dir, bin);
    } catch {}
  }
  return null;
}

// Run a command, append its output to db-build.log, return the exit status.
function runLogged(store, command, args, env = process.env) {
  log(store, `$ ${command} ${args.join(" ")}`);
  const r = spawnSync(command, args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, env });
  if (r.stdout) log(store, r.stdout.slice(-8000));
  if (r.stderr) log(store, r.stderr.slice(-8000));
  if (r.error) log(store, `spawn error: ${r.error.message}`);
  return r.status;
}

function detectedLanguages(target) {
  const store = storeFor(target);
  if (!existsSync(store.runsDir)) return [];
  let latest = null;
  for (const entry of readdirSync(store.runsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("host-context-")) continue;
    const ctx = join(store.runsDir, entry.name, "context.json");
    if (!existsSync(ctx)) continue;
    const mtime = statSync(ctx).mtime;
    if (!latest || mtime > latest.mtime) latest = { ctx, mtime };
  }
  const byLanguage = latest ? readJsonIfPresent(latest.ctx)?.inventory?.byLanguage ?? {} : {};
  return Object.entries(byLanguage).filter(([l, c]) => l !== "Other" && Number(c) > 0).map(([l]) => l);
}

function codeqlLanguages(target) {
  return [...new Set(detectedLanguages(target).map((l) => CODEQL_LANG[l]).filter(Boolean))];
}

function ensureInstalled(store, tool, includeInstall) {
  if (commandInstalled(tool)) return { ok: true };
  if (!includeInstall) return { ok: false, reason: `${tool} CLI not installed (run /install ${tool})` };
  log(store, `installing ${tool} (this can be large)…`);
  const status = runLogged(store, process.execPath, [INSTALL_TOOLING, "--only", tool, "--include-heavy", "--approved"]);
  return commandInstalled(tool) ? { ok: true } : { ok: false, reason: `install of ${tool} failed (status ${status})` };
}

function buildJoern(target, store, includeInstall, force) {
  if (existsSync(store.joernCpgPath) && !force) return { tool: "joern", ok: true, skipped: "cpg already present", path: store.joernCpgPath };
  const dep = ensureInstalled(store, "joern", includeInstall);
  if (!dep.ok) return { tool: "joern", ok: false, reason: dep.reason };
  mkdirSync(dirname(store.joernCpgPath), { recursive: true });
  const astgen = resolveAstgen();
  const env = astgen ? { ...process.env, ASTGEN_BIN: astgen } : process.env;
  if (astgen) log(store, `ASTGEN_BIN=${astgen}`);
  const status = runLogged(store, "joern-parse", [target, "--output", store.joernCpgPath], env);
  return status === 0 && existsSync(store.joernCpgPath)
    ? { tool: "joern", ok: true, path: store.joernCpgPath }
    : { tool: "joern", ok: false, reason: `joern-parse exited ${status} (see db-build.log)` };
}

function buildCodeql(target, store, includeInstall, force) {
  const langs = codeqlLanguages(target);
  if (!langs.length) return [{ tool: "codeql", ok: false, reason: "no codeql-supported languages detected" }];
  const dep = ensureInstalled(store, "codeql", includeInstall);
  if (!dep.ok) return [{ tool: "codeql", ok: false, reason: dep.reason }];
  const results = [];
  for (const lang of langs) {
    const dbPath = join(store.codeqlDbDir, lang);
    if (existsSync(dbPath) && !force) { results.push({ tool: "codeql", language: lang, ok: true, skipped: "db already present", path: dbPath }); continue; }
    mkdirSync(store.codeqlDbDir, { recursive: true });
    const args = ["database", "create", dbPath, `--language=${lang}`, `--source-root=${target}`, "--overwrite"];
    if (BUILD_MODE_NONE.has(lang)) args.push("--build-mode=none");
    const status = runLogged(store, "codeql", args);
    results.push(status === 0 && existsSync(dbPath)
      ? { tool: "codeql", language: lang, ok: true, path: dbPath }
      : { tool: "codeql", language: lang, ok: false, reason: `codeql database create exited ${status} (see db-build.log)` });
  }
  return results;
}

function writeState(store, results) {
  mkdirSync(store.root, { recursive: true });
  writeFileSync(store.dbBuildStatePath, `${JSON.stringify({ lastRun: new Date().toISOString(), results }, null, 2)}\n`);
}

export function buildDatabases({ target, which = "both", includeInstall = false, force = false }) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  log(store, `build start: which=${which} include-install=${includeInstall} force=${force}`);
  const results = [];
  if (which === "joern" || which === "both") results.push(buildJoern(resolvedTarget, store, includeInstall, force));
  if (which === "codeql" || which === "both") results.push(...buildCodeql(resolvedTarget, store, includeInstall, force));
  writeState(store, results);
  log(store, `build done — ${results.filter((r) => r.ok).length}/${results.length} ok`);
  return { ok: results.every((r) => r.ok), status: "completed", target: resolvedTarget, which, results };
}

// Re-spawn this script detached so the caller returns immediately.
function spawnBackground(flags) {
  const store = storeFor(resolve(flags.target));
  mkdirSync(store.root, { recursive: true });
  const logPath = logPathFor(store);
  const fd = openSync(logPath, "a");
  const args = [SELF, "--target", flags.target, "--which", flags.which ?? "both"];
  if (flags["include-install"]) args.push("--include-install");
  if (flags.force) args.push("--force");
  const child = spawn(process.execPath, args, { detached: true, stdio: ["ignore", fd, fd] });
  child.unref();
  return { ok: true, status: "started", target: resolve(flags.target), pid: child.pid, logPath, note: "building in the background; codeql/joern queries work once it finishes" };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("build-databases --target <repo> [--which codeql|joern|both] [--include-install] [--background] [--force]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["include-install", "background", "force", "help"],
    value: ["target", "which"]
  });
  if (!flags.target) { console.error("build-databases: --target is required"); process.exit(1); }
  if (flags.background) { emitResult(spawnBackground(flags)); return; }
  emitResult(buildDatabases({
    target: flags.target, which: flags.which ?? "both",
    includeInstall: Boolean(flags["include-install"]), force: Boolean(flags.force)
  }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
