// Native validation/execution backends for synthesized CodeQL queries and Joern
// scripts — the engines /semgrep-rule does NOT cover (it is Semgrep-only). The
// gate is native (spawnSync the CLIs directly), not MCP, so the agent that wrote
// the rule cannot talk around it. Each engine exposes a uniform surface:
//   available(target)                 -> { available, reason, dbs?/cpg? }
//   validate(ruleFile)                -> { ok, stage:"compile", stderr? }   (compile only)
//   selfMatch(ruleFile, target, seed) -> { ok, matched, lines:[...] }       (fires on the seed?)
//   repoRun(ruleFile, target)         -> { ok, matches:[{file,line}] }      (whole-repo)
//
// All functions degrade gracefully (return { available:false } / { ok:false })
// when the CLI or the prebuilt DB/CPG is absent — never throw.

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, resolve, relative, dirname, delimiter } from "node:path";

const RUN_MAX_BUFFER = 64 * 1024 * 1024;
const RUN_TIMEOUT = 120_000;

function cli(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: RUN_MAX_BUFFER, timeout: RUN_TIMEOUT, ...opts });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error };
}

function commandPresent(cmd, probeArgs) {
  const r = spawnSync(cmd, probeArgs, { encoding: "utf8", timeout: 10_000 });
  return !r.error && (r.status === 0 || r.status === null);
}

// ---------------------------------------------------------------------------
// CodeQL
// ---------------------------------------------------------------------------

function codeqlDbDir(target) {
  return join(resolve(target), ".kuzushi", "codeql-db");
}

// Languages with a built CodeQL DB under .kuzushi/codeql-db/<lang>/.
function codeqlDatabases(target) {
  const dir = codeqlDbDir(target);
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && existsSync(join(dir, e.name, "codeql-database.yml")))
      .map((e) => ({ language: e.name, path: join(dir, e.name) }));
  } catch { return []; }
}

// Where the standard CodeQL library packs (codeql/<lang>-all) live, so a
// standalone generated query can resolve `import <lang>`. Honors
// CODEQL_SEARCH_PATH, else the default ~/.codeql/packages.
function codeqlPacksPath() {
  const parts = [process.env.CODEQL_SEARCH_PATH, join(homedir(), ".codeql", "packages")].filter(Boolean);
  return parts.filter((p) => existsSync(p)).join(delimiter);
}

// A generated .ql needs a qlpack.yml beside it declaring the library deps, or
// `import java` won't resolve. Write one (covering every built DB language) if
// the agent didn't. Idempotent.
function ensureQlpack(ruleFile, languages) {
  const dir = dirname(resolve(ruleFile));
  const packPath = join(dir, "qlpack.yml");
  if (existsSync(packPath)) return;
  const deps = (languages.length ? languages : ["java"]).map((l) => `  codeql/${l}-all: "*"`).join("\n");
  writeFileSync(packPath, `name: kuzushi/rulesynth\nversion: 0.0.1\nlibraryPathDependencies: []\ndependencies:\n${deps}\n`);
}

export const codeql = {
  available(target) {
    if (!commandPresent("codeql", ["version", "--format=json"])) {
      return { available: false, reason: "codeql CLI not on PATH" };
    }
    const dbs = codeqlDatabases(target);
    if (!dbs.length) return { available: false, reason: "no CodeQL DB built (run /build-databases)" };
    return { available: true, dbs };
  },
  validate(ruleFile, target) {
    ensureQlpack(ruleFile, codeqlDatabases(target).map((d) => d.language));
    const packs = codeqlPacksPath();
    const args = ["query", "compile"];
    if (packs) args.push("--additional-packs", packs);
    args.push("--", resolve(ruleFile));
    const r = cli("codeql", args);
    return { ok: r.status === 0, stage: "compile", stderr: r.stderr.slice(0, 2000) };
  },
  // Run the query against the DB; return resolved match locations.
  _run(ruleFile, dbPath, target) {
    ensureQlpack(ruleFile, codeqlDatabases(target ?? process.cwd()).map((d) => d.language));
    const packs = codeqlPacksPath();
    const scratch = mkdtempSync(join(tmpdir(), "kuzushi-ruleql-"));
    try {
      const bqrs = join(scratch, "r.bqrs");
      const runArgs = ["query", "run", "--database", dbPath, "--output", bqrs];
      if (packs) runArgs.push("--additional-packs", packs);
      runArgs.push("--", resolve(ruleFile));
      const run = cli("codeql", runArgs);
      if (run.status !== 0) return { ok: false, matches: [], stderr: run.stderr.slice(0, 2000) };
      // --entities=url makes bqrs decode emit the file:line location per result.
      const dec = cli("codeql", ["bqrs", "decode", "--format=json", "--entities=url", "--", bqrs]);
      if (dec.status !== 0) return { ok: false, matches: [], stderr: dec.stderr.slice(0, 2000) };
      return { ok: true, matches: parseCodeqlMatches(dec.stdout) };
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  },
  selfMatch(ruleFile, target, seed) {
    const db = codeqlDatabases(target).find((d) => d.language === seed.language) ?? codeqlDatabases(target)[0];
    if (!db) return { ok: false, matched: false, reason: "no DB for seed language" };
    const r = this._run(ruleFile, db.path, target);
    if (!r.ok) return { ok: false, matched: false, stderr: r.stderr };
    const matched = r.matches.some((m) => sameFile(m.file, seed.filePath, target) && near(m.line, seed.startLine));
    return { ok: true, matched, lines: r.matches };
  },
  repoRun(ruleFile, target, seed) {
    const db = codeqlDatabases(target).find((d) => d.language === seed?.language) ?? codeqlDatabases(target)[0];
    if (!db) return { ok: false, matches: [] };
    const r = this._run(ruleFile, db.path, target);
    return { ok: r.ok, matches: r.matches, stderr: r.stderr };
  }
};

// CodeQL bqrs JSON → [{file,line}]. Tolerant of the columnar shape.
function parseCodeqlMatches(stdout) {
  let doc;
  try { doc = JSON.parse(stdout); } catch { return []; }
  const out = [];
  const tuples = doc?.["#select"]?.tuples ?? [];
  for (const row of tuples) {
    for (const cell of row) {
      const loc = cell?.url ?? cell;
      if (loc && typeof loc === "object" && (loc.uri || loc.path)) {
        out.push({ file: (loc.uri ?? loc.path).replace(/^file:\/\//, ""), line: loc.startLine ?? loc.line ?? 0 });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Joern
// ---------------------------------------------------------------------------

function joernCpg(target) {
  return join(resolve(target), ".kuzushi", "joern", "cpg.bin.zip");
}

export const joern = {
  available(target) {
    if (!commandPresent("joern", ["--version"])) return { available: false, reason: "joern CLI not on PATH" };
    const cpg = joernCpg(target);
    if (!existsSync(cpg)) return { available: false, reason: "no Joern CPG built (run /build-databases)" };
    return { available: true, cpg };
  },
  // Joern scripts are Scala; "compile" = run with a parse/typecheck. We run the
  // script against the CPG and treat a non-zero exit / stderr error as a failure.
  // The CPG path is passed via KUZUSHI_CPG. We avoid relying on -Dpath here
  // because some Joern 4.x launchers do not forward that property to scripts.
  validate(ruleFile, target) {
    const cpg = joernCpg(target);
    const r = cli("joern", ["--script", resolve(ruleFile)], { input: "", env: { ...process.env, KUZUSHI_CPG: cpg } });
    return { ok: r.status === 0, stage: "compile", stderr: r.stderr.slice(0, 2000) };
  },
  _run(ruleFile, target) {
    const cpg = joernCpg(target);
    const r = cli("joern", ["--script", resolve(ruleFile)], { env: { ...process.env, KUZUSHI_CPG: cpg } });
    return { ok: r.status === 0, matches: parseJoernMatches(r.stdout), stderr: r.stderr.slice(0, 2000) };
  },
  selfMatch(ruleFile, target, seed) {
    const r = this._run(ruleFile, target);
    if (!r.ok) return { ok: false, matched: false, stderr: r.stderr };
    const matched = r.matches.some((m) => sameFile(m.file, seed.filePath, target) && near(m.line, seed.startLine));
    return { ok: true, matched, lines: r.matches };
  },
  repoRun(ruleFile, target) {
    return this._run(ruleFile, target);
  }
};

// Joern scripts are asked to print matches as `KUZUSHI_MATCH<TAB>file<TAB>line`.
function parseJoernMatches(stdout) {
  const out = [];
  for (const line of (stdout ?? "").split(/\r?\n/)) {
    const m = /KUZUSHI_MATCH\t([^\t]+)\t(\d+)/.exec(line);
    if (m) out.push({ file: m[1], line: Number(m[2]) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

function sameFile(a, b, target) {
  if (!a || !b) return false;
  const na = relative(resolve(target), resolve(target, a));
  const nb = relative(resolve(target), resolve(target, b));
  return na === nb || a.endsWith(b) || b.endsWith(a);
}

function near(line, seedLine, window = 3) {
  return Math.abs(Number(line) - Number(seedLine ?? 0)) <= window;
}

export const ENGINES = { codeql, joern };
