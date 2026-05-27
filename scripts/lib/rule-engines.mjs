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
import { tmpdir } from "node:os";
import { join, resolve, relative } from "node:path";

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

export const codeql = {
  available(target) {
    if (!commandPresent("codeql", ["version", "--format=json"])) {
      return { available: false, reason: "codeql CLI not on PATH" };
    }
    const dbs = codeqlDatabases(target);
    if (!dbs.length) return { available: false, reason: "no CodeQL DB built (run /build-databases)" };
    return { available: true, dbs };
  },
  validate(ruleFile) {
    const r = cli("codeql", ["query", "compile", "--", resolve(ruleFile)]);
    return { ok: r.status === 0, stage: "compile", stderr: r.stderr.slice(0, 2000) };
  },
  // Run the query against the DB for `language`; return resolved match locations.
  _run(ruleFile, dbPath) {
    const scratch = mkdtempSync(join(tmpdir(), "kuzushi-ruleql-"));
    try {
      const bqrs = join(scratch, "r.bqrs");
      const run = cli("codeql", ["query", "run", "--database", dbPath, "--output", bqrs, "--", resolve(ruleFile)]);
      if (run.status !== 0) return { ok: false, matches: [], stderr: run.stderr.slice(0, 2000) };
      const dec = cli("codeql", ["bqrs", "decode", "--format=json", "--", bqrs]);
      if (dec.status !== 0) return { ok: false, matches: [], stderr: dec.stderr.slice(0, 2000) };
      return { ok: true, matches: parseCodeqlMatches(dec.stdout) };
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  },
  selfMatch(ruleFile, target, seed) {
    const db = codeqlDatabases(target).find((d) => d.language === seed.language) ?? codeqlDatabases(target)[0];
    if (!db) return { ok: false, matched: false, reason: "no DB for seed language" };
    const r = this._run(ruleFile, db.path);
    if (!r.ok) return { ok: false, matched: false, stderr: r.stderr };
    const matched = r.matches.some((m) => sameFile(m.file, seed.filePath, target) && near(m.line, seed.startLine));
    return { ok: true, matched, lines: r.matches };
  },
  repoRun(ruleFile, target, seed) {
    const db = codeqlDatabases(target).find((d) => d.language === seed?.language) ?? codeqlDatabases(target)[0];
    if (!db) return { ok: false, matches: [] };
    const r = this._run(ruleFile, db.path);
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
  validate(ruleFile, target) {
    const cpg = joernCpg(target);
    const r = cli("joern", ["--script", resolve(ruleFile), `-Dpath=${cpg}`], { input: "" });
    return { ok: r.status === 0, stage: "compile", stderr: r.stderr.slice(0, 2000) };
  },
  _run(ruleFile, target) {
    const cpg = joernCpg(target);
    const r = cli("joern", ["--script", resolve(ruleFile), `-Dpath=${cpg}`]);
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
