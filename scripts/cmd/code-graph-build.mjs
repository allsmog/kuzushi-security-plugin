#!/usr/bin/env node
// Build a persistent, compact code-graph for the repo: entry points + per-symbol
// caller counts (the blast-radius / attack-surface signal). Cached at
// .kuzushi/code-graph.json so producers (e.g. /diff-review) read it instead of
// re-deriving caller info live each run. Deterministic, read-only.
//
// Backend: a ripgrep heuristic (function-definition scan + a single call-site
// tally pass) that needs no heavy tooling and works on any language. If a Joern
// CPG is present it is noted as an available higher-fidelity upgrade (a future
// backend); the heuristic still runs so the artifact is always produced.

import { existsSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { resolve, join, extname } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { runRg, buildGlobs } from "../lib/ripgrep.mjs";

const JOERN_MAX_BUFFER = 64 * 1024 * 1024;

function joernAvailable() {
  const r = spawnSync("joern", ["--version"], { encoding: "utf8" });
  return !r.error && (r.status === 0 || r.status === null);
}

// Real call edges from a prebuilt Joern CPG: per (app-owned) method, the call-site
// count (callIn) and a few caller names. Returns null on any failure → caller
// falls back to the ripgrep heuristic. callIn.size is a true edge count, not a
// token tally, so it's a far better blast-radius signal.
function buildFromJoern(cpgPath, maxSymbols) {
  const script = [
    "import io.shiftleft.semanticcpg.language._",
    "import scala.util.Try",
    'val cpgFile = sys.env.getOrElse("KUZUSHI_CPG", throw new RuntimeException("missing KUZUSHI_CPG"))',
    "importCpg(cpgFile)",
    `cpg.method.isExternal(false).take(${Math.max(50, maxSymbols)}).foreach { m =>`,
    "  val callers = Try(m.caller.name.dedup.take(8).l).getOrElse(Nil)",
    "  val count = Try(m.callIn.size).getOrElse(0)",
    '  val line = m.lineNumber.map(_.toString).getOrElse("0")',
    '  println("KGRAPH\\t" + m.name + "\\t" + m.filename + "\\t" + line + "\\t" + count + "\\t" + callers.mkString(","))',
    "}"
  ].join("\n");
  const scratch = mkdtempSync(join(tmpdir(), "kuzushi-cgraph-"));
  const scriptPath = join(scratch, "graph.sc");
  try {
    writeFileSync(scriptPath, script);
    const r = spawnSync("joern", ["--script", scriptPath], {
      encoding: "utf8", maxBuffer: JOERN_MAX_BUFFER, env: { ...process.env, KUZUSHI_CPG: cpgPath }
    });
    if (r.status !== 0 || !r.stdout) return null;
    const symbols = [];
    for (const raw of r.stdout.split(/\r?\n/)) {
      if (!raw.startsWith("KGRAPH\t")) continue;
      const [, name, file, line, count, callers] = raw.split("\t");
      if (!name || name.startsWith("<")) continue; // skip synthetic <global>/<operator>/<clinit>
      symbols.push({
        name, file, line: Number(line) || 1, callerCount: Number(count) || 0,
        callers: callers ? callers.split(",").filter(Boolean) : [], callees: []
      });
    }
    return symbols.length ? symbols : null;
  } catch {
    return null;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

// Definition probes: a regex whose match line contains a function/method name we
// extract with `nameOf`. Keyword forms are reliable; the C/Java method form is
// approximate but the caller-count signal tolerates a partial definition set.
const DEF_PROBES = [
  { re: "\\bdef\\s+[A-Za-z_]\\w*\\s*\\(", nameOf: /\bdef\s+([A-Za-z_]\w*)/ },                 // python
  { re: "\\bfn\\s+[A-Za-z_]\\w*\\s*[<(]", nameOf: /\bfn\s+([A-Za-z_]\w*)/ },                  // rust
  { re: "\\bfunc\\s+(?:\\([^)]*\\)\\s*)?[A-Za-z_]\\w*\\s*\\(", nameOf: /\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)/ }, // go
  { re: "\\bfunction\\s+[A-Za-z_]\\w*\\s*\\(", nameOf: /\bfunction\s+([A-Za-z_]\w*)/ },        // js/ts
  { re: "^[\\w\\*&:<>\\[\\]\\s]+\\s+[A-Za-z_]\\w*\\s*\\([^;{}]*\\)\\s*\\{", nameOf: /([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{/ } // c/c++/java method def
];

// Identifiers we never count as user functions (control flow / common noise).
const STOPWORDS = new Set(["if", "for", "while", "switch", "catch", "return", "sizeof",
  "function", "func", "def", "fn", "and", "or", "not", "in", "with", "match", "case",
  "do", "else", "new", "await", "yield", "typeof", "super", "assert", "print", "println"]);

function lineNameMatches(text, re) {
  for (const raw of text.split(/\r?\n/)) {
    const m = re.exec(raw);
    if (m) return m;
  }
  return null;
}

// Pass 1: collect function/method definitions { name -> {file, line, defCount} }.
function collectDefs(target, globs) {
  const defs = new Map();
  for (const probe of DEF_PROBES) {
    const r = runRg(target, ["--json", "-n", "-e", probe.re, ...globs, "."]);
    if (!r.ok) continue;
    for (const line of r.stdout.split(/\r?\n/)) {
      if (!line.trim()) continue;
      let ev; try { ev = JSON.parse(line); } catch { continue; }
      if (ev.type !== "match") continue;
      const text = ev.data?.lines?.text ?? "";
      const m = probe.nameOf.exec(text);
      if (!m) continue;
      const name = m[1];
      if (STOPWORDS.has(name) || name.length < 2) continue;
      const prev = defs.get(name);
      if (prev) { prev.defCount += 1; continue; }
      defs.set(name, { name, filePath: ev.data?.path?.text, line: ev.data?.line_number ?? 1, defCount: 1 });
    }
  }
  return defs;
}

// Pass 2: one sweep tallying every `name(` call token across the repo.
function tallyCalls(target, globs) {
  const tally = new Map();
  const r = runRg(target, ["-o", "--no-filename", "-e", "[A-Za-z_][A-Za-z0-9_]*\\s*\\(", ...globs, "."]);
  if (!r.ok) return tally;
  for (const raw of r.stdout.split(/\r?\n/)) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(raw.trim());
    if (!m) continue;
    const name = m[1];
    if (STOPWORDS.has(name)) continue;
    tally.set(name, (tally.get(name) ?? 0) + 1);
  }
  return tally;
}

function entryPointsFor(store) {
  const ep = readJsonIfPresent(join(store.xRayDir, "entry-points.json"));
  if (!Array.isArray(ep)) return [];
  return ep.slice(0, 100).map((e) => ({ filePath: e.filePath, line: e.line, kind: e.kind, boundary: e.boundary }));
}

export function buildCodeGraph(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const maxSymbols = Number(input.maxSymbols ?? 400);
  const globs = buildGlobs();

  const joernCpgPresent = existsSync(store.joernCpgPath);

  // Prefer a Joern CPG (real call edges) when present + the CLI is available;
  // otherwise the ripgrep heuristic (call-site token tally).
  let backend, symbols, definitionCount = null;
  if (joernCpgPresent && joernAvailable() && !input.forceHeuristic) {
    const joernSyms = buildFromJoern(store.joernCpgPath, maxSymbols);
    if (joernSyms) {
      backend = "joern";
      symbols = joernSyms.sort((a, b) => b.callerCount - a.callerCount).slice(0, maxSymbols);
    }
  }
  if (!symbols) {
    backend = "ripgrep-heuristic";
    const defs = collectDefs(resolvedTarget, globs);
    const tally = tallyCalls(resolvedTarget, globs);
    definitionCount = defs.size;
    // callerCount = call-site occurrences minus the symbol's own definition lines
    // (each def line contains `name(` once). Clamp at 0.
    symbols = [...defs.values()]
      .map((d) => ({
        name: d.name, file: d.filePath, line: d.line,
        callerCount: Math.max(0, (tally.get(d.name) ?? 0) - d.defCount),
        callers: [], callees: []
      }))
      .sort((a, b) => b.callerCount - a.callerCount)
      .slice(0, maxSymbols);
  }

  const entryPoints = entryPointsFor(store);
  const upgradeNote = backend === "joern"
    ? "Real call edges from the Joern CPG (callIn counts)."
    : (joernCpgPresent ? "Joern CPG present but the joern CLI was unavailable/failed — used the heuristic." : "Build a Joern CPG (/build-databases) for exact interprocedural edges.");

  const doc = {
    version: "1.0",
    schemaVersion: "code-graph.v1",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    backend,
    upgrades: { joernCpgPresent, note: upgradeNote },
    entryPoints,
    symbols,
    summary: { ...(definitionCount !== null ? { definitionCount } : {}), symbolCount: symbols.length, entryPointCount: entryPoints.length, topSymbol: symbols[0]?.name ?? null }
  };
  atomicWrite(store.codeGraphPath, `${JSON.stringify(doc, null, 2)}\n`);

  const run = openRun(resolvedTarget, "code-graph");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    codeGraphPath: store.codeGraphPath, backend,
    symbolCount: symbols.length, entryPointCount: entryPoints.length,
    joernCpgPresent, topSymbols: symbols.slice(0, 8).map((s) => `${s.name} (${s.callerCount})`)
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("code-graph-build --target <path> [--input '{\"maxSymbols\":400}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("code-graph-build: --target is required");
    process.exit(1);
  }
  emitResult(buildCodeGraph(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
