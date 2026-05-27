#!/usr/bin/env node
// Prepare phase for /supply-chain. Finds dependency manifests, light-parses the
// DIRECT dependencies (name + manifest path/line for evidence), and hands the
// supply-chain-auditor agent a worklist. The agent does the network research
// (maintainers / popularity / CVE history / cadence) — this stage is offline and
// deterministic.

import { existsSync, readFileSync } from "node:fs";
import { resolve, join, relative } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult } from "../lib/artifact-store.mjs";
import { listFiles } from "../lib/ripgrep.mjs";

// Manifest basenames we light-parse for direct deps. Each parser returns
// [{ name, line }] for the manifest's own direct dependencies only.
const MANIFESTS = [
  { match: /^package\.json$/, ecosystem: "npm", parse: parsePackageJson },
  { match: /^requirements[\w.-]*\.txt$/, ecosystem: "pypi", parse: parseRequirements },
  { match: /^go\.mod$/, ecosystem: "go", parse: parseGoMod },
  { match: /^Cargo\.toml$/, ecosystem: "crates", parse: parseCargoToml },
  { match: /^Gemfile$/, ecosystem: "rubygems", parse: parseGemfile },
  { match: /^pom\.xml$/, ecosystem: "maven", parse: parsePomXml }
];

function lineOf(text, idx) {
  return text.slice(0, idx).split(/\n/).length;
}

function parsePackageJson(text) {
  const out = [];
  let json;
  try { json = JSON.parse(text); } catch { return out; }
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const name of Object.keys(json[field] ?? {})) {
      const m = text.indexOf(`"${name}"`);
      out.push({ name, line: m >= 0 ? lineOf(text, m) : 1, dev: field !== "dependencies" });
    }
  }
  return out;
}

function parseRequirements(text) {
  const out = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) return;
    const name = line.split(/[<>=!~;\[\s]/)[0].trim();
    if (name) out.push({ name, line: i + 1 });
  });
  return out;
}

function parseGoMod(text) {
  const out = [];
  const lines = text.split(/\r?\n/);
  let inBlock = false;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line.startsWith("require (")) { inBlock = true; return; }
    if (inBlock && line === ")") { inBlock = false; return; }
    const m = (inBlock ? line : line.replace(/^require\s+/, line.startsWith("require ") ? "" : line))
      .match(/^([\w.\-/]+)\s+v[\w.\-+]/);
    if ((inBlock || line.startsWith("require ")) && m) out.push({ name: m[1], line: i + 1 });
  });
  return out;
}

function parseCargoToml(text) {
  const out = [];
  const lines = text.split(/\r?\n/);
  let inDeps = false;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (/^\[(.*\.)?dependencies\]$/.test(line) || /^\[dev-dependencies\]$/.test(line)) { inDeps = true; return; }
    if (/^\[/.test(line)) { inDeps = false; return; }
    if (inDeps) {
      const m = line.match(/^([A-Za-z0-9_\-]+)\s*=/);
      if (m) out.push({ name: m[1], line: i + 1 });
    }
  });
  return out;
}

function parseGemfile(text) {
  const out = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const m = raw.match(/^\s*gem\s+['"]([^'"]+)['"]/);
    if (m) out.push({ name: m[1], line: i + 1 });
  });
  return out;
}

function parsePomXml(text) {
  const out = [];
  const re = /<artifactId>([^<]+)<\/artifactId>/g;
  let m;
  while ((m = re.exec(text))) out.push({ name: m[1], line: lineOf(text, m.index) });
  return out;
}

// rg include-globs for the manifest filenames (default source-extension globs
// would skip .json/.txt/.mod/.toml/Gemfile). Default excludes still drop
// node_modules / vendor / .kuzushi etc.
const MANIFEST_GLOBS = [
  "package.json", "requirements*.txt", "go.mod", "Cargo.toml", "Gemfile", "*.gemspec", "pom.xml"
];

function collectManifests(target, maxFiles = 12) {
  const files = listFiles(target, { includeGlobs: MANIFEST_GLOBS }).filter((rel) => {
    const base = rel.split("/").pop();
    return MANIFESTS.some((spec) => spec.match.test(base));
  }).slice(0, maxFiles);
  const manifests = [];
  for (const rel of files) {
    const abs = join(target, rel);
    let text;
    try { text = readFileSync(abs, "utf8"); } catch { continue; }
    const spec = MANIFESTS.find((s) => s.match.test(rel.split("/").pop()));
    const deps = spec.parse(text).slice(0, 120);
    if (deps.length) manifests.push({ path: rel, ecosystem: spec.ecosystem, deps });
  }
  return manifests;
}

export function prepareSupplyChain(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const maxDeps = Number(input.maxDeps ?? 40);

  const manifests = collectManifests(resolvedTarget);
  // Flatten to a capped, de-duplicated worklist (direct deps across manifests).
  const seen = new Set();
  const deps = [];
  for (const m of manifests) {
    for (const d of m.deps) {
      const key = `${m.ecosystem}:${d.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deps.push({ name: d.name, ecosystem: m.ecosystem, manifest: m.path, line: d.line, dev: Boolean(d.dev) });
      if (deps.length >= maxDeps) break;
    }
    if (deps.length >= maxDeps) break;
  }

  const run = openRun(resolvedTarget, "supply-chain");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    manifestCount: manifests.length, depCount: deps.length, deps, input
  });

  return {
    ok: true,
    status: deps.length ? "prepared" : "no-deps",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.supply-chain.json"),
    manifestCount: manifests.length,
    depCount: deps.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "supply-chain-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("supply-chain-prepare --target <path> [--input '{\"maxDeps\":40}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("supply-chain-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareSupplyChain(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
