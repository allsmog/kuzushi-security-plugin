#!/usr/bin/env node
// Prepare phase for /rule-synth (CodeQL/Joern rule synthesis — the engines
// /semgrep-rule does NOT cover). Seeds from confirmed/proven/exploitable findings,
// gathers a root-cause excerpt, and reports which heavy engines are available
// (a built CodeQL DB / Joern CPG). The agent then writes a query per seed for the
// recommended engine; finalize runs the native compile→seed-match→repo-run→
// precision gate and persists only validated, digest-attested rules. Read-only.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join, extname } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { codeql, joern } from "../lib/rule-engines.mjs";

const EXCERPT_RADIUS = 12;
const EXT_LANGUAGE = {
  ".rs": "rust", ".py": "python", ".js": "javascript", ".mjs": "javascript", ".ts": "typescript",
  ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".go": "go", ".java": "java", ".rb": "ruby", ".php": "php"
};

function languageFor(filePath) {
  return EXT_LANGUAGE[extname(filePath ?? "").toLowerCase()] ?? "unknown";
}

function excerptFor(target, anchor) {
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return null;
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  const start = Math.max(1, anchorLine - EXCERPT_RADIUS);
  const end = Math.min(lines.length, anchorLine + EXCERPT_RADIUS);
  return { filePath: anchor.filePath, startLine: anchorLine, lines: lines.slice(start - 1, end).map((text, i) => ({ line: start + i, text })) };
}

function isSeed(f) {
  return f.status === "confirmed" || f.status === "proven" ||
    (f.status === "open" && (f.verdict === "exploitable" || f.verdict === "finding"));
}

export function prepareRuleSynth(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) throw new Error(`${store.findingsPath} not found — confirm a finding first (/verify, /threat-hunt)`);

  const seeds = (findingsDoc.findings ?? []).filter(isSeed);
  const run = openRun(resolvedTarget, "rule-synth");

  const cq = codeql.available(resolvedTarget);
  const jn = joern.available(resolvedTarget);
  const engines = {
    codeql: cq.available ? { available: true, dbs: cq.dbs.map((d) => d.language) } : { available: false, reason: cq.reason },
    joern: jn.available ? { available: true } : { available: false, reason: jn.reason }
  };

  if (!seeds.length) {
    const out = { ok: true, status: "no-seeds", target: resolvedTarget, runId: run.runId, runDir: run.runDir, engines,
      reason: "no confirmed/proven/exploitable findings to seed from — run /verify or /threat-hunt first" };
    run.writeJson("prep.json", { ...out, seeds: [] });
    return out;
  }
  if (!engines.codeql.available && !engines.joern.available) {
    const out = { ok: true, status: "no-engine", target: resolvedTarget, runId: run.runId, runDir: run.runDir, engines,
      reason: "no CodeQL DB or Joern CPG built — run /build-databases (or use /semgrep-rule for Semgrep)" };
    run.writeJson("prep.json", { ...out, seeds: [] });
    return out;
  }

  const maxSeeds = Number(input.maxSeeds ?? 8);
  const seedCtx = seeds.slice(0, maxSeeds).map((f) => {
    const anchor = (f.evidence ?? [])[0];
    const language = languageFor(anchor?.filePath);
    const codeqlHasLang = engines.codeql.available && engines.codeql.dbs.includes(language);
    const recommendedEngine = codeqlHasLang ? "codeql" : (engines.joern.available ? "joern" : (engines.codeql.available ? "codeql" : "none"));
    return {
      seedFingerprint: f.fingerprint, title: f.title, cwe: f.cwe, severity: f.severity,
      language, anchor: anchor ? { filePath: anchor.filePath, startLine: anchor.startLine } : null,
      excerpt: excerptFor(resolvedTarget, anchor), rationale: f.rationale, recommendedEngine
    };
  });

  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    references: artifactSnapshot(resolvedTarget), engines, seedCount: seedCtx.length, seeds: seedCtx, input
  });

  return {
    ok: true, status: "prepared", target: resolvedTarget, runId: run.runId, runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"), draftPath: join(run.runDir, "draft.rule-synth.json"),
    seedCount: seedCtx.length, engines,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "rule-synth-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("rule-synth-prepare --target <path> [--input '{\"maxSeeds\":8}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) { console.error("rule-synth-prepare: --target is required"); process.exit(1); }
  emitResult(prepareRuleSynth(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
