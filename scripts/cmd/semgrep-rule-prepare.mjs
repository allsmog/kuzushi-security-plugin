#!/usr/bin/env node
// Prepare phase for /semgrep-rule. Picks confirmed findings as seeds and, for
// each, hands the agent an excerpt + a target rule path under .kuzushi/rules/ so
// it can author a test-driven Semgrep rule that detects that bug class. The
// generated rules seed /variant-hunt and future /sast re-runs. Read-only.

import { existsSync, readFileSync, statSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { normalizeCweId } from "../lib/taint-catalog.mjs";

const EXCERPT_RADIUS = 12;

function isSeed(f) {
  if (f.status === "confirmed" || f.status === "proven") return true;
  if (f.status === "open" && (f.verdict === "exploitable" || f.verdict === "finding")) return true;
  return false;
}

function excerptFor(target, anchor) {
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return { filePath: anchor.filePath, startLine: anchor.startLine ?? 1, lines: [] };
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  const start = Math.max(1, anchorLine - EXCERPT_RADIUS);
  const end = Math.min(lines.length, anchorLine + EXCERPT_RADIUS);
  return { filePath: anchor.filePath, startLine: anchorLine, lines: lines.slice(start - 1, end).map((text, i) => ({ line: start + i, text })) };
}

function slugFor(f) {
  const cwe = normalizeCweId(Array.isArray(f.cwe) ? f.cwe[0] : (f.cwe ?? "rule")).toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `${cwe}-${String(f.fingerprint).slice(0, 8)}`;
}

export function prepareSemgrepRule(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) {
    throw new Error(`${store.findingsPath} not found — confirm a finding first (/threat-hunt → /verify, or /taint-analysis / /systems-hunt)`);
  }
  mkdirSync(store.rulesDir, { recursive: true });
  const maxSeeds = Number(input.maxSeeds ?? 6);
  const seeds = (findingsDoc.findings ?? []).filter(isSeed).slice(0, maxSeeds).map((f) => {
    const slug = slugFor(f);
    return {
      seedFingerprint: f.fingerprint,
      title: f.title,
      cwe: (Array.isArray(f.cwe) ? f.cwe[0] : f.cwe) ?? "",
      severity: f.severity ?? "",
      anchor: f.evidence?.[0] ? { filePath: f.evidence[0].filePath, startLine: f.evidence[0].startLine } : null,
      excerpt: excerptFor(resolvedTarget, f.evidence?.[0]),
      ruleId: slug,
      rulePath: join(store.rulesDir, `${slug}.yaml`),
      fixtureHint: join(store.rulesDir, `${slug}.fixture`)
    };
  });

  const run = openRun(resolvedTarget, "semgrep-rule");
  run.writeJson("prep.json", { runId: run.runId, runDir: run.runDir, target: resolvedTarget, rulesDir: store.rulesDir, seedCount: seeds.length, seeds, input });

  return {
    ok: true,
    status: seeds.length ? "prepared" : "no-seeds",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.semgrep-rule.json"),
    rulesDir: store.rulesDir,
    seedCount: seeds.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "semgrep-rule-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("semgrep-rule-prepare --target <path> [--input '{\"maxSeeds\":6}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("semgrep-rule-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareSemgrepRule(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
