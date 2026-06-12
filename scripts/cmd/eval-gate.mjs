#!/usr/bin/env node
// Deterministic gate for an existing eval scoreboard JSON. The billed eval remains
// manual; this script turns its metrics into release criteria without re-running agents.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";

const MIN_THRESHOLDS = {
  "min-routing-recall": "routingRecall",
  "min-reasoning-recall": "reasoningRecall",
  "min-site-context-recall": "siteContextRecall",
  "min-site-reasoning-recall": "siteReasoningRecall",
  "min-blind-recall": "blindRecall",
  "min-confirmed-on-target": "confirmedOnTarget",
  "min-proven-on-target": "provenOnTarget"
};

const MAX_THRESHOLDS = {
  "max-false-proof-rate": "falseProofRate",
  "max-extra-confirmed-per-case": "extraConfirmedPerCase",
  "max-extra-proven-per-case": "extraProvenPerCase",
  "max-cost-per-true-finding": "costPerTrueFinding"
};

export function parseThreshold(value) {
  const s = String(value ?? "").trim();
  if (!s) return null;
  if (s.endsWith("%")) {
    const n = Number(s.slice(0, -1));
    return Number.isFinite(n) ? n / 100 : null;
  }
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function metricValue(scoreboard, key) {
  const v = scoreboard?.aggregate?.[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function evaluateScoreboardGate(scoreboard, thresholds = {}) {
  const failures = [];
  const checks = [];

  for (const [flag, metric] of Object.entries(MIN_THRESHOLDS)) {
    if (thresholds[flag] === undefined) continue;
    const want = parseThreshold(thresholds[flag]);
    const got = metricValue(scoreboard, metric);
    const ok = want !== null && got !== null && got >= want;
    checks.push({ metric, comparator: ">=", threshold: want, value: got, ok });
    if (!ok) failures.push(`${metric}: ${got ?? "missing"} < ${want ?? "invalid-threshold"}`);
  }

  for (const [flag, metric] of Object.entries(MAX_THRESHOLDS)) {
    if (thresholds[flag] === undefined) continue;
    const want = parseThreshold(thresholds[flag]);
    const got = metricValue(scoreboard, metric);
    const ok = want !== null && got !== null && got <= want;
    checks.push({ metric, comparator: "<=", threshold: want, value: got, ok });
    if (!ok) failures.push(`${metric}: ${got ?? "missing"} > ${want ?? "invalid-threshold"}`);
  }

  return {
    ok: failures.length === 0,
    schemaVersion: "eval-gate.v1",
    scoreboardSchemaVersion: scoreboard?.schemaVersion ?? null,
    checks,
    failures
  };
}

function main() {
  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["help", "json"],
    value: ["scoreboard", ...Object.keys(MIN_THRESHOLDS), ...Object.keys(MAX_THRESHOLDS)]
  });
  if (flags.help) {
    console.log([
      "eval-gate --scoreboard eval/scoreboard.cve.json [thresholds]",
      "",
      "Thresholds accept decimals (0.6) or percentages (60%).",
      "Examples:",
      "  --min-routing-recall 80%",
      "  --min-reasoning-recall 60%",
      "  --min-site-context-recall 40%",
      "  --min-site-reasoning-recall 60%",
      "  --min-blind-recall 60%",
      "  --min-proven-on-target 40%",
      "  --max-false-proof-rate 0",
      "  --max-extra-confirmed-per-case 1",
      "  --max-cost-per-true-finding 120"
    ].join("\n"));
    return;
  }

  const path = resolve(flags.scoreboard ?? "eval/scoreboard.json");
  if (!existsSync(path)) {
    console.error(`eval-gate: scoreboard not found: ${path}`);
    process.exit(2);
  }
  const scoreboard = JSON.parse(readFileSync(path, "utf8"));
  const result = evaluateScoreboardGate(scoreboard, flags);
  if (flags.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (result.ok) {
    process.stdout.write(`eval-gate: passed ${result.checks.length} checks\n`);
  } else {
    process.stderr.write(`eval-gate: failed\n${result.failures.map((f) => `- ${f}`).join("\n")}\n`);
  }
  process.exit(result.ok ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
