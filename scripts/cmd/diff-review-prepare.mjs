#!/usr/bin/env node
// Prepare phase for /diff-review. Resolves a base ref, collects the changed
// files + per-file unified diff via git, risk-scores each by path/keyword, and
// hands the diff-reviewer agent a change-focused worklist. Deterministic; needs
// a git repo.

import { resolve, join } from "node:path";
import { spawnSync } from "node:child_process";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";

// Blast radius from the cached code-graph (.kuzushi/code-graph.json): for a changed
// file, the symbols defined in it + their caller counts. Deterministic and repo-wide
// — better than live intra-file caller counting. Returns null when no graph exists
// (the agent then falls back to live `tree_sitter:callers`).
function blastRadiusFor(graph, path) {
  if (!graph?.symbols) return null;
  const norm = (p) => String(p ?? "").replace(/^\.\//, "");
  const syms = graph.symbols
    .filter((s) => norm(s.file) === norm(path))
    .map((s) => ({ name: s.name, callerCount: s.callerCount }))
    .sort((a, b) => b.callerCount - a.callerCount);
  if (!syms.length) return null;
  return { fromGraph: true, symbols: syms.slice(0, 12), maxCallerCount: syms[0].callerCount };
}

function git(target, args) {
  const r = spawnSync("git", ["-C", target, ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { ok: !r.error && r.status === 0, stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: r.status };
}

function isGitRepo(target) {
  return git(target, ["rev-parse", "--is-inside-work-tree"]).stdout.trim() === "true";
}

// Resolve the base to diff against: explicit input.base, else the merge-base
// with the first existing of origin/main, main, origin/master, master, else HEAD~1.
function resolveBase(target, input) {
  if (input.base) return input.base;
  for (const ref of ["origin/main", "main", "origin/master", "master"]) {
    if (git(target, ["rev-parse", "--verify", "--quiet", ref]).ok) {
      const mb = git(target, ["merge-base", ref, "HEAD"]);
      if (mb.ok && mb.stdout.trim()) return mb.stdout.trim();
    }
  }
  return git(target, ["rev-parse", "--verify", "--quiet", "HEAD~1"]).ok ? "HEAD~1" : null;
}

// Path/keyword heuristics → a coarse risk score so the agent triages high-risk
// changes first (auth, crypto, value transfer, deserialization, exec, etc.).
const RISK_PATTERNS = [
  { re: /(auth|login|session|token|passwd|password|jwt|oauth|saml)/i, w: 5, tag: "auth" },
  { re: /(crypto|cipher|encrypt|decrypt|hash|hmac|signature|tls|ssl)/i, w: 5, tag: "crypto" },
  { re: /(payment|billing|charge|refund|wallet|transfer|balance|ledger)/i, w: 5, tag: "value-transfer" },
  { re: /(exec|spawn|shell|subprocess|eval|deserialize|pickle|unmarshal|yaml\.load)/i, w: 4, tag: "exec/deser" },
  { re: /(sql|query|db|database|orm)/i, w: 3, tag: "data-access" },
  { re: /(upload|file|path|fs\.|os\.)/i, w: 2, tag: "fs" },
  { re: /(cors|csrf|origin|header|cookie|middleware)/i, w: 3, tag: "web-guard" }
];

function riskScore(path, diffText) {
  const hay = `${path}\n${diffText}`;
  const tags = [];
  let score = 0;
  for (const p of RISK_PATTERNS) {
    if (p.re.test(hay)) { score += p.w; tags.push(p.tag); }
  }
  return { score, tags };
}

export function prepareDiffReview(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  if (!isGitRepo(resolvedTarget)) {
    throw new Error(`${resolvedTarget} is not a git repository — /diff-review needs git history`);
  }
  const base = resolveBase(resolvedTarget, input);
  if (!base) {
    throw new Error("could not resolve a base ref to diff against (no main/master and no HEAD~1). Pass --input '{\"base\":\"<ref>\"}'.");
  }
  const nameStatus = git(resolvedTarget, ["diff", "--name-status", `${base}...HEAD`]);
  if (!nameStatus.ok) throw new Error(`git diff failed: ${nameStatus.stderr.trim()}`);

  // Cached code-graph (if /code-graph has been run) → deterministic blast radius.
  const codeGraph = readJsonIfPresent(storeFor(resolvedTarget).codeGraphPath);

  const maxFiles = Number(input.maxFiles ?? 40);
  const entries = nameStatus.stdout.split(/\r?\n/).filter(Boolean).slice(0, maxFiles);
  const files = [];
  for (const line of entries) {
    const [status, ...rest] = line.split(/\t/);
    const path = rest[rest.length - 1];
    if (!path) continue;
    // Skip deletions (nothing to review) and obvious non-source noise.
    if (status.startsWith("D")) continue;
    const diff = git(resolvedTarget, ["diff", `${base}...HEAD`, "--", path]);
    const diffText = diff.ok ? diff.stdout.slice(0, 8000) : "";
    const { score, tags } = riskScore(path, diffText);
    files.push({ path, status, riskScore: score, riskTags: tags, diff: diffText, blastRadius: blastRadiusFor(codeGraph, path) });
  }
  files.sort((a, b) => b.riskScore - a.riskScore);

  const run = openRun(resolvedTarget, "diff-review");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    base, head: "HEAD", changedFileCount: files.length, files, input
  });

  return {
    ok: true,
    status: files.length ? "prepared" : "no-changes",
    target: resolvedTarget,
    base,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.diff-review.json"),
    changedFileCount: files.length,
    codeGraphPresent: Boolean(codeGraph),
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "diff-review-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("diff-review-prepare --target <path> [--input '{\"base\":\"origin/main\",\"maxFiles\":40}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("diff-review-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareDiffReview(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
