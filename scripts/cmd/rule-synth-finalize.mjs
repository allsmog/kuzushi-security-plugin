#!/usr/bin/env node
// Finalize phase for /rule-synth — the native, four-stage validation gate for
// synthesized CodeQL/Joern rules. Per rule: A compile, B fire-on-seed, C repo
// run, D precision cap. accept = A∧B∧C∧D. Accepted rules are copied into the
// digest-attested pack (.kuzushi/rules/{codeql,joern}/ + pack.json) and their new
// repo matches are promoted into findings.json as `candidate` leads (refId
// rule-synth:<id>). Rejected rules are recorded with a reason and NEVER persisted
// to the pack. The gate is native (spawnSync the CLIs) so the agent can't bypass it.

import { resolve, join, relative } from "node:path";
import { existsSync, readFileSync, copyFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";
import { writePack, digestBytes } from "../lib/rule-pack.mjs";
import { codeql, joern } from "../lib/rule-engines.mjs";

const EXT = { codeql: ".ql", joern: ".sc" };
const DEFAULT_CAPS = { maxMatches: 200, maxFileFraction: 0.25 };

function fail(message) {
  console.error(`rule-synth-finalize: ${message}`);
  process.exit(1);
}

// Pure verdict logic — testable without a real engine. Given the stage outcomes,
// decide accept/reject and the reason. `repoFileCount` is the repo's source-file
// count (for the density cap). Returns { accepted, stages, rejectionReason }.
export function gradeRule({ compile, seedMatch, repoMatches, repoFileCount, caps = DEFAULT_CAPS }) {
  const stages = { compile: "fail", seedMatch: "n/a", repoMatchCount: 0, precision: "n/a" };
  if (!compile?.ok) return { accepted: false, stages, rejectionReason: `compile: ${compile?.stderr?.slice(0, 200) || "did not compile"}` };
  stages.compile = "pass";

  if (!seedMatch?.ok || !seedMatch.matched) {
    stages.seedMatch = "fail";
    return { accepted: false, stages, rejectionReason: "seedMatch: rule did not fire on the known-vulnerable seed line" };
  }
  stages.seedMatch = "pass";

  const matches = repoMatches ?? [];
  stages.repoMatchCount = matches.length;
  const distinctFiles = new Set(matches.map((m) => m.file)).size;
  const fraction = repoFileCount > 0 ? distinctFiles / repoFileCount : 0;
  if (matches.length > caps.maxMatches || fraction > caps.maxFileFraction) {
    stages.precision = "fail";
    return { accepted: false, stages, rejectionReason: `precision: ${matches.length} matches across ${distinctFiles} files (cap ${caps.maxMatches} / ${Math.round(caps.maxFileFraction * 100)}% of files) — rule is too broad` };
  }
  stages.precision = "pass";
  return { accepted: true, stages, rejectionReason: null };
}

function engineFor(name) {
  return name === "codeql" ? codeql : name === "joern" ? joern : null;
}

function repoSourceFileCount(target) {
  // Cheap proxy for the density cap: the file count the latest context run saw.
  // 0 means "unknown" — the density cap then defers to the absolute match cap.
  const runsDir = join(resolve(target), ".kuzushi", "runs");
  if (!existsSync(runsDir)) return 0;
  try {
    let latest = null;
    for (const name of readdirSync(runsDir)) {
      if (!name.startsWith("host-context-")) continue;
      const ctx = join(runsDir, name, "context.json");
      if (existsSync(ctx)) { const m = statSync(ctx).mtimeMs; if (!latest || m > latest.m) latest = { ctx, m }; }
    }
    return latest ? Number(readJsonIfPresent(latest.ctx)?.inventory?.totalFiles ?? 0) : 0;
  } catch { return 0; }
}

export function finalizeRuleSynth(target, runDir, options = {}) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.rule-synth.json");
  if (!existsSync(draftPath)) fail(`no draft.rule-synth.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.rule-synth.json is not valid JSON"); }
  if (!Array.isArray(draft.rules)) fail("draft must have a rules[] array");

  const prep = readJsonIfPresent(join(resolvedRunDir, "prep.json"));
  const seedByFp = new Map((prep?.seeds ?? []).map((s) => [s.seedFingerprint, s]));
  const caps = { ...DEFAULT_CAPS, ...(options.caps ?? {}) };
  const repoFileCount = Number(prep?.repoFileCount ?? repoSourceFileCount(resolvedTarget));

  const records = [];
  const packEntries = [];
  const promoted = [];

  for (const r of draft.rules) {
    const id = r.ruleId ?? r.id;
    if (!id || !r.engine || !r.seedRef) fail(`a rule is missing ruleId/engine/seedRef`);
    const engine = engineFor(r.engine);
    if (!engine) fail(`rule ${id}: unknown engine "${r.engine}" (codeql|joern)`);
    const ruleFile = r.ruleFile ? (resolve(resolvedRunDir, r.ruleFile)) : null;
    if (!ruleFile || !existsSync(ruleFile)) fail(`rule ${id}: ruleFile not found (${r.ruleFile})`);
    const seed = seedByFp.get(r.seedRef) ?? { filePath: r.seedFile, startLine: r.seedLine, language: r.language };

    const avail = engine.available(resolvedTarget);
    if (!avail.available) {
      records.push({ ruleId: id, engine: r.engine, seedRef: r.seedRef, accepted: false, rejectionReason: `engine unavailable: ${avail.reason}` });
      continue;
    }

    const compile = engine.validate(ruleFile, resolvedTarget);
    let seedMatch = { ok: false, matched: false };
    let repo = { ok: false, matches: [] };
    if (compile.ok) {
      seedMatch = engine.selfMatch(ruleFile, resolvedTarget, seed);
      if (seedMatch.ok && seedMatch.matched) repo = engine.repoRun(ruleFile, resolvedTarget, seed);
    }
    const grade = gradeRule({ compile, seedMatch, repoMatches: repo.matches, repoFileCount, caps });

    const base = {
      ruleId: id, engine: r.engine, seedRef: r.seedRef, cwe: r.cwe ?? "", severity: r.severity ?? "",
      compile: grade.stages.compile, seedMatch: grade.stages.seedMatch,
      repoMatchCount: grade.stages.repoMatchCount, precision: grade.stages.precision,
      accepted: grade.accepted, rejectionReason: grade.rejectionReason
    };

    if (!grade.accepted) { records.push(base); continue; }

    // Persist the accepted rule into the pack + record its digest.
    const destDir = r.engine === "codeql" ? store.rulesCodeqlDir : store.rulesJoernDir;
    mkdirSync(destDir, { recursive: true });
    const destFile = join(destDir, `${id}${EXT[r.engine]}`);
    copyFileSync(ruleFile, destFile);
    const digest = digestBytes(readFileSync(destFile));
    const relFile = relative(resolvedTarget, destFile);
    packEntries.push({
      ruleId: id, engine: r.engine, language: seed.language ?? r.language ?? null, cwe: r.cwe ?? "", severity: r.severity ?? "",
      file: relFile, digest,
      provenance: { seedRef: r.seedRef, synthesizedRun: prep?.runId ?? null },
      validated: { compile: true, seedMatch: true, repoMatchCount: grade.stages.repoMatchCount, precision: true }
    });

    // Promote new repo matches (excluding the seed's own site) as candidate leads.
    for (const m of repo.matches) {
      promoted.push({
        source: "rule-synth", refId: `rule-synth:${id}`,
        title: `${r.title ?? id} @ ${m.file}:${m.line}`, severity: r.severity ?? "", cwe: r.cwe ?? "",
        verdict: "candidate", status: verdictToStatus("candidate"),
        evidence: [{ filePath: m.file, startLine: m.line }],
        rationale: `Matched synthesized ${r.engine} rule ${id} (seed ${r.seedRef}); rule validated: compiles, fires on the seed, ${grade.stages.repoMatchCount} repo matches.`,
        nextChecks: ["triage with /verify or /variant-hunt"]
      });
    }
    records.push({ ...base, file: relFile, digest });
  }

  if (packEntries.length) writePack(resolvedTarget, packEntries);
  const findingsDoc = promoted.length ? upsertFindings(resolvedTarget, promoted) : readJsonIfPresent(store.findingsPath);

  const summary = { synthesized: records.length, accepted: records.filter((r) => r.accepted).length, rejected: records.filter((r) => !r.accepted).length, promoted: promoted.length };
  const doc = { version: "1.0", generatedAt: new Date().toISOString(), target: resolvedTarget, rules: records, summary };
  atomicWrite(store.ruleSynthPath, `${JSON.stringify(doc, null, 2)}\n`);

  const run = openRun(resolvedTarget, "rule-synth-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget, summary,
    accepted: records.filter((r) => r.accepted).map((r) => r.ruleId),
    rejected: records.filter((r) => !r.accepted).map((r) => ({ ruleId: r.ruleId, reason: r.rejectionReason })),
    ruleSynthPath: store.ruleSynthPath, rulePackManifestPath: store.rulePackManifestPath,
    findingsPath: store.findingsPath, findingsSummary: findingsDoc?.summary ?? null
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("rule-synth-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeRuleSynth(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
