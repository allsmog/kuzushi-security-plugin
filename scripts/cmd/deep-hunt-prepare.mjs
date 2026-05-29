#!/usr/bin/env node
// Prepare phase for /deep-hunt — the interprocedural, hypothesis-driven hunt.
//
// /deep-scan reads whole files; /taint-analysis traces labeled source→sink. This is
// the third recall lever: it ranks TRACE ANCHORS (where untrusted input enters and
// where dangerous operations happen), hands the deep-hunter agent each anchor's
// enclosing function plus the forward/backward call-graph CLIs, and lets it WALK a
// flow across files over multiple rounds — pursuing a hypothesis, not pattern-matching
// one line. Deterministic here: same repo + artifacts → same ranked anchor list.
//
// Anchors are textual hints (an entry-point/sink site); the agent confirms the actual
// flow by reading each hop. Budget-bounded and honest about the un-anchored remainder.

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, buildGlobs } from "../lib/ripgrep.mjs";
import { rankFiles } from "../lib/risk-rank.mjs";
import { enclosingFunction } from "../lib/callgraph.mjs";
import { extractRoutes } from "../lib/routes.mjs";
import { buildCodeGraph } from "./code-graph-build.mjs";

const norm = (p) => String(p ?? "").replace(/^\.\//, "");

// Where untrusted input ENTERS (path origins). Framework routes, command handlers,
// lambda/CLI entry, and direct request/argv/stream access.
const SOURCE_RE = "@(app|router)\\.(get|post|put|delete|patch|use)|@(Get|Post|Put|Delete|Patch|Request)Mapping|\\b(app|router|fastify)\\.(get|post|put|delete|patch|use)\\s*\\(|\\w+Command\\s*\\(|exports\\.handler|def\\s+\\w+\\(\\s*(self,\\s*)?request|func\\s+\\w+\\(\\w+\\s+http\\.|req\\.(body|query|params|headers|cookies)|request\\.(GET|POST|args|form|json|data)|process\\.argv|os\\.Args|getParameter|getInputStream|System\\.in";

// Dangerous OPERATIONS (path destinations). Injection/exec/deser/file/template/native.
// NOTE: each alternative carries its own boundaries — do NOT wrap the whole group in
// \b(...)\b, since alternatives ending in "(" (e.g. `.query(`) have no trailing word
// boundary and the wrap would silently fail to match them.
const SINK_RE = "\\b(system|popen|execve?|execl[ep]?|spawnSync|spawn|fork|Runtime|ProcessBuilder|eval)\\s*\\(|os\\.system|subprocess\\.|child_process|new Function|vm\\.runIn|pickle\\.loads?|yaml\\.(load|unsafe_load)|marshal\\.loads|ObjectInputStream|readObject|XMLDecoder|unserialize|deserialize|\\.(query|execute|raw|exec)\\s*\\(|executeQuery|createStatement|prepareStatement|innerHTML|dangerouslySetInnerHTML|document\\.write|sendFile|sendfile|readFileSync|readFile|createReadStream|fopen|memcpy|memmove|strcpy|strcat|sprintf|\\bgets\\s*\\(|alloca";

function rgAnchors(target, scopeDir, pattern, kind) {
  const r = runRg(target, ["--json", "-n", "-S", "--max-count", "8", "-e", pattern, ...buildGlobs(), scopeDir === "." ? "." : scopeDir]);
  if (!r.ok) return [];
  const out = [];
  const seen = new Set();
  for (const h of parseJsonMatches(r.stdout, 5000)) {
    const filePath = norm(h.filePath);
    if (!filePath) continue;
    const key = `${filePath}:${h.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ kind, filePath, line: h.line ?? 1, signal: (h.text ?? "").trim().slice(0, 160) });
  }
  return out;
}

// Entry points the regex misses but the graph/x-ray know about (dispatch tables, etc.).
function graphSources(store) {
  const out = [];
  const cg = readJsonIfPresent(store.codeGraphPath);
  for (const e of cg?.entryPoints ?? []) if (e?.filePath) out.push({ kind: "source", filePath: norm(e.filePath), line: e.line ?? 1, signal: `entry-point (${e.kind ?? "graph"})` });
  const xr = readJsonIfPresent(`${store.xRayDir}/entry-points.json`);
  for (const e of Array.isArray(xr) ? xr : []) if (e?.filePath) out.push({ kind: "source", filePath: norm(e.filePath), line: e.line ?? 1, signal: `entry-point (${e.kind ?? e.id ?? "x-ray"})` });
  return out;
}

export function prepareDeepHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const scopeDir = input.scopeDir ?? ".";
  const maxFiles = Number(input.maxFiles ?? 30);
  const maxAnchors = Number(input.maxAnchors ?? Math.min(40, Math.max(12, maxFiles)));
  const maxHops = Number(input.maxHops ?? 4);
  const rounds = Number(input.rounds ?? 2);

  // Reachability ranking + the agent's cross-file walk both want a code-graph; build
  // it cheaply if absent (ripgrep heuristic, or a Joern CPG if one already exists).
  if (input.buildCodeGraph !== false && !existsSync(store.codeGraphPath)) {
    try { buildCodeGraph(resolvedTarget, {}); } catch { /* ranking/anchoring degrade, not fatal */ }
  }

  // Rank files so anchors in high-risk files (entry surface, blast radius, churn,
  // parsers) come first — the same signal /deep-scan uses.
  const { ranked } = rankFiles(resolvedTarget, { maxFiles, scopeDir });
  const fileScore = new Map(ranked.map((f) => [f.filePath, f.score]));

  // Framework routes are first-class source anchors — the handlers a generic
  // entry-def regex misses (Express/Flask/FastAPI/Django/Spring/Go + OpenAPI). Each
  // carries its METHOD routePath so the agent knows the exact attacker surface.
  const routeAnchors = extractRoutes(resolvedTarget, { scopeDir }).map((r) => ({
    kind: "source", filePath: r.filePath, line: r.line,
    signal: `route ${r.method} ${r.routePath} (${r.framework})`
  }));

  // Collect candidate anchors, prioritize those in risk-ranked files, then cap.
  const all = [
    ...routeAnchors,
    ...rgAnchors(resolvedTarget, scopeDir, SOURCE_RE, "source"),
    ...graphSources(store),
    ...rgAnchors(resolvedTarget, scopeDir, SINK_RE, "sink")
  ];
  // Dedupe across the two source streams by file:line:kind.
  const dedup = new Map();
  for (const a of all) dedup.set(`${a.kind}:${a.filePath}:${a.line}`, a);
  const candidates = [...dedup.values()].map((a) => ({ ...a, rank: fileScore.get(a.filePath) ?? 0 }));
  // Highest-risk file first; keep sources and sinks both represented by sorting
  // within kind and interleaving so a sink-heavy repo still surfaces its entries.
  candidates.sort((a, b) => b.rank - a.rank || a.filePath.localeCompare(b.filePath) || a.line - b.line);
  const sources = candidates.filter((a) => a.kind === "source");
  const sinks = candidates.filter((a) => a.kind === "sink");
  const half = Math.ceil(maxAnchors / 2);
  const chosen = [...sources.slice(0, half), ...sinks.slice(0, maxAnchors - Math.min(half, sources.length))]
    .slice(0, maxAnchors);

  // Attach the enclosing function (name + range) to each chosen anchor — the agent's
  // starting context and the unit it walks out of. Uses the new forward primitive.
  const anchors = chosen.map((a) => {
    const fn = enclosingFunction(resolvedTarget, a.filePath, a.line);
    return {
      kind: a.kind, filePath: a.filePath, line: a.line, signal: a.signal,
      enclosingFunction: fn ? { name: fn.name, startLine: fn.startLine, endLine: fn.endLine } : null
    };
  });

  const cg = readJsonIfPresent(store.codeGraphPath);
  const cmdDir = import.meta.dirname ?? resolve(".");
  const run = openRun(resolvedTarget, "deep-hunt");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget, scopeDir,
    references: artifactSnapshot(resolvedTarget),
    budget: { maxAnchors, maxHops, rounds },
    anchorCount: anchors.length,
    sourceCount: anchors.filter((a) => a.kind === "source").length,
    sinkCount: anchors.filter((a) => a.kind === "sink").length,
    // honest: candidate anchors found but not handed to the agent this run
    unanchoredCount: Math.max(0, candidates.length - anchors.length),
    anchors,
    reachability: {
      calleesCli: join(cmdDir, "callees.mjs"),
      callersCli: join(cmdDir, "callers.mjs"),
      cpgPresent: Boolean(cg?.summary?.topSymbol) || existsSync(store.joernCpgPath)
    },
    input
  });

  return {
    ok: true,
    status: anchors.length ? "prepared" : "no-anchors",
    target: resolvedTarget, runId: run.runId, runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.deep-hunt.json"),
    anchorCount: anchors.length, unanchoredCount: Math.max(0, candidates.length - anchors.length),
    assembleCommand: `node "${join(cmdDir, "deep-hunt-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('deep-hunt-prepare --target <path> [--input \'{"maxAnchors":24,"maxHops":4,"scopeDir":"src"}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) { console.error("deep-hunt-prepare: --target is required"); process.exit(1); }
  emitResult(prepareDeepHunt(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
