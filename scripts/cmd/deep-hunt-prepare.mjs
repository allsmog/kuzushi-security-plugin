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

// Existing findings (any producer) are the highest-value anchors — deep-hunt walks
// cross-file FROM a real lead, extending what /deep-scan, /taint, /authz, … already
// found. This is the generalizing seed: it rides the whole pipeline's recall instead of
// re-deriving entry/sink tokens. reviewed/noise/remediated are skipped.
function findingSeedAnchors(store) {
  const doc = readJsonIfPresent(store.findingsPath);
  if (!doc?.findings?.length) return [];
  const skip = new Set(["reviewed", "noise", "remediated"]);
  const out = [];
  for (const f of doc.findings) {
    if (skip.has(f.status)) continue;
    const ev = f.evidence?.[0];
    if (ev?.filePath) out.push({ kind: "finding", filePath: norm(ev.filePath), line: ev.startLine ?? 1, signal: `existing ${f.source ?? "?"} finding: ${String(f.title ?? "").slice(0, 80)}` });
  }
  return out;
}

export function prepareDeepHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const scopeDir = input.scopeDir ?? ".";
  const maxFiles = Number(input.maxFiles ?? 30);
  // The anchor budget must cover the risk-ranked files (the routing backbone) plus
  // headroom for finding/pattern anchors — otherwise file-seeded routing is squeezed
  // out by token-dense sink sites (the exact failure the eval caught on redis).
  const maxAnchors = Number(input.maxAnchors ?? (maxFiles + 16));
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

  // Anchor sources, in PRIORITY order (the principled, generalizing fix):
  //   (1) existing findings — walk cross-file from real leads (any producer);
  //   (2) the risk-ranked FILES as a routing backbone — so a bug on NO source/sink
  //       token (proto-pollution, logic, broken-tenant) still gets walked, and so
  //       deep-hunt inherits the file ranker's routing instead of re-introducing
  //       pattern-gating at the anchor level;
  //   (3) precise route/source/sink pattern anchors (specific start points + files
  //       beyond the ranked top-N).
  const findingAnchors = findingSeedAnchors(store);
  const fileAnchors = ranked.map((f) => ({
    kind: "file", filePath: f.filePath, line: 1,
    signal: `risk-ranked file: ${(f.reasons ?? []).slice(0, 3).join(", ") || "ranked"}`
  }));
  const patternAll = [
    ...routeAnchors,
    ...rgAnchors(resolvedTarget, scopeDir, SOURCE_RE, "source"),
    ...graphSources(store),
    ...rgAnchors(resolvedTarget, scopeDir, SINK_RE, "sink")
  ].map((a) => ({ ...a, rank: fileScore.get(a.filePath) ?? 0 }));
  // Keep sources and sinks both represented (interleave by file risk) so a sink-heavy
  // repo still surfaces its entries.
  const byRank = (a, b) => b.rank - a.rank || a.filePath.localeCompare(b.filePath) || a.line - b.line;
  const pSources = patternAll.filter((a) => a.kind === "source").sort(byRank);
  const pSinks = patternAll.filter((a) => a.kind === "sink").sort(byRank);
  const interleaved = [];
  for (let i = 0; i < Math.max(pSources.length, pSinks.length); i += 1) {
    if (i < pSources.length) interleaved.push(pSources[i]);
    if (i < pSinks.length) interleaved.push(pSinks[i]);
  }

  // Priority-ordered pool → dedup by file:line → cap at the budget. Findings and the
  // ranked-file backbone come first so routing is guaranteed; patterns fill the rest.
  const ordered = [...findingAnchors, ...fileAnchors, ...interleaved];
  // Dedup by file:line, keeping the first slot (so the findings/file-backbone keep
  // their early, routing-guaranteed positions) but UPGRADING a generic "file" slot to
  // a specific source/sink/finding anchor when one lands on the same line.
  const slot = new Map();
  const order = [];
  for (const a of ordered) {
    const k = `${a.filePath}:${a.line}`;
    const cur = slot.get(k);
    if (!cur) { slot.set(k, a); order.push(k); }
    else if (cur.kind === "file" && a.kind !== "file") slot.set(k, a);
  }
  const deduped = order.map((k) => slot.get(k));
  const chosen = deduped.slice(0, maxAnchors);

  // Attach the enclosing function to source/sink/finding anchors — the agent's starting
  // context. A "file" anchor has no specific line, so the agent reads the whole file
  // (deep-scan style) to locate the source/sink, then walks from there.
  const anchors = chosen.map((a) => {
    const fn = a.kind === "file" ? null : enclosingFunction(resolvedTarget, a.filePath, a.line);
    return {
      kind: a.kind, filePath: a.filePath, line: a.line, signal: a.signal,
      enclosingFunction: fn ? { name: fn.name, startLine: fn.startLine, endLine: fn.endLine } : null
    };
  });
  const unanchoredCount = Math.max(0, deduped.length - anchors.length);

  const cg = readJsonIfPresent(store.codeGraphPath);
  const cmdDir = import.meta.dirname ?? resolve(".");
  const run = openRun(resolvedTarget, "deep-hunt");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget, scopeDir,
    references: artifactSnapshot(resolvedTarget),
    budget: { maxAnchors, maxHops, rounds, maxFiles },
    anchorCount: anchors.length,
    byKind: anchors.reduce((acc, a) => { acc[a.kind] = (acc[a.kind] ?? 0) + 1; return acc; }, {}),
    // honest: candidate anchors found but not handed to the agent this run
    unanchoredCount,
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
    anchorCount: anchors.length, unanchoredCount,
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
