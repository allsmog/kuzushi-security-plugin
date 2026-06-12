#!/usr/bin/env node
// Prepare phase for /deep-scan — the whole-file deep reader.
//
// Every other producer is pattern-gated: it greps for known-dangerous shapes, so a
// bug that doesn't match a pattern is never surfaced (the recall ceiling). /deep-scan
// removes that gate. It picks the highest-risk files (within a token budget) and
// hands the deep-scanner agent the *files themselves* to read in full and reason
// about from first principles — the way a human auditor finds the bugs scanners miss.
// Deterministic here: same repo + artifacts → same ranked file list. No reasoning.

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { rankFiles } from "../lib/risk-rank.mjs";
import { languageOf } from "../lib/sharding.mjs";
import { extractObligations } from "../lib/sink-obligations.mjs";
import { rankObligations } from "../lib/obligation-routing.mjs";
import { buildObligationLedgerFromDeepScanPrep, writeObligationLedger } from "../lib/obligation-ledger.mjs";
import { buildObligationSlicesFromDeepScanPrep, writeObligationSlices } from "../lib/obligation-slices.mjs";
import { buildScopedCpg, runJoernQuery, joernAvailable } from "../lib/scoped-cpg.mjs";
import { buildCodeGraph } from "./code-graph-build.mjs";

const JOERN_PACK = resolve(import.meta.dirname ?? ".", "..", "..", "packs", "starter", "joern");
const NATIVE_RE = /\.(c|cc|cpp|cxx|h|hpp|m|mm|rs)$/i;
const INPUT_PROC_RE = /(pars(e|er)|lex|tokeniz|scanner|decode|deserial|unmarshal|unpack|inflate|\bvm\b|interp|bytecode|codec|reader|loader|protocol)/i;

// Pick the memory-relevant subsystem directories that fell BELOW the file-read budget — the
// long tail where a cross-function memory bug (the redis Lua int-overflow at rank #169) hides
// from file-routing. Rank dirs by INTERPRETER/PARSER density (INPUT_PROC files: lexer, parser,
// vm, decoder), NOT raw native count — memory bugs concentrate in those subsystems, and they're
// small enough to CPG lightly. Ranking by native count alone picks the giant catch-all `src/`
// (heavy and bug-sparse) and buries the vendored interpreter where the bug actually lives.
// `maxDirFiles` skips a dir too big to scope a *light* CPG over.
function memorySubsystemDirs(rankedFull, maxFiles, cap, { maxDirFiles = 150 } = {}) {
  const inputCount = new Map();   // dir -> # interpreter/parser files below budget
  const nativeCount = new Map();  // dir -> # native files below budget
  const totalCount = new Map();   // dir -> total files seen (for the lightness cap)
  for (let idx = 0; idx < rankedFull.length; idx += 1) {
    const f = rankedFull[idx].filePath;
    const dir = f.includes("/") ? f.slice(0, f.lastIndexOf("/")) : ".";
    totalCount.set(dir, (totalCount.get(dir) ?? 0) + 1);
    if (idx < maxFiles) continue;                     // already covered by the file lane
    if (INPUT_PROC_RE.test(f)) inputCount.set(dir, (inputCount.get(dir) ?? 0) + 1);
    else if (NATIVE_RE.test(f)) nativeCount.set(dir, (nativeCount.get(dir) ?? 0) + 1);
  }
  const dirs = new Set([...inputCount.keys(), ...nativeCount.keys()]);
  const scored = [...dirs]
    .filter((d) => (totalCount.get(d) ?? 0) <= maxDirFiles)        // keep the CPG light
    .map((d) => ({ d, input: inputCount.get(d) ?? 0, native: nativeCount.get(d) ?? 0 }))
    .filter((x) => x.input > 0 || x.native > 0)
    // Interpreter/parser DENSITY is strictly primary — a dir with 6 lexer/parser/vm files
    // (deps/lua/src) must beat a 2-parser, 189-other dir (src), so native count is only a
    // tiebreak, never additive (additive let the giant catch-all dir win).
    .sort((a, b) => b.input - a.input || b.native - a.native || a.d.localeCompare(b.d));
  return scored.slice(0, cap).map((x) => x.d);
}

// Discovery lenses (Lever 4): a closed taxonomy of bug-class viewpoints. One reading
// collapses these into a blur and the subtle class gets skipped; naming them lets the
// agent make a DISTINCT pass per lens and lets a completeness critic name the lens it
// never checked. Each lens maps to the obligation `kind`s it owns so an opt-in ensemble
// (`--input '{"lens":"lifetime"}'`) can focus a job without re-reading for everything.
export const LENSES = {
  memory: ["fixed-size-buffer", "raw-copy", "alloc-arith", "gc-rooting"],
  lifetime: ["lifetime-free", "gc-rooting"],
  arithmetic: ["int-overflow-size", "alloc-arith"],
  injection: ["command-exec", "sql-sink", "dynamic-eval", "deserialization", "path-fs", "ssrf", "template-xss"],
  authz: ["object-authz", "authz-decision", "open-redirect"],
  concurrency: [] // no static obligation kind yet — carried so the critic still names it
};

export function prepareDeepScan(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxFiles = Number(input.maxFiles ?? 30);
  const scopeDir = input.scopeDir ?? ".";

  // Reachability-driven ranking needs a code-graph. Build/refresh it first (cheap
  // ripgrep heuristic; uses a Joern CPG automatically if one exists) unless one is
  // already present and the caller opted out. This is what lets risk-rank prioritize
  // high-blast-radius core files over keyword matches.
  const store = storeFor(resolvedTarget);
  if (input.buildCodeGraph !== false && !existsSync(store.codeGraphPath)) {
    try { buildCodeGraph(resolvedTarget, {}); } catch { /* ranking degrades to keyword/churn */ }
  }

  // Explicit focus: when the caller names specific files, deep-read exactly those
  // (skip ranking). Useful to drill into a subsystem — and to isolate the
  // breadth-vs-depth variable in eval (read one file deeply, not 30 shallowly).
  let ranked;
  let totalCandidates;
  let unread;
  let rankedFull = [];
  if (Array.isArray(input.files) && input.files.length) {
    ranked = input.files.map((f) => ({ filePath: String(f).replace(/^\.\//, ""), language: languageOf(String(f)), score: null, reasons: ["explicit-focus"] }));
    totalCandidates = ranked.length;
    unread = 0;
  } else {
    // Get the FULL ranking so the discovery-time CPG pass can target memory subsystems in the
    // tail (below the read budget); the file lane still reads only the top `maxFiles`.
    const full = rankFiles(resolvedTarget, { maxFiles: Number.MAX_SAFE_INTEGER, scopeDir });
    rankedFull = full.ranked;
    ranked = rankedFull.slice(0, maxFiles);
    totalCandidates = full.totalCandidates;
    unread = Math.max(0, totalCandidates - ranked.length);
  }

  // Attach sink obligations per file (AIxCC-style): a finite checklist of dangerous
  // primitives the agent must discharge, instead of hoping it spots them while
  // free-reading. Native files yield memory obligations (buffers, copies, lifetime,
  // overflow); web/managed files yield injection/authz/logic obligations (command-exec,
  // sql, deser, path, ssrf, xss, object-authz, …). Files in neither family get [].
  // Optional lens focus (Lever 4 ensemble): when set, keep only the obligations this lens
  // owns so a job reads for ONE class deeply. Unset (default) = all classes, one pass —
  // no extra spend unless the caller opts into an ensemble.
  const lens = typeof input.lens === "string" && LENSES[input.lens] ? input.lens : null;
  const lensKinds = lens ? new Set(LENSES[lens]) : null;

  let obligationCount = 0;
  if (input.obligations !== false) {
    for (const f of ranked) {
      let obs = extractObligations(resolvedTarget, f.filePath);
      if (lensKinds) obs = obs.filter((o) => lensKinds.has(o.kind));
      f.obligations = obs;
      obligationCount += f.obligations.length;
    }
  }

  // Cost control is the FILE budget (maxFiles) + function-scoped discharge (the agent
  // pulls each obligation's enclosing function via tree_sitter:node_at, not the whole
  // file). The per-file `obligations` list is the checklist the agent works for each
  // file it reads — it is even-sampled so a dangerous site deep in a long file (e.g.
  // redis t_stream.c's xackdel buffer at L3538) survives. We deliberately do NOT
  // collapse to a global top-K: a file with many sites (t_stream.c) would lose its one
  // vulnerable site to higher-ranked files' noise.

  // Obligation overlay (roadmap Phase 1): a discharge worklist of dangerous SITES in files
  // ranked BELOW the file-read budget — pure additive long-tail coverage that file-routing
  // misses, without losing a Tier-1 win (the top `maxFiles` are still read by the file lane).
  // Opt-in (cost): only when input.byObligation. Caveat (measured): this delivers LOCAL,
  // intraprocedural obligations; cross-function lifetime bugs (a free inside a callee) are
  // not regex-detectable and belong to the CPG dataflow queries / execution lane, not here.
  let obligationOverlay = null;
  if (input.byObligation) {
    try {
      obligationOverlay = rankObligations(resolvedTarget, {
        scopeDir,
        maxObligations: Number(input.maxObligations ?? 60),
        excludeTopFiles: maxFiles
      });
    } catch { /* overlay is best-effort; the file lane still runs */ }
  }

  // Discovery-time scoped-CPG memory pass (the routing-INDEPENDENT lane at discovery, not just
  // verify): scope a light CPG to each memory subsystem that fell below the read budget, run the
  // interprocedural memory queries, and hand the agent the source→sink flows as leads. This is
  // what reaches the redis Lua int-overflow (lbaselib #169, never in the top-30 read set): the
  // CPG surfaces its 345→349 flow regardless of file rank, and the agent discharges it. Opt-in
  // + joern-gated + bounded (few dirs, deduped, capped). Leads, not auto-promoted findings — the
  // agent and /verify keep precision.
  let cpgLeads = null;
  if (input.cpgMemory && joernAvailable() && rankedFull.length) {
    const dirs = memorySubsystemDirs(rankedFull, maxFiles, Number(input.maxCpgDirs ?? 2));
    const seen = new Set();
    const leads = [];
    for (const dir of dirs) {
      const built = buildScopedCpg(resolvedTarget, { scopeDir: dir });
      if (!built.ok) continue;
      for (const q of ["integer-overflow.sc", "use-after-free.sc"]) {
        const res = runJoernQuery(built.cpgPath, join(JOERN_PACK, q));
        for (const fl of res.flows ?? []) {
          const key = `${dir}/${fl.filePath}:${fl.sinkLine}`;
          if (seen.has(key)) continue;
          seen.add(key);
          leads.push({ cwe: fl.cwe, scopeDir: dir, filePath: fl.filePath, sourceLine: fl.sourceLine, sinkLine: fl.sinkLine });
        }
      }
    }
    cpgLeads = leads.slice(0, Number(input.maxCpgLeads ?? 30));
  }

  const run = openRun(resolvedTarget, "deep-scan");
  const obligationSlicesPath = join(store.slicesDir, `${run.runId}-obligation-slices.json`);
  const prepDoc = {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    scopeDir,
    references: artifactSnapshot(resolvedTarget),
    budget: { maxFiles },
    totalCandidates,
    unreadCount: unread,          // honest: how many in-scope files were NOT read
    fileCount: ranked.length,
    obligationCount,              // sink sites the agent must discharge (per file)
    lens,                         // the focused lens, or null for an all-class pass
    lenses: Object.keys(LENSES),  // the closed lens taxonomy the completeness critic checks against
    files: ranked,                // [{ filePath, language, score, reasons[], obligations[] }]
    obligationOverlay,            // Phase 1: sub-budget-file obligation worklist, or null
    cpgLeads,                     // discovery-time scoped-CPG memory flows (leads), or null
    obligationSlicesPath,         // Phase 2: function-scoped excerpts for each obligation/lead
    obligationSlicesRunPath: join(run.runDir, "obligation-slices.json"),
    input
  };
  run.writeJson("prep.json", prepDoc);
  const ledgerResult = writeObligationLedger(
    resolvedTarget,
    buildObligationLedgerFromDeepScanPrep(prepDoc)
  );
  const slicesResult = writeObligationSlices(
    resolvedTarget,
    run.runDir,
    run.runId,
    buildObligationSlicesFromDeepScanPrep(prepDoc, { maxLines: Number(input.maxSliceLines ?? 80) })
  );

  return {
    ok: true,
    status: ranked.length ? "prepared" : "no-files",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.deep-scan.json"),
    obligationLedgerPath: ledgerResult.ledgerPath,
    obligationsJsonlPath: ledgerResult.jsonlPath,
    obligationSlicesPath: slicesResult.globalPath,
    obligationSlicesRunPath: slicesResult.runPath,
    obligationSliceCount: slicesResult.sliceCount,
    fileCount: ranked.length,
    unreadCount: unread,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "deep-scan-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('deep-scan-prepare --target <path> [--input \'{"maxFiles":25,"scopeDir":"src"}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("deep-scan-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareDeepScan(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
