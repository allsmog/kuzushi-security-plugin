// Risk-ranking for the /deep-scan reader. The deep reader is token-expensive, so
// instead of reading every file we read the highest-risk files first within a
// budget. Ranking signals (all already produced elsewhere in the pipeline):
//   • entry points        — x-ray / code-graph (attacker-reachable surface)
//   • trust boundaries    — deep-context.json (where untrusted meets trusted)
//   • high caller-count   — code-graph symbols (blast radius)
//   • recently changed    — git (fresh bugs cluster in churn)
//   • security-relevant   — path/name heuristic (auth, pay, query, exec, …)
// Deterministic given the same repo + artifacts, so a deep sweep is reproducible.
// CRITICAL: this RANKS, it never silently drops — callers report the unread tail.

import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { readJsonIfPresent, storeFor } from "./artifact-store.mjs";
import { inventory, languageOf } from "./sharding.mjs";
import { runRg, parseJsonMatches, buildGlobs } from "./ripgrep.mjs";
import { routeFiles } from "./routes.mjs";
import { dispatchHandlerFiles } from "./dispatch.mjs";

// Files that DEFINE request/command entry points — the attacker-reachable surface.
// This is the reachability signal that call-count misses: a command handler or HTTP
// route is dispatched (table / framework), so it has few inbound C calls, yet it is
// exactly where untrusted input enters. Catches redis `*Command(`, web routes,
// lambda handlers, `main`, etc. Returns Map(file -> entryPointCount).
const ENTRY_DEF = "\\w+Command\\s*\\(|@app\\.(route|get|post|put|delete|patch)|@(Get|Post|Put|Delete|Patch|Request)Mapping|app\\.(get|post|put|delete|patch|use)\\s*\\(|router\\.(get|post|put|delete|patch)\\s*\\(|exports\\.handler|def\\s+\\w+\\(\\s*request|func\\s+\\w+\\(\\s*\\w+\\s+http\\.|int\\s+main\\s*\\(|fastify\\.(get|post)";
function entryPointDefFiles(target, scopeDir) {
  const counts = new Map();
  const r = runRg(target, ["--json", "-n", "-e", ENTRY_DEF, ...buildGlobs(), scopeDir === "." ? "." : scopeDir]);
  if (!r.ok) return counts;
  for (const hit of parseJsonMatches(r.stdout, 20000)) {
    const f = norm(hit.filePath);
    counts.set(f, (counts.get(f) ?? 0) + 1);
  }
  return counts;
}

const SECURITY_HINT = /(auth|login|logout|session|token|password|passwd|cred|secret|crypto|cipher|hash|jwt|oauth|saml|admin|payment|billing|charge|checkout|order|invoice|upload|download|exec|command|shell|spawn|query|\bsql\b|database|\bdb\b|deserial|pickle|yaml|xml|template|render|redirect|cors|csrf|permission|role|\bacl\b|tenant|account|\buser\b|route|controller|handler|middleware|validate|sanitiz|escape|webhook|ingest|parse)/i;

// Input-processing files are a top attacker-data surface, but they're reached through
// library/C-API calls (lua parser, deserializers, codecs), so neither entry-point
// density NOR inbound-call-count ranks them — yet they're exactly where the deep,
// long-lived memory bugs live (e.g. the Redis Lua parser GC-UAF). Give these a real
// weight so a reachability-driven ranker doesn't drop them for first-party handlers.
const INPUT_PROC = /(pars(e|er)|lex(er)?|tokeniz|scanner|decode|decoder|deserial|unmarshal|unpack|inflate|unzip|\bvm\b|interp|bytecode|codec|reader|loader|protocol)/i;

function entryPointFiles(store) {
  const set = new Set();
  const ep = readJsonIfPresent(`${store.xRayDir}/entry-points.json`);
  for (const e of Array.isArray(ep) ? ep : []) if (e?.filePath) set.add(norm(e.filePath));
  const cg = readJsonIfPresent(store.codeGraphPath);
  for (const e of cg?.entryPoints ?? []) if (e?.filePath) set.add(norm(e.filePath));
  return set;
}

function trustBoundaryFiles(store) {
  const set = new Set();
  const dc = readJsonIfPresent(store.deepContextPath);
  for (const b of dc?.trustBoundaries ?? []) if (b?.filePath) set.add(norm(b.filePath));
  for (const e of dc?.entryPoints ?? []) if (e?.filePath) set.add(norm(e.filePath));
  return set;
}

// Dataflow-reachability signal (Lever 5 — the MEASURED, gated form; NOT sink-density,
// which the eval proved a false win). A file that is an endpoint of a real source→sink
// flow already discovered by a FLOW producer (taint-analysis / deep-hunt / chain) is, by
// construction, reachable with attacker data — the strongest routing signal there is. This
// is the closed feedback loop the roadmap's L5 left open: a confirmed/candidate flow feeds
// back into which files the deep reader prioritizes next.
//
// Why it can't be a false win on the corpus: it reads ONLY persisted flow findings. The
// candidate-recall bench runs prepare-only with no findings.json, so the signal is inert
// there (0 boost) — it cannot displace correct routing (the live-recall gate proves this).
// It earns its weight on re-runs / sweeps where a flow producer already ran. We deliberately
// exclude `deep-scan`'s own findings (that would be self-reinforcing) — only true dataflow
// paths count.
const FLOW_SOURCES = new Set(["taint-analysis", "deep-hunt", "chain"]);
const ACTIONABLE_STATUS = new Set(["open", "confirmed", "proven", "needs-evidence", "needs-trace", "candidate"]);
function dataflowReachFiles(store) {
  const set = new Set();
  const doc = readJsonIfPresent(store.findingsPath);
  for (const f of doc?.findings ?? []) {
    if (!FLOW_SOURCES.has(String(f.source ?? ""))) continue;
    if (f.status && !ACTIONABLE_STATUS.has(String(f.status))) continue;
    for (const e of f.evidence ?? []) if (e?.filePath) set.add(norm(e.filePath));
    for (const n of f.evidenceGraph?.nodes ?? []) if (n?.filePath) set.add(norm(n.filePath));
  }
  return set;
}

// file -> total inbound calls to the functions it defines (blast-radius / reachability
// proxy). SUM, not max: a core file full of heavily-called functions is where bugs
// reach the most code. This is the dominant ranking signal when a code-graph exists —
// it's what makes a file like redis's t_stream.c rank without a keyword match.
function callerWeight(store) {
  const cg = readJsonIfPresent(store.codeGraphPath);
  const byFile = new Map();
  for (const s of cg?.symbols ?? []) {
    if (!s?.file) continue;
    const f = norm(s.file);
    byFile.set(f, (byFile.get(f) ?? 0) + (Number(s.callerCount) || 0));
  }
  return byFile;
}

// Compress a raw inbound-call sum into a bounded reachability score (0..8) so one
// giant file can't dominate everything, but high-reachability files clearly outrank
// keyword-only hits. log2-ish bands.
function reachScore(sum) {
  if (sum <= 0) return 0;
  return Math.min(8, Math.round(Math.log2(sum + 1) * 1.6));
}

function recentlyChanged(target, limit = 80) {
  const set = new Set();
  try {
    const r = spawnSync("git", ["-C", target, "log", "--name-only", "--pretty=format:", "-n", "60"], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    if (r.status === 0) {
      for (const line of `${r.stdout}`.split(/\r?\n/)) {
        const f = line.trim();
        if (f && set.size < limit) set.add(norm(f));
      }
    }
  } catch { /* not a git repo — skip this signal */ }
  return set;
}

function norm(p) {
  return String(p ?? "").replace(/^\.\//, "");
}

function inScope(file, scopeDir) {
  if (!scopeDir || scopeDir === ".") return true;
  return file === scopeDir || file.startsWith(`${scopeDir}/`);
}

// Returns { ranked: [{filePath, language, score, reasons[]}], totalCandidates, budget }
export function rankFiles(target, { maxFiles = 25, scopeDir = "." } = {}) {
  const store = storeFor(target);
  const files = inventory(target).files.filter((f) => inScope(f, scopeDir));
  const entries = entryPointFiles(store);
  const boundaries = trustBoundaryFiles(store);
  const callers = callerWeight(store);
  const changed = recentlyChanged(target);
  const entryDefs = entryPointDefFiles(target, scopeDir);
  // Files that declare framework routes / OpenAPI endpoints — attacker-reachable
  // surface that the generic entry-def regex misses (L4). Best-effort; empty if rg
  // is unavailable.
  const routes = (() => { try { return routeFiles(target, { scopeDir }); } catch { return new Set(); } })();
  // Files that DEFINE a dispatch-registered handler (command table, vtable, registry, or a
  // convention-named *Command/*Handler whose table is generated). These are the real
  // attacker entry points that call-count reachability scores ~0 (no inbound call edge) —
  // the exact blind spot that buried redis t_stream.c under a vendored RESP parser.
  const dispatch = (() => { try { return dispatchHandlerFiles(target, { scopeDir }); } catch { return new Set(); } })();
  // Files a real source→sink flow already reached (closed feedback loop). Empty on a
  // first/prepare-only run, so it never displaces routing where there's no flow evidence.
  const dataflowReach = dataflowReachFiles(store);

  const scored = files.map((file) => {
    const reasons = [];
    let score = 0;
    // (1) Attacker-reachable surface: files defining request/command entry points.
    // The strongest signal — it's where untrusted input enters — and it catches the
    // dispatch-table handlers (redis `*Command`) that call-count ranking misses.
    const ed = entryDefs.get(file) ?? 0;
    if (ed > 0) { score += Math.min(7, 3 + ed); reasons.push(`entry-defs=${ed}`); }
    // (2) Blast radius: inbound calls to the file's functions (reach), bounded.
    const cw = callers.get(file) ?? 0;
    const rs = reachScore(cw);
    if (rs > 0) { score += rs; reasons.push(`reach=${cw}`); }
    if (entries.has(file)) { score += 4; reasons.push("entry-point"); }
    if (routes.has(file)) { score += 4; reasons.push("framework-route"); }
    // Strong: a dispatch handler IS the attacker entry point. Weighted above input-processor
    // (+5) so a real command handler outranks a file that merely matches a "parser" keyword
    // (a vendored RESP reader). Additive — a handler that also has callers still wins.
    if (dispatch.has(file)) { score += 6; reasons.push("dispatch-entry"); }
    if (boundaries.has(file)) { score += 3; reasons.push("trust-boundary"); }
    // A real source→sink flow already reached this file — earned, strong, additive. Weighted
    // at +5 (peer of input-processor): a proven-reachable file should outrank a keyword guess
    // but not blindly beat a fresh attacker-surface entry point.
    if (dataflowReach.has(file)) { score += 5; reasons.push("dataflow-reach"); }
    if (changed.has(file)) { score += 2; reasons.push("recently-changed"); }
    // Input-processing surface (parser/decoder/deserializer/VM): real weight — these
    // are reached via APIs, not entry-point defs, but are prime memory-bug surfaces.
    if (INPUT_PROC.test(file)) { score += 5; reasons.push("input-processor"); }
    // Generic keyword path hint stays a weak tiebreak.
    if (SECURITY_HINT.test(file)) { score += 1; reasons.push("security-relevant-path"); }
    return { filePath: file, language: languageOf(file), score, reasons };
  });

  // Stable sort: score desc, then path asc for reproducibility.
  scored.sort((a, b) => b.score - a.score || a.filePath.localeCompare(b.filePath));
  const ranked = scored.slice(0, maxFiles);
  return {
    ranked,
    totalCandidates: scored.length,
    unread: Math.max(0, scored.length - ranked.length),
    budget: { maxFiles, scopeDir }
  };
}
