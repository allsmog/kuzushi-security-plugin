// CodeQL performance tuning — shared by the DB builder and the MCP query server.
//
// CodeQL defaults to a SINGLE thread and an unbounded-but-unhinted RAM budget,
// and `codeql query run` recompiles the query every call. Across the pipeline
// (8+ agents each firing several queries against the same DB) that is the bulk of
// the wall-clock cost. These helpers give every invocation all cores, a sane RAM
// budget, and a persistent compiled-query cache so a repeated query skips
// compilation. Env overrides: KUZUSHI_CODEQL_THREADS, KUZUSHI_CODEQL_RAM_MB.

import { totalmem } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

// RAM budget in MB for the CodeQL evaluator. Default: 75% of system memory (leave
// the OS headroom), floored at 1 GB. Explicit override wins. Returns null when it
// can't determine a budget (then we omit --ram and let CodeQL pick).
export function ramBudgetMb({ totalMb, override = process.env.KUZUSHI_CODEQL_RAM_MB } = {}) {
  const o = Number(override);
  if (Number.isFinite(o) && o > 0) return Math.floor(o);
  // Only fall back to system memory when totalMb wasn't supplied at all; an
  // explicit non-finite value means "unknown" → omit --ram.
  const total = totalMb === undefined ? Math.floor(totalmem() / (1024 * 1024)) : Number(totalMb);
  if (!Number.isFinite(total) || total <= 0) return null;
  return Math.max(1024, Math.floor(total * 0.75));
}

// Parallelism + memory args for `database create`, `query run`, `database analyze`.
// `--threads 0` tells CodeQL to use every available core.
export function codeqlPerfArgs(opts = {}) {
  const threads = process.env.KUZUSHI_CODEQL_THREADS ?? "0";
  const args = ["--threads", String(threads)];
  const ram = ramBudgetMb(opts);
  if (ram) args.push("--ram", String(ram));
  return args;
}

// A stable directory for CodeQL's compiled-query cache, derived from the database
// location: <target>/.kuzushi/codeql-db/<lang> → <target>/.kuzushi/codeql-cache.
// Persisting it across MCP calls means the second run of a query (or any query
// sharing compiled library predicates) skips recompilation.
export function compilationCacheDir(databasePath) {
  let dir = resolve(databasePath);
  for (let i = 0; i < 6; i += 1) {
    if (basename(dir) === ".kuzushi") return join(dir, "codeql-cache");
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // No .kuzushi ancestor (e.g. an external DB): cache beside the DB.
  return join(dirname(resolve(databasePath)), "codeql-cache");
}

// Build the argv for a batched `codeql database analyze` run: one DB open +
// one evaluation pass over many queries, results as SARIF. This replaces N
// separate `query run` calls (each paying JVM + DB-open + compile) with one.
export function analyzeArgs({ database, queries, output, format = "sarif-latest", extraArgs = [] }) {
  return [
    "database", "analyze", resolve(database),
    ...queries.map((q) => resolve(q)),
    `--format=${format}`,
    `--output=${output}`,
    "--rerun",
    ...extraArgs
  ];
}
