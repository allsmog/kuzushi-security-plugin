// CodeQL tuning helpers shared by the DB builder and the MCP query server. These
// pin the parallelism/RAM args, the compilation-cache path derivation, and the
// batched-analyze argv so a regression that drops a flag (and silently reverts to
// single-threaded, recompile-every-call CodeQL) fails loudly.

import { test } from "node:test";
import assert from "node:assert/strict";
import { ramBudgetMb, codeqlPerfArgs, compilationCacheDir, analyzeArgs } from "../scripts/lib/codeql-tuning.mjs";

test("ramBudgetMb: 75% of total, floored at 1GB, override wins", () => {
  assert.equal(ramBudgetMb({ totalMb: 16384 }), 12288); // 75% of 16GB
  assert.equal(ramBudgetMb({ totalMb: 512 }), 1024); // floored to 1GB
  assert.equal(ramBudgetMb({ totalMb: 16384, override: "4096" }), 4096); // explicit wins
  assert.equal(ramBudgetMb({ totalMb: NaN }), null); // unknown → omit --ram
});

test("codeqlPerfArgs: all cores + a RAM budget", () => {
  const args = codeqlPerfArgs({ totalMb: 8192 });
  assert.deepEqual(args.slice(0, 2), ["--threads", "0"]); // 0 = every core
  const i = args.indexOf("--ram");
  assert.ok(i >= 0 && Number(args[i + 1]) > 0, "includes a --ram budget");
});

test("codeqlPerfArgs honors a threads override", () => {
  const prev = process.env.KUZUSHI_CODEQL_THREADS;
  process.env.KUZUSHI_CODEQL_THREADS = "4";
  try { assert.deepEqual(codeqlPerfArgs({ totalMb: 8192 }).slice(0, 2), ["--threads", "4"]); }
  finally { if (prev === undefined) delete process.env.KUZUSHI_CODEQL_THREADS; else process.env.KUZUSHI_CODEQL_THREADS = prev; }
});

test("compilationCacheDir lands next to the .kuzushi DB root", () => {
  assert.equal(
    compilationCacheDir("/repo/.kuzushi/codeql-db/javascript"),
    "/repo/.kuzushi/codeql-cache"
  );
  // External DB with no .kuzushi ancestor → cache beside it.
  assert.equal(compilationCacheDir("/tmp/somedb"), "/tmp/codeql-cache");
});

test("analyzeArgs batches many queries into one database analyze run", () => {
  const args = analyzeArgs({
    database: "/repo/.kuzushi/codeql-db/javascript",
    queries: ["/q/a.ql", "/q/b.ql"],
    output: "/out/r.sarif"
  });
  assert.deepEqual(args.slice(0, 3), ["database", "analyze", "/repo/.kuzushi/codeql-db/javascript"]);
  assert.ok(args.includes("/q/a.ql") && args.includes("/q/b.ql"), "all queries passed in one run");
  assert.ok(args.includes("--format=sarif-latest"));
  assert.ok(args.includes("--output=/out/r.sarif"));
});
