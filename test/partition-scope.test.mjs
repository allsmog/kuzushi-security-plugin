// Per-partition fan-out: taint-analysis-prepare --partition scopes its candidate
// files to one subsystem so concurrent partition runs cover different components
// (the parallel-discovery payoff). These pin that the scope actually filters to the
// partition's component and that an unscoped run sees the whole surface.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareTaintAnalysis } from "../scripts/cmd/taint-analysis-prepare.mjs";
import { componentOf } from "../scripts/lib/partition.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";

const rgPresent = !spawnSync("rg", ["--version"]).error;

function repoWithTwoComponents() {
  const t = mkdtempSync(join(tmpdir(), "kz-pscope-"));
  mkdirSync(join(t, "src", "auth"), { recursive: true });
  mkdirSync(join(t, "src", "orders"), { recursive: true });
  // Strong, catalog-matching sink/source tokens so both files are found.
  writeFileSync(join(t, "src", "auth", "login.js"), 'const x = req.body.id; db.query("select " + x); eval(x);\n');
  writeFileSync(join(t, "src", "orders", "create.js"), 'const y = req.query.id; db.query("insert " + y); eval(y);\n');
  // Two partitions, one per component.
  mkdirSync(storeFor(t).root, { recursive: true });
  writeFileSync(join(storeFor(t).root, "partitions.json"), JSON.stringify({
    partitions: [
      { id: "p1", label: "auth", attackSurface: [{ filePath: "src/auth/login.js" }] },
      { id: "p2", label: "orders", attackSurface: [{ filePath: "src/orders/create.js" }] }
    ]
  }));
  return t;
}

function sinkFiles(prep) {
  return JSON.parse(readFileSync(prep.prepPath, "utf8")).candidateFiles.sinks;
}

test("unscoped prepare sees both components; --partition auth scopes to the auth subsystem", { skip: rgPresent ? false : "ripgrep not on PATH" }, () => {
  const t = repoWithTwoComponents();

  const full = prepareTaintAnalysis(t, {});
  const fullSinks = sinkFiles(full);
  assert.ok(fullSinks.some((f) => componentOf(f) === "auth"), "unscoped sees auth");
  assert.ok(fullSinks.some((f) => componentOf(f) === "orders"), "unscoped sees orders");

  const scoped = prepareTaintAnalysis(t, { partition: "auth" });
  assert.deepEqual(scoped.partition, { id: "p1", label: "auth" });
  const scopedSinks = sinkFiles(scoped);
  assert.ok(scopedSinks.length >= 1, "scoped still finds the auth sink");
  for (const f of scopedSinks) assert.equal(componentOf(f), "auth", `${f} leaked outside the auth partition`);
});

test("an unknown partition is a no-op with a warning (proceeds unscoped, never crashes)", { skip: rgPresent ? false : "ripgrep not on PATH" }, () => {
  const t = repoWithTwoComponents();
  const scoped = prepareTaintAnalysis(t, { partition: "does-not-exist" });
  assert.equal(scoped.partition, null);
  assert.ok(scoped.warnings.some((w) => /not found/.test(w)), "warns the partition wasn't found");
});
