// The partitioner splits the attack surface so parallel hunters explore different
// subsystems instead of converging on the same shallow bug. These pin the
// component grouping, the cap-with-merge behavior (nothing dropped), and the
// end-to-end /partition command reading x-ray's entry points.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { componentOf, partitionAttackSurface } from "../scripts/lib/partition.mjs";
import { buildPartitions } from "../scripts/cmd/partition.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";

test("componentOf skips non-distinguishing roots to find the subsystem", () => {
  assert.equal(componentOf("src/auth/login.js"), "auth");
  assert.equal(componentOf("lib/payments/charge.py"), "payments");
  assert.equal(componentOf("app/internal/api/users.go"), "api"); // src/lib/app/internal skipped
  assert.equal(componentOf("server.js"), "(root)");
});

test("groups entry points by subsystem into non-overlapping partitions", () => {
  const eps = [
    { filePath: "src/auth/a.js", kind: "express-route" },
    { filePath: "src/auth/b.js", kind: "express-route" },
    { filePath: "src/payments/c.js", kind: "express-route" },
    { filePath: "src/api/d.js", kind: "openapi-route" }
  ];
  const parts = partitionAttackSurface({ entryPoints: eps, maxPartitions: 6 });
  const byLabel = Object.fromEntries(parts.map((p) => [p.label, p]));
  assert.equal(byLabel.auth.size, 2);
  assert.equal(byLabel.payments.size, 1);
  assert.equal(byLabel.api.size, 1);
  // Every entry point lands in exactly one partition (no overlap, none dropped).
  assert.equal(parts.reduce((n, p) => n + p.attackSurface.length, 0), eps.length);
});

test("caps partitions and merges the long tail into 'other' (nothing dropped)", () => {
  const eps = [];
  for (const c of ["a", "b", "c", "d", "e", "f", "g", "h"]) eps.push({ filePath: `src/${c}/x.js`, kind: "route" });
  const parts = partitionAttackSurface({ entryPoints: eps, maxPartitions: 3 });
  assert.equal(parts.length, 3);
  assert.ok(parts.some((p) => p.label === "other"));
  assert.equal(parts.reduce((n, p) => n + p.attackSurface.length, 0), eps.length);
});

test("/partition reads x-ray entry points and writes partitions.json", () => {
  const t = mkdtempSync(join(tmpdir(), "kz-part-"));
  const store = storeFor(t);
  mkdirSync(store.xRayDir, { recursive: true });
  writeFileSync(join(store.xRayDir, "entry-points.json"), JSON.stringify([
    { filePath: "src/auth/login.js", kind: "express-route", line: 3 },
    { filePath: "src/orders/create.js", kind: "express-route", line: 7 }
  ]));
  const res = buildPartitions(t, {});
  assert.equal(res.status, "completed");
  assert.equal(res.partitionCount, 2);
  const doc = JSON.parse(readFileSync(join(store.root, "partitions.json"), "utf8"));
  assert.deepEqual(doc.partitions.map((p) => p.label).sort(), ["auth", "orders"]);
});
