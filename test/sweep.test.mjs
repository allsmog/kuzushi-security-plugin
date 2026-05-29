// Regression contracts for the /sweep orchestrator: the deterministic planner
// (sharding + job manifest + requirement/offline gating), the coverage map, and
// the findings-index lock that makes the parallel fan-out safe. Engine-free — no
// agents, no producers actually run; we assert the plan/coverage math and that
// concurrent-style upserts don't lose writes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { planShards, inventory } from "../scripts/lib/sharding.mjs";
import { buildCoverageMap } from "../scripts/lib/coverage.mjs";
import { prepareSweep } from "../scripts/cmd/sweep-prepare.mjs";
import { finalizeSweep } from "../scripts/cmd/sweep-finalize.mjs";

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-sweep-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}
function emptyFindings(t) {
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
}
function write(t, rel, body) {
  const abs = join(t, rel);
  mkdirSync(join(abs, ".."), { recursive: true });
  writeFileSync(abs, body);
}

// A small polyglot repo across two top-level modules.
function seedRepo(t) {
  write(t, "api/users.py", "def get(request):\n    return User.objects.get(id=request.GET['id'])\n");
  write(t, "api/auth.py", "import hashlib\nhashlib.md5(b'x')\n");
  write(t, "core/parse.c", "#include <string.h>\nvoid f(char*s){char b[8];strcpy(b,s);}\n");
  write(t, "README.md", "# not source\n"); // ignored by the source inventory
}

test("sweep: planner shards the repo and emits shard×producer + repo jobs", () => {
  const t = repo();
  seedRepo(t);
  const res = prepareSweep(t, {});
  assert.equal(res.status, "prepared");
  assert.ok(res.shardCount >= 2, "at least the api/ and core/ shards");
  assert.ok(res.jobCount > 0);

  const plan = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  // A C shard must get systems-hunt; a Python shard must get authz/logic-hunt.
  const bySource = {};
  for (const j of plan.jobs) (bySource[j.producer] ??= []).push(j);
  assert.ok(bySource["systems-hunt"], "native shard gets systems-hunt");
  assert.ok(bySource["authz"], "web shard gets authz");
  assert.ok(bySource["logic-hunt"], "web shard gets logic-hunt");
  // Every shard job carries an executable prepareCommand + budget-scaled cap.
  for (const j of plan.jobs.filter((x) => x.scope === "shard")) {
    assert.match(j.prepareCommand, /-prepare\.mjs/);
    assert.ok(j.prepInput.maxCandidates >= 4);
    assert.ok(j.prepInput.scopeDir);
  }
});

test("sweep: threat-hunt is skipped without a threat model; present with one", () => {
  const t = repo();
  seedRepo(t);
  let plan = prepareSweep(t, {});
  let planDoc = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.ok(planDoc.skipped.some((s) => s.producer === "threat-hunt"), "skipped: no threat model");

  writeFileSync(storeFor(t).threatModelPath, JSON.stringify({ threats: [] }) + "\n");
  prepareSweep(t, {});
  planDoc = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.ok(planDoc.jobs.some((j) => j.producer === "threat-hunt"), "threat-hunt job present with a model");
});

test("sweep: offline skips network producers (supply-chain)", () => {
  const t = repo();
  seedRepo(t);
  prepareSweep(t, { offline: true });
  const plan = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.ok(plan.offline);
  assert.ok(!plan.jobs.some((j) => j.producer === "supply-chain"), "supply-chain not queued offline");
  assert.ok(plan.skipped.some((s) => s.producer === "supply-chain"), "supply-chain recorded as skipped");
});

test("sweep: explicit producer subset restricts the plan", () => {
  const t = repo();
  seedRepo(t);
  prepareSweep(t, { producers: ["authz"] });
  const plan = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.deepEqual([...new Set(plan.jobs.map((j) => j.producer))], ["authz"]);
});

test("sweep: deep-scan joins only in deep mode, budgeted by maxFiles", () => {
  const t = repo();
  seedRepo(t);
  prepareSweep(t, {});
  let plan = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.ok(!plan.jobs.some((j) => j.producer === "deep-scan"), "deep-scan absent by default");

  prepareSweep(t, { deep: true });
  plan = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  const deepJobs = plan.jobs.filter((j) => j.producer === "deep-scan");
  assert.ok(deepJobs.length >= 1, "deep-scan present in deep mode");
  for (const j of deepJobs) assert.ok(j.prepInput.maxFiles >= 1, "deep jobs budget by maxFiles, not maxCandidates");
  // Deep mode carries an interproc plan; offline never recommends a network build.
  assert.ok(plan.interproc, "deep mode includes an interproc plan");
  prepareSweep(t, { deep: true, offline: true });
  const off = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.notEqual(off.interproc.status, "recommended", "offline never recommends building DBs");
});

test("coverage: a partial plan reports the uncovered shards", () => {
  const t = repo();
  seedRepo(t);
  const inv = inventory(t);
  const shards = planShards(inv.files);
  // Plan that only covers the first shard.
  const plan = { jobs: [{ scope: "shard", shardId: shards[0].id, producer: "authz" }], input: {} };
  const cov = buildCoverageMap(plan, inv.files);
  assert.ok(cov.coveragePct < 100, "not everything covered");
  assert.ok(cov.uncoveredFileCount > 0);
  assert.ok(cov.uncovered.length >= 1);
});

test("sweep: finalize writes sweep.json + coverage-map.json", () => {
  const t = repo();
  seedRepo(t);
  emptyFindings(t);
  const prep = prepareSweep(t, {});
  const res = finalizeSweep(t, prep.runDir);
  assert.equal(res.status, "completed");
  assert.ok(typeof res.coveragePct === "number");
  const cov = JSON.parse(readFileSync(storeFor(t).coverageMapPath, "utf8"));
  assert.equal(cov.coveragePct, 100, "all shards covered by the full plan");
});

test("findings lock: rapid sequential upserts never lose-update", () => {
  const t = repo();
  emptyFindings(t);
  for (let i = 0; i < 12; i += 1) {
    upsertFindings(t, [{
      source: "sweep-test", refId: `r${i}`, title: `f${i}`, severity: "low",
      verdict: "finding", evidence: [{ filePath: `f${i}.js`, startLine: 1 }], rationale: "x"
    }]);
  }
  const doc = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8"));
  assert.equal(doc.findings.length, 12, "all 12 distinct findings retained");
});

test("hunt integrity: applicable hunters are planned; inapplicable are skipped with reasons", () => {
  const t = repo();
  // polyglot + threat model so threat-hunt applies; native so systems-hunt applies
  write(t, "api/orders.py", "@app.route('/o')\ndef o():\n    return Order.objects.get(id=request.args['id'])\n");
  write(t, "core/parse.c", "#include <string.h>\nvoid f(char*s){char b[8];strcpy(b,s);}\n");
  writeFileSync(storeFor(t).threatModelPath, JSON.stringify({ threats: [] }) + "\n");
  prepareSweep(t, {});
  const plan = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  const producers = new Set(plan.jobs.map((j) => j.producer));
  // Every classic hunter that applies must be planned (the only HUNT path now that
  // they're all user-invocable:false).
  for (const p of ["threat-hunt", "taint-analysis", "authz", "logic-hunt", "crypto-review", "sharp-edges", "systems-hunt", "iac", "supply-chain"]) {
    assert.ok(producers.has(p), `hunt phase must run ${p}`);
  }
  // Inapplicable ones are skipped WITH a reason (applicability decided by the plan).
  const skipped = Object.fromEntries(plan.skipped.map((s) => [s.producer, s.reason]));
  assert.ok(skipped["binary-recon"], "binary-recon skipped (no binaries) with a reason");
  // offline drops the network producer with a reason
  prepareSweep(t, { offline: true });
  const off = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.ok(off.skipped.some((s) => s.producer === "supply-chain"), "offline skips supply-chain");
});

test("interproc: deep mode reports 'ready' when a Joern CPG is present", () => {
  const t = repo();
  seedRepo(t);
  // simulate a prebuilt CPG
  mkdirSync(join(t, ".kuzushi", "joern"), { recursive: true });
  writeFileSync(join(t, ".kuzushi", "joern", "cpg.bin.zip"), "x");
  prepareSweep(t, { deep: true });
  const plan = JSON.parse(readFileSync(storeFor(t).sweepPlanPath, "utf8"));
  assert.equal(plan.interproc.status, "ready", "CPG present → cross-file flow tracing ready");
  assert.equal(plan.interproc.joernCpg, true);
});
