// Contracts for the proactive attack-path engine (the /chain upgrade):
// chain-prepare must (a) admit sub-threshold lead/candidate primitives as path
// links and (b) feed the searcher the crown-jewel assets + entry points +
// reachability; chain-finalize must escalate composed severity to at least the
// strongest member and carry the path fields. Engine-independent (no LLM).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { storeFor, atomicWrite } from "../scripts/lib/artifact-store.mjs";
import { prepareChain } from "../scripts/cmd/chain-prepare.mjs";
import { finalizeChain } from "../scripts/cmd/chain-finalize.mjs";

function tmp() { return mkdtempSync(join(tmpdir(), "kz-attackpath-")); }
const finding = (over = {}) => ({
  source: "taint-analysis", refId: "f", title: "t", severity: "medium", cwe: "89",
  verdict: "finding", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }],
  rationale: "x", ...over
});
const readPrep = (res) => JSON.parse(readFileSync(res.prepPath, "utf8"));
const fpsOf = (t) => JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings;

// ---- sub-threshold primitives are chainable -------------------------------

test("chain-prepare admits lead/candidate primitives as path links", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "lead1", status: "lead", evidence: [{ filePath: "a.js", startLine: 1 }] }),
    finding({ refId: "cand1", status: "candidate", evidence: [{ filePath: "b.js", startLine: 2 }] })
  ]);
  const res = prepareChain(t, {});
  assert.equal(res.memberCount, 2, "a lead + a candidate are now 2 chainable members");
});

test("chain-prepare still excludes reviewed/noise/remediated", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "rev", status: "reviewed", verdict: "reviewed-no-impact", evidence: [{ filePath: "a.js", startLine: 1 }] }),
    finding({ refId: "noise", status: "noise", verdict: "likely-library-noise", evidence: [{ filePath: "b.js", startLine: 2 }] })
  ]);
  assert.throws(() => prepareChain(t, {}), /at least 2 live findings/);
});

// ---- attack-path scaffolding (assets / entry points / reachability) -------

test("chain-prepare feeds assets, entry points, and reachability into prep context", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "a", status: "open", evidence: [{ filePath: "src/handler.js", startLine: 5 }] }),
    finding({ refId: "b", status: "confirmed", evidence: [{ filePath: "src/db.js", startLine: 9 }] })
  ]);
  const store = storeFor(t);
  atomicWrite(store.threatModelPath, JSON.stringify({
    version: "2.0",
    dfd: { nodes: [{ id: "db", type: "database", name: "Users DB" }, { id: "act", type: "actor", name: "Client" }], flows: [], trustBoundaries: [] },
    threats: []
  }));
  atomicWrite(store.deepContextPath, JSON.stringify({
    dataStores: [{ name: "Session store", filePath: "src/session.js", startLine: 3 }],
    entryPoints: [{ filePath: "src/handler.js", kind: "http" }]
  }));
  atomicWrite(store.codeGraphPath, JSON.stringify({
    entryPoints: [{ filePath: "src/handler.js", line: 5, kind: "route" }],
    symbols: [{ name: "query", file: "src/db.js", line: 9, callerCount: 12 }]
  }));

  const res = prepareChain(t, {});
  const prep = readPrep(res);
  const assetNames = prep.context.assets.map((a) => a.name);
  assert.ok(assetNames.includes("Users DB"), "threat-model database node is an asset");
  assert.ok(assetNames.includes("Session store"), "deep-context data store is an asset");
  assert.ok(prep.context.entryPoints.some((e) => e.filePath === "src/handler.js"), "entry point pulled");
  assert.ok(prep.context.reachability.topSymbols.some((s) => s.name === "query"), "reachability summary present");
  assert.equal(prep.context.hasThreatModel, true);
  assert.equal(res.assetCount, prep.context.assets.length);
});

test("chain-prepare degrades gracefully with no threat model / code-graph", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "a", status: "open" }),
    finding({ refId: "b", status: "open", evidence: [{ filePath: "b.js", startLine: 2 }] })
  ]);
  const res = prepareChain(t, {});
  const prep = readPrep(res);
  assert.deepEqual(prep.context.assets, [], "no assets without artifacts");
  assert.equal(prep.context.reachability, null, "no reachability without a code-graph");
  assert.equal(prep.context.hasThreatModel, false);
});

// ---- finalize: severity escalation + path fields --------------------------

test("chain-finalize escalates composed severity to at least the strongest member", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "leak", title: "Info leak", severity: "low", status: "candidate", evidence: [{ filePath: "a.js", startLine: 1 }] }),
    finding({ refId: "rce", title: "Deserialization RCE", severity: "critical", status: "open", evidence: [{ filePath: "b.js", startLine: 2 }] })
  ]);
  const res = prepareChain(t, {});
  const members = fpsOf(t).map((f) => f.fingerprint);
  writeFileSync(join(res.runDir, "draft.chain.json"), JSON.stringify({ chains: [{
    title: "Leak → RCE", kind: "attack-path", entryPoint: "POST /import", asset: "app process",
    members, severity: "medium", // deliberately under-rated; finalize must floor it at critical
    narrative: "x".repeat(130)
  }] }));
  const out = finalizeChain(t, res.runDir);
  assert.equal(out.chainCount, 1);
  const chain = JSON.parse(readFileSync(storeFor(t).chainsPath, "utf8")).chains[0];
  assert.equal(chain.severity, "critical", "escalated to the max member severity, not the claimed 'medium'");
  assert.equal(chain.kind, "attack-path");
  assert.equal(chain.entryPoint, "POST /import");
  assert.equal(chain.asset, "app process");
});

test("chain-finalize infers kind=composition for a legacy draft without path fields", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "a", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }] }),
    finding({ refId: "b", status: "open", evidence: [{ filePath: "b.js", startLine: 2 }] })
  ]);
  const res = prepareChain(t, {});
  const members = fpsOf(t).map((f) => f.fingerprint);
  writeFileSync(join(res.runDir, "draft.chain.json"), JSON.stringify({ chains: [{
    title: "A + B", members, severity: "high", narrative: "y".repeat(130)
  }] }));
  finalizeChain(t, res.runDir);
  const chain = JSON.parse(readFileSync(storeFor(t).chainsPath, "utf8")).chains[0];
  assert.equal(chain.kind, "composition", "no entryPoint/asset → composition kind");
  // and the chains ref is attached onto each member (status unchanged)
  const fps = fpsOf(t);
  assert.ok(fps.every((f) => Array.isArray(f.chains) && f.chains.length === 1), "members carry the chain ref");
  assert.ok(fps.every((f) => f.status === "open"), "member status unchanged");
});
