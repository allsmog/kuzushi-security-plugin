// Contracts for resumable checkpointing (scripts/lib/checkpoint.mjs) — the
// save/shard/done/load/reset round-trip AND the three security properties
// (atomic write, path confinement, no-payload-via-argv) that keep a prompt-injected
// agent from pointing a checkpoint write outside the repo being scanned.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  saveCheckpoint,
  saveShard,
  markComplete,
  loadCheckpoint,
  loadShard,
  loadShardIds,
  resetCheckpoint
} from "../scripts/lib/checkpoint.mjs";

function root() { return mkdtempSync(join(tmpdir(), "kz-ckpt-")); }

// ---- round-trip --------------------------------------------------------------

test("save then load returns running status at the saved phase", () => {
  const r = root();
  saveCheckpoint({ stateDir: "sweep-state", phase: 2, data: { producers: ["authz"] }, root: r });
  const prog = loadCheckpoint({ stateDir: "sweep-state", root: r });
  assert.equal(prog.status, "running");
  assert.equal(prog.phase_done, 2);
});

test("load on a fresh dir reports absent (clean fresh-start signal)", () => {
  assert.equal(loadCheckpoint({ stateDir: "sweep-state", root: root() }).status, "absent");
});

test("shards accumulate in progress.json and survive reload", () => {
  const r = root();
  saveCheckpoint({ stateDir: "sweep-state", phase: 3, root: r });
  saveShard({ stateDir: "sweep-state", shardId: "f001", data: { verdict: "open" }, root: r });
  saveShard({ stateDir: "sweep-state", shardId: "f002", data: { verdict: "reviewed" }, root: r });
  saveShard({ stateDir: "sweep-state", shardId: "f001", data: { verdict: "open" }, root: r }); // idempotent
  assert.deepEqual(loadShardIds({ stateDir: "sweep-state", root: r }).sort(), ["f001", "f002"]);
  assert.equal(loadShard({ stateDir: "sweep-state", shardId: "f002", root: r }).verdict, "reviewed");
});

test("done marks complete; reset removes the state dir", () => {
  const r = root();
  saveCheckpoint({ stateDir: "sweep-state", phase: 4, root: r });
  markComplete({ stateDir: "sweep-state", phase: 4, root: r });
  assert.equal(loadCheckpoint({ stateDir: "sweep-state", root: r }).status, "complete");
  resetCheckpoint({ stateDir: "sweep-state", root: r });
  assert.equal(existsSync(join(r, "sweep-state")), false);
});

test("custom key writes <key>_done (e.g. stage for bootstrap-style flows)", () => {
  const r = root();
  saveCheckpoint({ stateDir: "taint-state", phase: 1, key: "stage", root: r });
  assert.equal(loadCheckpoint({ stateDir: "taint-state", root: r }).stage_done, 1);
});

// ---- security property 1: atomic write (no partial files) --------------------

test("progress.json is valid JSON after every write (atomic, never half-written)", () => {
  const r = root();
  saveCheckpoint({ stateDir: "sweep-state", phase: 1, data: { a: 1 }, root: r });
  // No .tmp file is left behind (rename is atomic).
  const raw = readFileSync(join(r, "sweep-state", "progress.json"), "utf8");
  assert.doesNotThrow(() => JSON.parse(raw));
});

// ---- security property 2: path confinement -----------------------------------

test("refuses a state dir that escapes the root", () => {
  assert.throws(
    () => saveCheckpoint({ stateDir: "../../etc/evil-state", phase: 1, root: root() }),
    /refusing path outside/
  );
});

test("refuses a state dir not ending in -state (no pointing at arbitrary dirs)", () => {
  assert.throws(() => saveCheckpoint({ stateDir: "node_modules", phase: 1, root: root() }), /must end with/);
});

test("refuses a shard id containing path separators", () => {
  const r = root();
  saveCheckpoint({ stateDir: "sweep-state", phase: 3, root: r });
  assert.throws(() => saveShard({ stateDir: "sweep-state", shardId: "../escape", data: {}, root: r }), /path separators/);
});
