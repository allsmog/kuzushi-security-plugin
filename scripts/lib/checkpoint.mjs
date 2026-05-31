#!/usr/bin/env node
// Resumable checkpointing for the long orchestrators (/sweep, /taint-analysis) and
// the eval reps. A rate-limit or context-exhaustion mid-run should resume on a phase
// boundary, not restart the whole fan-out.
//
// Three security properties, copied from the reference runbook's checkpoint helper:
//   1. ATOMIC writes — tmp + rename (reuse artifact-store's atomicWrite), so a kill
//      mid-write never leaves a half-written progress.json that breaks resume.
//   2. PATH CONFINEMENT — every path must resolve under the run/repo root. The Bash
//      permission for this script is a prefix wildcard, so a prompt-injected agent
//      could otherwise point save/reset at ~/.ssh or ~/.bashrc. Confining to root
//      keeps the blast radius at the repo being scanned.
//   3. PAYLOAD FROM A FILE, never argv/heredoc — repo-derived bytes (a finding's
//      title, a code excerpt) in a heredoc can terminate the delimiter early and
//      break out to shell. The CLI takes --from <file> (written via the Write tool);
//      no target-derived bytes touch the Bash argv.
//
// Usable two ways:
//   • imported (eval.mjs calls saveCheckpoint/loadCheckpoint directly — no shell), or
//   • as a CLI from a skill via Bash:
//       node checkpoint.mjs save  <stateDir> <N> [name] --from <file> [--key K] [--root R]
//       node checkpoint.mjs shard <stateDir> <shardId>  --from <file> [--root R]
//       node checkpoint.mjs done  <stateDir> <N> [--key K] [--root R]
//       node checkpoint.mjs load  <stateDir> [--root R]
//       node checkpoint.mjs reset <stateDir> [--root R]
//
// progress.json schema: { status:"running"|"complete", <key>_done:N, shards_done:[...], updated:iso }

import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { atomicWrite } from "./artifact-store.mjs";

// ---- confinement helpers -----------------------------------------------------

function confine(p, root, { mustEnd = null } = {}) {
  const base = resolve(root ?? process.env.CHECKPOINT_ROOT ?? process.cwd());
  const r = resolve(base, p);
  if (r !== base && !r.startsWith(base + "/")) {
    throw new Error(`checkpoint: refusing path outside ${base}: ${p}`);
  }
  if (mustEnd && !r.endsWith(mustEnd)) {
    throw new Error(`checkpoint: refusing ${p} (name must end with "${mustEnd}")`);
  }
  return r;
}

function safeToken(s, what) {
  const str = String(s);
  if (str.includes("/") || str.includes("\\") || str.includes("..")) {
    throw new Error(`checkpoint: refusing ${what} with path separators: ${str}`);
  }
  return str;
}

function writeJson(path, value) {
  atomicWrite(path, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(path) {
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null;
}

function writeProgress(stateDir, { status, key, n, shards }) {
  writeJson(resolve(stateDir, "progress.json"), {
    status,
    [`${key}_done`]: n,
    shards_done: shards,
    updated: new Date().toISOString()
  });
}

// ---- importable API ----------------------------------------------------------
// stateDir must end with "-state" and resolve under `root` (default: cwd).

export function saveCheckpoint({ stateDir, phase, key = "phase", data, root }) {
  const dir = confine(stateDir, root, { mustEnd: "-state" });
  const k = safeToken(key, "key");
  mkdirSync(dir, { recursive: true });
  writeJson(resolve(dir, `${k}${phase}.json`), data ?? {});
  writeProgress(dir, { status: "running", key: k, n: phase, shards: loadShardIds({ stateDir, root }) });
  return { stateDir: dir, phase, key: k };
}

export function saveShard({ stateDir, shardId, data, root }) {
  const dir = confine(stateDir, root, { mustEnd: "-state" });
  const id = safeToken(shardId, "shardId");
  mkdirSync(dir, { recursive: true });
  writeJson(resolve(dir, `shard_${id}.json`), data ?? {});
  const prog = readJson(resolve(dir, "progress.json")) ?? { status: "running" };
  const shards = Array.isArray(prog.shards_done) ? prog.shards_done : [];
  if (!shards.includes(id)) shards.push(id);
  prog.shards_done = shards;
  prog.updated = new Date().toISOString();
  prog.status = prog.status ?? "running";
  writeJson(resolve(dir, "progress.json"), prog);
  return { stateDir: dir, shardId: id, shardsDone: shards };
}

export function markComplete({ stateDir, phase, key = "phase", root }) {
  const dir = confine(stateDir, root, { mustEnd: "-state" });
  writeProgress(dir, { status: "complete", key: safeToken(key, "key"), n: phase, shards: loadShardIds({ stateDir, root }) });
  return { stateDir: dir, status: "complete" };
}

// Returns the progress object, or { status:"absent" } if no checkpoint exists.
export function loadCheckpoint({ stateDir, root }) {
  const dir = confine(stateDir, root, { mustEnd: "-state" });
  return readJson(resolve(dir, "progress.json")) ?? { status: "absent" };
}

export function loadShard({ stateDir, shardId, root }) {
  const dir = confine(stateDir, root, { mustEnd: "-state" });
  return readJson(resolve(dir, `shard_${safeToken(shardId, "shardId")}.json`));
}

// The authoritative list of completed shard ids comes from progress.json, NOT a glob
// of shard_*.json on disk — stale shard files from a prior run may exist, and resume
// must only trust shards recorded after their progress update committed.
export function loadShardIds({ stateDir, root }) {
  const prog = loadCheckpoint({ stateDir, root });
  return Array.isArray(prog.shards_done) ? prog.shards_done : [];
}

export function resetCheckpoint({ stateDir, root }) {
  const dir = confine(stateDir, root, { mustEnd: "-state" });
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  return { stateDir: dir, status: "reset" };
}

// ---- CLI ---------------------------------------------------------------------

function popOpt(argv, flag, dflt = undefined) {
  const i = argv.indexOf(flag);
  if (i === -1) return [argv, dflt];
  return [argv.slice(0, i).concat(argv.slice(i + 2)), argv[i + 1]];
}

function readFromFile(src, root) {
  if (src === undefined) {
    throw new Error("checkpoint: payload must be passed via --from <file> (stdin/heredoc disabled to prevent shell injection)");
  }
  const p = confine(src, root);
  const raw = readFileSync(p, "utf8");
  try { JSON.parse(raw); } catch (e) { throw new Error(`checkpoint: --from ${src} is not valid JSON: ${e.message}`); }
  return JSON.parse(raw);
}

function main(argv) {
  const cmd = argv[0];
  let rest = argv.slice(1);
  let root, key, from;
  [rest, root] = popOpt(rest, "--root");
  [rest, key] = popOpt(rest, "--key", "phase");
  [rest, from] = popOpt(rest, "--from");

  try {
    switch (cmd) {
      case "save": {
        const [stateDir, n] = rest;
        const out = saveCheckpoint({ stateDir, phase: Number(n), key, data: readFromFile(from, root), root });
        process.stdout.write(`checkpoint: ${key} ${n} saved → ${out.stateDir}/\n`);
        return 0;
      }
      case "shard": {
        const [stateDir, shardId] = rest;
        const out = saveShard({ stateDir, shardId, data: readFromFile(from, root), root });
        process.stdout.write(`checkpoint: shard ${shardId} saved (${out.shardsDone.length} done)\n`);
        return 0;
      }
      case "done": {
        const [stateDir, n] = rest;
        markComplete({ stateDir, phase: Number(n), key, root });
        process.stdout.write("checkpoint: complete\n");
        return 0;
      }
      case "load": {
        process.stdout.write(`${JSON.stringify(loadCheckpoint({ stateDir: rest[0], root }))}\n`);
        return 0;
      }
      case "reset": {
        resetCheckpoint({ stateDir: rest[0], root });
        process.stdout.write("checkpoint: reset\n");
        return 0;
      }
      default:
        process.stderr.write("usage: checkpoint.mjs {save|shard|done|load|reset} <state_dir> ...\n");
        return 2;
    }
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main(process.argv.slice(2)));
}
