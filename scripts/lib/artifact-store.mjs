// Artifact store: paths, run-id mint, atomic writes.
//
// The store directory is <target>/.kuzushi/. If a target still has a
// <target>/.security-agent/ directory left over from a brief naming
// detour, we migrate it to .kuzushi/ on first access (atomic same-fs
// rename in the common case; recursive copy + delete as a fallback).
// Callers must go through storeFor(target) — do not hardcode paths.

import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { randomBytes } from "node:crypto";

const STORE_DIR_NAME = ".kuzushi";
const LEGACY_STORE_DIR_NAME = ".security-agent";

function migrateLegacyStore(target) {
  const legacy = resolve(target, LEGACY_STORE_DIR_NAME);
  const current = resolve(target, STORE_DIR_NAME);
  if (!existsSync(legacy) || existsSync(current)) return;
  try {
    renameSync(legacy, current);
  } catch (error) {
    if (error.code === "EXDEV") {
      cpSync(legacy, current, { recursive: true });
      rmSync(legacy, { recursive: true, force: true });
    } else {
      throw error;
    }
  }
}

export function mintRunId(prefix) {
  const ts = Date.now();
  const rand = randomBytes(5).toString("hex");
  return `${prefix}-${ts}-${rand}`;
}

export function storeFor(target) {
  migrateLegacyStore(target);
  const root = resolve(target, STORE_DIR_NAME);
  return {
    target: resolve(target),
    root,
    storeName: STORE_DIR_NAME,
    legacyStoreName: LEGACY_STORE_DIR_NAME,
    runsDir: join(root, "runs"),
    threatModelPath: join(root, "threat-model.json"),
    threatLeadsPath: join(root, "threat-leads.json"),
    threatIntelAppliedJsonPath: join(root, "threat-intel-applied.json"),
    threatIntelAppliedMdPath: join(root, "threat-intel-applied.md"),
    validatedFindingsPath: join(root, "validated-findings.json"),
    findingsDbPath: join(root, "v2", "findings.sqlite3"),
    catalogsDir: join(root, "catalogs"),
    xRayDir: resolve(target, "x-ray")
  };
}

export function openRun(target, kind, runId = null) {
  const store = storeFor(target);
  const id = runId ?? mintRunId(`host-${kind}`);
  const runDir = join(store.runsDir, id);
  mkdirSync(runDir, { recursive: true });
  return {
    runId: id,
    runDir,
    relativeRunDir: relative(store.target, runDir),
    writeJson(name, value) {
      atomicWrite(join(runDir, name), `${JSON.stringify(value, null, 2)}\n`);
    },
    writeText(name, value) {
      atomicWrite(join(runDir, name), value.endsWith("\n") ? value : `${value}\n`);
    },
    finalize(result) {
      this.writeJson("result.json", result);
      return result;
    }
  };
}

// Atomic write: write to a sibling .tmp then rename. Same-fs in practice.
export function atomicWrite(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}.${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, content);
  renameSync(tmp, path);
}

// Common entry-point for host scripts that need a uniform "what artifacts are
// already on disk for this target" snapshot. Returns null for missing paths so
// downstream code can render "not present" without crashing.
export function artifactSnapshot(target) {
  const store = storeFor(target);
  const paths = {
    xRay: join(store.xRayDir, "x-ray.md"),
    entryPoints: join(store.xRayDir, "entry-points.md"),
    invariants: join(store.xRayDir, "invariants.md"),
    threatModel: store.threatModelPath,
    threatLeads: store.threatLeadsPath,
    threatIntel: store.threatIntelAppliedJsonPath,
    validatedFindings: store.validatedFindingsPath
  };
  return Object.fromEntries(
    Object.entries(paths).map(([key, path]) => [
      key,
      existsSync(path) ? { path, mtime: statSync(path).mtime.toISOString() } : null
    ])
  );
}

export function readJsonIfPresent(path) {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

export function readRunResult(target, runId) {
  const store = storeFor(target);
  const path = join(store.runsDir, runId, "result.json");
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

// Result shape emitted to stdout by every host script. Keeping this in one
// place lets cli.mjs and tests assert a stable envelope.
export function emitResult(result) {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
