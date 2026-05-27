// Detection: has a *completed* context run been recorded for a target dir?
//
// A context run is a directory <target>/.kuzushi/runs/host-context-* created by
// context-build. We treat it as "built" only when it contains a result.json,
// so a half-written or crashed run doesn't count. When several context runs
// exist we report the most recent by result.json mtime.

import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { storeFor } from "./artifact-store.mjs";

const CONTEXT_RUN_PREFIX = "host-context-";

export function hasContextRun(target) {
  const store = storeFor(target);
  if (!existsSync(store.runsDir)) {
    return { built: false, runId: null, runDir: null, mtime: null };
  }

  let entries;
  try {
    entries = readdirSync(store.runsDir, { withFileTypes: true });
  } catch {
    return { built: false, runId: null, runDir: null, mtime: null };
  }

  let latest = null;
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (!entry.name.startsWith(CONTEXT_RUN_PREFIX)) continue;
    const runDir = join(store.runsDir, entry.name);
    const resultPath = join(runDir, "result.json");
    if (!existsSync(resultPath)) continue;
    let mtime;
    try {
      mtime = statSync(resultPath).mtime;
    } catch {
      continue;
    }
    if (!latest || mtime > latest.mtime) {
      latest = { runId: entry.name, runDir, mtime };
    }
  }

  if (!latest) {
    return { built: false, runId: null, runDir: null, mtime: null };
  }
  return {
    built: true,
    runId: latest.runId,
    runDir: latest.runDir,
    mtime: latest.mtime.toISOString()
  };
}

// Has x-ray been run? x-ray writes <target>/x-ray/x-ray.md (top-level, not under
// .kuzushi). Presence of that file is the signal.
export function hasXray(target) {
  const xRayMd = join(storeFor(target).xRayDir, "x-ray.md");
  if (!existsSync(xRayMd)) {
    return { built: false, path: null, mtime: null };
  }
  let mtime = null;
  try {
    mtime = statSync(xRayMd).mtime.toISOString();
  } catch {
    // File vanished between checks — treat as not built.
    return { built: false, path: null, mtime: null };
  }
  return { built: true, path: xRayMd, mtime };
}

// Has a threat model been built? The canonical artifact is
// <target>/.kuzushi/threat-model.json (storeFor().threatModelPath).
export function hasThreatModel(target) {
  return artifactStatus(storeFor(target).threatModelPath);
}

// Has live CVE threat-intel research been run? (.kuzushi/threat-intel.json)
export function hasThreatIntel(target) {
  return artifactStatus(storeFor(target).threatIntelPath);
}

// Has the adversarial per-threat review been run? (.kuzushi/threat-hunt.json)
export function hasThreatHunt(target) {
  return artifactStatus(storeFor(target).threatHuntPath);
}

// Has the native / memory-safety review been run? (.kuzushi/systems-hunt.json)
export function hasSystemsHunt(target) {
  return artifactStatus(storeFor(target).systemsHuntPath);
}

// Has exploitability verification been run? (.kuzushi/verify.json)
export function hasVerify(target) {
  return artifactStatus(storeFor(target).verifyPath);
}

// Have empirical PoCs been built/run? (.kuzushi/poc.json)
export function hasPoc(target) {
  return artifactStatus(storeFor(target).pocPath);
}

// Has memory-corruption exploitability assessment been run? (.kuzushi/mem-exploitability.json)
export function hasMemExploitability(target) {
  return artifactStatus(storeFor(target).memExploitabilityPath);
}

// Has PoC⁺ patch validation been run? (.kuzushi/fix.json)
export function hasFix(target) {
  return artifactStatus(storeFor(target).fixPath);
}

// Is a CodeQL database built? (any .kuzushi/codeql-db/<lang> directory present)
export function hasCodeqlDb(target) {
  const dir = storeFor(target).codeqlDbDir;
  if (!existsSync(dir)) return { built: false, path: null, mtime: null };
  try {
    const langs = readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory());
    if (!langs.length) return { built: false, path: null, mtime: null };
    return { built: true, path: dir, languages: langs.map((e) => e.name), mtime: statSync(dir).mtime.toISOString() };
  } catch {
    return { built: false, path: null, mtime: null };
  }
}

// Is a Joern CPG built? (.kuzushi/joern/cpg.bin.zip)
export function hasJoernCpg(target) {
  return artifactStatus(storeFor(target).joernCpgPath);
}

// Shared {built,path,mtime} probe for a single artifact file.
function artifactStatus(path) {
  if (!existsSync(path)) {
    return { built: false, path: null, mtime: null };
  }
  try {
    return { built: true, path, mtime: statSync(path).mtime.toISOString() };
  } catch {
    return { built: false, path: null, mtime: null };
  }
}
