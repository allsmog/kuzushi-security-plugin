// The synthesized CodeQL/Joern rule pack: a digest-attested manifest at
// .kuzushi/rules/pack.json that records every accepted rule, the engine, the
// seed it came from, the validation evidence at synthesis time, and a content
// digest. The digest is the contract the execution gate enforces — the codeql /
// joern MCP servers (and any CI replay) recompute the on-disk digest and refuse
// to run a rule whose bytes don't match the manifest (assertRunnable).

import { existsSync, readFileSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { storeFor, atomicWrite, readJsonIfPresent } from "./artifact-store.mjs";
import { digestBytes, assertRunnable } from "./attest.mjs";
import { assertValid } from "./schemas.mjs";

export function loadPack(target) {
  const manifest = readJsonIfPresent(storeFor(target).rulePackManifestPath);
  return manifest ?? { schemaVersion: "rule-pack.v1", version: "1.0", target: resolve(target), rules: [] };
}

// Upsert accepted rules into the manifest (keyed by ruleId). `entries` are the
// finalize records; only accepted rules should be passed here.
export function writePack(target, entries) {
  const store = storeFor(target);
  const pack = loadPack(target);
  const byId = new Map((pack.rules ?? []).map((r) => [r.ruleId, r]));
  for (const e of entries) byId.set(e.ruleId, e);
  const doc = { schemaVersion: "rule-pack.v1", version: "1.0", generatedAt: new Date().toISOString(), target: resolve(target), rules: [...byId.values()] };
  assertValid("rulePack", doc);
  atomicWrite(store.rulePackManifestPath, `${JSON.stringify(doc, null, 2)}\n`);
  return doc;
}

// Find a pack entry for an on-disk rule file path (absolute or repo-relative).
export function packEntryForFile(target, ruleFilePath) {
  const store = storeFor(target);
  const abs = resolve(ruleFilePath);
  const rel = relative(resolve(target), abs);
  return (loadPack(target).rules ?? []).find((r) => r.file === rel || resolve(target, r.file) === abs) ?? null;
}

// The execution gate: throw unless `ruleFilePath` is a pack rule whose current
// bytes match the manifest digest and whose compile validation passed. Used by
// the codeql/joern MCP query path before executing a pack query, and by replay.
export function assertPackRunnable(target, ruleFilePath) {
  if (!existsSync(ruleFilePath)) throw new Error(`assertPackRunnable: rule file not found: ${ruleFilePath}`);
  const entry = packEntryForFile(target, ruleFilePath);
  if (!entry) throw new Error(`assertPackRunnable: ${ruleFilePath} is not in the rule pack manifest (${storeFor(target).rulePackManifestPath})`);
  assertRunnable(entry, readFileSync(ruleFilePath));
  return entry;
}

export { digestBytes };
