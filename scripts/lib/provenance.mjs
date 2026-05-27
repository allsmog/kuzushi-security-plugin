// Provenance: cheap, stable digests stamped onto every result envelope so a run
// is reproducible/auditable — what toolchain produced it, against what repo
// state, under what scope and policy. All digests are best-effort and never
// throw (a missing context.json just yields a null repo/scope digest).

// NB: deliberately does NOT import artifact-store (which imports this module to
// stamp provenance) — it reads the runs dir + JSON directly to stay cycle-free.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { policyDigest } from "./policy.mjs";

function readJsonIfPresent(path) {
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

const PLUGIN_VERSION = (() => {
  try {
    return JSON.parse(readFileSync(new URL("../../.claude-plugin/plugin.json", import.meta.url), "utf8")).version;
  } catch { return "unknown"; }
})();

function shortHash(value) {
  return createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex").slice(0, 16);
}

// Most recent completed context.json for the target, if any.
function latestContext(target) {
  const runsDir = join(resolve(target), ".kuzushi", "runs");
  if (!existsSync(runsDir)) return null;
  let latest = null;
  for (const name of readdirSync(runsDir)) {
    if (!name.startsWith("host-context-")) continue;
    const ctx = join(runsDir, name, "context.json");
    if (!existsSync(ctx)) continue;
    const mtime = statSync(ctx).mtimeMs;
    if (!latest || mtime > latest.mtime) latest = { path: ctx, mtime };
  }
  return latest ? readJsonIfPresent(latest.path) : null;
}

export function provenanceFor(target) {
  const ctx = latestContext(target);
  const byLanguage = ctx?.inventory?.byLanguage ?? null;
  return {
    pluginVersion: PLUGIN_VERSION,
    nodeVersion: process.version,
    toolchainDigest: shortHash({ plugin: PLUGIN_VERSION, node: process.version, platform: process.platform }),
    repoDigest: ctx ? shortHash({ files: ctx.inventory?.totalFiles ?? 0, byLanguage }) : null,
    scopeDigest: byLanguage ? shortHash(Object.keys(byLanguage).sort()) : null,
    policyDigest: policyDigest(target),
    generatedAt: new Date().toISOString()
  };
}
