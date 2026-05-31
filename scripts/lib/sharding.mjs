// Repo sharding for /sweep. Turns the flat source inventory into a set of shards
// — contiguous slices of the repo grouped by top-level directory — so the
// orchestrator can fan a producer out across the WHOLE repo instead of only the
// threat-model-seeded hotspots (the recall gap). Pure/deterministic: same repo →
// same shards, so a sweep is reproducible and resumable.

import { listFiles } from "./ripgrep.mjs";

// Keep in sync with x-ray.mjs languageFromPath — duplicated rather than imported
// because x-ray.mjs is a CLI entry, not a lib, and we don't want to couple to it.
const EXT_LANG = [
  [/\.(java)$/, "Java"],
  [/\.(kt|kts)$/, "Kotlin"],
  [/\.(scala)$/, "Scala"],
  [/\.(tsx?)$/, "TypeScript"],
  [/\.(jsx?|mjs|cjs)$/, "JavaScript"],
  [/\.(c|h)$/, "C"],
  [/\.(cc|cpp|hpp|cxx)$/, "C++"],
  [/\.(m|mm)$/, "Objective-C"],
  [/\.(rs)$/, "Rust"],
  [/\.(go)$/, "Go"],
  [/\.(rb|erb)$/, "Ruby"],
  [/\.(py)$/, "Python"],
  [/\.(php)$/, "PHP"]
];

export function languageOf(filePath) {
  for (const [re, lang] of EXT_LANG) if (re.test(filePath)) return lang;
  return "Other";
}

// First path segment as the shard key; files at the repo root share a "(root)"
// shard. A top-level dir bigger than maxFilesPerShard is split into numbered
// sub-shards so no single shard blows the per-job token budget.
function topLevel(filePath) {
  const i = filePath.indexOf("/");
  return i === -1 ? "(root)" : filePath.slice(0, i);
}

function langCounts(files) {
  const by = {};
  for (const f of files) {
    const l = languageOf(f);
    by[l] = (by[l] ?? 0) + 1;
  }
  return by;
}

// Build the inventory once (rg --files, with a pure-Node fallback). rg emits
// "./a/b" while the Node fallback emits "a/b" — normalize the leading "./" so
// sharding (which keys on the first path segment) is consistent across both.
export function inventory(target) {
  const files = listFiles(target).map((f) => f.replace(/^\.\//, ""));
  return { files, totalFiles: files.length, byLanguage: langCounts(files) };
}

// Group the inventory into shards. Options: { maxFilesPerShard = 60 }.
export function planShards(files, { maxFilesPerShard = 60 } = {}) {
  const groups = new Map();
  for (const f of files) {
    const key = topLevel(f);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  const shards = [];
  for (const [dir, groupFiles] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const sorted = groupFiles.slice().sort();
    if (sorted.length <= maxFilesPerShard) {
      shards.push(makeShard(dir, sorted, null));
    } else {
      // Split oversized dirs deterministically into contiguous numbered chunks.
      let part = 0;
      for (let i = 0; i < sorted.length; i += maxFilesPerShard) {
        shards.push(makeShard(dir, sorted.slice(i, i + maxFilesPerShard), ++part));
      }
    }
  }
  return shards;
}

function makeShard(dir, files, part) {
  const id = part ? `${slug(dir)}__${part}` : slug(dir);
  return {
    id,
    name: part ? `${dir} (part ${part})` : dir,
    scopeDir: dir === "(root)" ? "." : dir,
    files,
    fileCount: files.length,
    byLanguage: langCounts(files)
  };
}

function slug(dir) {
  return dir.replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "root";
}
