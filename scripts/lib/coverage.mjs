// Coverage map for /sweep. Answers the question Xint's "we scanned everything"
// claim dodges: which files did each producer ACTUALLY examine, and what slice of
// the repo did the whole sweep leave untouched? Silent truncation reads as
// "covered everything" when it isn't — so we compute the uncovered set explicitly
// and surface it. Pure: given a plan + the per-shard file lists, the map is fixed.

import { planShards } from "./sharding.mjs";

// Build the coverage map from a sweep plan and the inventory it was planned over.
// `plan.shards` carries fileCount but not the file lists (to keep the plan small),
// so we re-derive the per-shard file lists deterministically from the inventory —
// planShards is pure, so this reproduces exactly what the plan was built on.
export function buildCoverageMap(plan, inventoryFiles, { maxFilesPerShard = 60 } = {}) {
  const shards = planShards(inventoryFiles, { maxFilesPerShard });
  const filesByShard = new Map(shards.map((s) => [s.id, s.files]));

  // A file is "covered" if at least one shard-scoped job ran over its shard.
  const coveredShardIds = new Set();
  const producersByShard = new Map();
  const repoProducers = [];
  for (const job of plan.jobs ?? []) {
    if (job.scope === "repo") {
      repoProducers.push(job.producer);
      continue;
    }
    coveredShardIds.add(job.shardId);
    if (!producersByShard.has(job.shardId)) producersByShard.set(job.shardId, new Set());
    producersByShard.get(job.shardId).add(job.producer);
  }

  const covered = [];
  const uncovered = [];
  for (const s of shards) {
    (coveredShardIds.has(s.id) ? covered : uncovered).push(s);
  }
  const coveredFileCount = covered.reduce((n, s) => n + s.fileCount, 0);
  const totalFiles = inventoryFiles.length;

  return {
    totalFiles,
    coveredFileCount,
    uncoveredFileCount: totalFiles - coveredFileCount,
    coveragePct: totalFiles ? Math.round((coveredFileCount / totalFiles) * 1000) / 10 : 100,
    repoProducers: [...new Set(repoProducers)].sort(),
    shards: shards.map((s) => ({
      id: s.id,
      name: s.name,
      fileCount: s.fileCount,
      covered: coveredShardIds.has(s.id),
      producers: [...(producersByShard.get(s.id) ?? new Set())].sort()
    })),
    uncovered: uncovered.map((s) => ({ id: s.id, name: s.name, fileCount: s.fileCount, sampleFiles: (filesByShard.get(s.id) ?? []).slice(0, 5) }))
  };
}
