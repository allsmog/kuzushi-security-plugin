#!/usr/bin/env node
// /partition — split the attack surface into parallel-discovery partitions.
//
// Discovery parallelizes well, but naive fan-out makes agents converge on the same
// shallow bugs. This does the harness's "first pass to partition the search space"
// deterministically: it reads the entry points /x-ray found and groups them by
// subsystem into non-overlapping partitions. A hunt coordinator then spawns one
// subagent per partition (scoped to that partition's attackSurface), so parallel
// hunters explore DIFFERENT components instead of racing to the same finding.
//
// Deterministic + offline. Writes .kuzushi/partitions.json.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { partitionAttackSurface } from "../lib/partition.mjs";

function fail(message) {
  console.error(`partition: ${message}`);
  process.exit(1);
}

export function buildPartitions(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const maxPartitions = Number(input.maxPartitions ?? 6);

  const entryPoints = readJsonIfPresent(join(store.xRayDir, "entry-points.json"));
  if (!Array.isArray(entryPoints) || !entryPoints.length) {
    fail("no .kuzushi/x-ray/entry-points.json — run /x-ray first to map the attack surface");
  }

  const partitions = partitionAttackSurface({ entryPoints, maxPartitions });
  const doc = {
    version: "1.0",
    schemaVersion: "partitions.v1",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    entryPointCount: entryPoints.length,
    partitionCount: partitions.length,
    partitions
  };
  const partitionsPath = join(store.root, "partitions.json");
  atomicWrite(partitionsPath, `${JSON.stringify(doc, null, 2)}\n`);

  return {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    partitionsPath,
    entryPointCount: entryPoints.length,
    partitionCount: partitions.length,
    partitions: partitions.map((p) => ({ id: p.id, label: p.label, size: p.size, focusHint: p.focusHint }))
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("partition --target <path> [--input '{\"maxPartitions\":6}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) fail("--target is required");
  emitResult(buildPartitions(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
