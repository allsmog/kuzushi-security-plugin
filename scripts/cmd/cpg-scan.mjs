#!/usr/bin/env node
// cpg-scan — the scalable cross-function memory lane as a CLI the discovery agents invoke
// (like callers.mjs / callees.mjs). Given a suspect file, it builds a SCOPED (light) Joern
// CPG bounded to that file's subsystem (or caller/callee closure) and runs an
// interprocedural memory query against it — surfacing use-after-free / double-free /
// integer-overflow flows that a single-file read can't see and a whole-repo CPG is too
// heavy to build on a laptop. Build cost scales with the scope, not the repo.
//
// Self-skips cleanly (status "skipped") when the `joern` CLI isn't installed.

import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFlags } from "../lib/argv.mjs";
import { emitResult } from "../lib/artifact-store.mjs";
import { investigateFile, joernAvailable } from "../lib/scoped-cpg.mjs";

const PACK = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "packs", "starter", "joern");
// The memory-class queries this lane runs. `all` chains them.
const QUERIES = {
  uaf: "use-after-free.sc",
  "double-free": "double-free.sc",
  "int-overflow": "integer-overflow.sc"
};

function main() {
  if (process.argv.includes("--help")) {
    console.log('cpg-scan --target <path> --file <relpath> [--query uaf|double-free|int-overflow|all] [--mode dir|closure]');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "file", "query", "mode"] });
  if (!flags.target || !flags.file) {
    console.error("cpg-scan: --target and --file are required");
    process.exit(1);
  }
  const target = resolve(flags.target);
  if (!joernAvailable()) {
    emitResult({ ok: true, status: "skipped", reason: "joern CLI not installed — install Joern to use the scoped-CPG memory lane", target, file: flags.file });
    return;
  }
  const which = flags.query && flags.query !== "all" ? [flags.query] : Object.keys(QUERIES);
  const mode = flags.mode === "closure" ? "closure" : "dir";
  const results = [];
  for (const key of which) {
    const q = QUERIES[key];
    if (!q) continue;
    const r = investigateFile(target, flags.file, join(PACK, q), { mode });
    results.push({ query: key, ok: r.ok, scope: r.scope, buildMs: r.buildMs ?? null, flowCount: (r.flows ?? []).length, flows: r.flows ?? [], reason: r.reason ?? null });
  }
  emitResult({
    ok: true, status: "completed", target, file: flags.file, mode,
    queries: results,
    totalFlows: results.reduce((a, r) => a + r.flowCount, 0)
  });
}

main();
