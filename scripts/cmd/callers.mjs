#!/usr/bin/env node
// Repo-wide cross-file caller lookup for agents. tree_sitter:callers is single-file;
// this gives a deep-scan / verify agent the call sites of a function ANYWHERE in the
// repo (definition line excluded) so it can judge reachability across files without a
// full CPG. A reachability HINT (textual call sites), not sound dataflow — open the
// listed files to confirm the actual flow.

import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { emitResult } from "../lib/artifact-store.mjs";
import { crossFileCallers } from "../lib/callgraph.mjs";

function main() {
  if (process.argv.includes("--help")) {
    console.log('callers --target <path> --symbol <name> [--scope <dir>]');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "symbol", "scope"] });
  if (!flags.target || !flags.symbol) {
    console.error("callers: --target and --symbol are required");
    process.exit(1);
  }
  const target = resolve(flags.target);
  const callers = crossFileCallers(target, flags.symbol, { scopeDir: flags.scope ?? "." });
  emitResult({ ok: true, symbol: flags.symbol, target, callerCount: callers.length, callers });
}

main();
