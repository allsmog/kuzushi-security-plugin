#!/usr/bin/env node
// Forward complement to callers.mjs: the functions a given function CALLS, each
// with its resolved definition site(s) — so a deep-hunt / verify agent can follow
// tainted data FORWARD across files (callers.mjs walks backward). A reachability
// HINT (textual call sites + textual def resolution), not sound dataflow — open
// the listed defs to confirm the actual propagation.

import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { emitResult } from "../lib/artifact-store.mjs";
import { crossFileCallees } from "../lib/callgraph.mjs";

function main() {
  if (process.argv.includes("--help")) {
    console.log("callees --target <path> --file <relpath> --line <n> [--scope <dir>]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "file", "line", "scope"] });
  if (!flags.target || !flags.file || !flags.line) {
    console.error("callees: --target, --file, and --line are required");
    process.exit(1);
  }
  const target = resolve(flags.target);
  const res = crossFileCallees(target, { filePath: flags.file, line: Number(flags.line), scopeDir: flags.scope ?? "." });
  emitResult({
    ok: true,
    target,
    file: flags.file,
    line: Number(flags.line),
    function: res.function,
    calleeCount: res.callees.length,
    callees: res.callees
  });
}

main();
