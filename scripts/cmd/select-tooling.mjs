#!/usr/bin/env node
// Advisory tooling selector: read the latest context snapshot's detected
// languages and compute which LSP servers + MCP backends are relevant for this
// repo (and which are installed). Writes <target>/.kuzushi/tooling-selection.json.
//
// LSP servers are auto-gated by Claude Code per file extension; MCP backends
// (beyond the bundled self-gating tree-sitter server) are advisory — enable the
// relevant ones and /reload-plugins.

import { resolve, join } from "node:path";
import { existsSync, readdirSync, statSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { selectCapabilities } from "../lib/capabilities.mjs";

// Latest completed context run's byLanguage (same pattern as threat-model-prepare).
function latestByLanguage(target) {
  const store = storeFor(target);
  if (!existsSync(store.runsDir)) return {};
  let latest = null;
  for (const entry of readdirSync(store.runsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("host-context-")) continue;
    const ctx = join(store.runsDir, entry.name, "context.json");
    if (!existsSync(ctx)) continue;
    const mtime = statSync(ctx).mtime;
    if (!latest || mtime > latest.mtime) latest = { path: ctx, mtime };
  }
  const context = latest ? readJsonIfPresent(latest.path) : null;
  return context?.inventory?.byLanguage ?? {};
}

export function selectForTarget(target) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const byLanguage = latestByLanguage(resolvedTarget);
  const selection = selectCapabilities(byLanguage);

  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    detected: selection.detected,
    lsp: selection.lsp,
    mcp: selection.mcp,
    note: "LSP servers auto-start per file extension; MCP backends beyond the bundled tree-sitter server are advisory (enable + /reload-plugins)."
  };

  const path = join(store.root, "tooling-selection.json");
  atomicWrite(path, `${JSON.stringify(result, null, 2)}\n`);
  return { ...result, selectionPath: path };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("select-tooling --target <path>: report LSP/MCP tooling relevant to the repo's detected languages.");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target"] });
  if (!flags.target) {
    console.error("select-tooling: --target is required");
    process.exit(1);
  }
  emitResult(selectForTarget(flags.target));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
