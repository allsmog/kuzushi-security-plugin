#!/usr/bin/env node
// Preflight diagnostics: Node deps, plugin MCP server health, and the presence
// of the external CLIs / LSP binaries the plugin can use. Prints a readable
// status report with install hints for anything missing. `--json` emits the
// machine-readable envelope instead.
//
// The heavy CLIs (CodeQL, Joern, jdtls, clangd, rust-analyzer, gopls) can't be
// bundled in the plugin; this is where we tell the user how to install them.

import { existsSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { emitResult, storeFor, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { SUPPORTED_BACKENDS, mcpHealth } from "../lib/mcp.mjs";
import { LSP_SERVERS, MCP_BACKENDS, toolAvailable } from "../lib/capabilities.mjs";
import { loadPolicy, policyDigest } from "../lib/policy.mjs";

const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const REQUIRED_NODE_PACKAGES = [
  "@modelcontextprotocol/sdk", "tree-sitter-wasms", "web-tree-sitter", "zod",
  "typescript-language-server", "pyright"
];

function checkNodeDeps() {
  const missing = REQUIRED_NODE_PACKAGES.filter(
    (pkg) => !existsSync(join(PLUGIN_ROOT, "node_modules", pkg, "package.json"))
  );
  return { ok: missing.length === 0, missing };
}

async function gather() {
  const nodeDeps = checkNodeDeps();

  const mcpServers = await Promise.all(
    SUPPORTED_BACKENDS.map(async (name) => {
      const health = await mcpHealth(name, { timeoutMs: 8000 });
      const backend = MCP_BACKENDS.find((b) => b.name === name);
      const cliInstalled = backend?.bundled ? true : (toolAvailable(backend?.name) || toolAvailable(backend?.probe));
      return {
        name,
        serverReady: health.ready,
        toolCount: health.tools?.length ?? 0,
        reason: health.reason ?? null,
        cliInstalled,
        installHint: backend?.installHint ?? null
      };
    })
  );

  const lsp = LSP_SERVERS.map((server) => ({
    name: server.name,
    languages: server.languages,
    bundled: Boolean(server.bundled),
    installed: server.bundled ? true : toolAvailable(server.name),
    installHint: server.installHint
  }));

  // Effective tool-boundary policy for the current dir.
  const target = process.cwd();
  const { effective, sources } = loadPolicy(target);
  const store = storeFor(target);
  const rulePack = readJsonIfPresent(store.rulePackManifestPath);
  const policy = {
    digest: policyDigest(target),
    activeProfile: effective.activeProfile,
    overridden: Boolean(sources.override),
    rawQuery: effective.mcp?.rawQuery ?? "allow",
    confineQueryPaths: effective.mcp?.confineQueryPaths ?? true,
    maxQueryBytes: effective.mcp?.maxQueryBytes ?? 200000,
    gitApply: effective.git?.apply ?? "require-approval",
    writeRoots: effective.filesystem?.writeRoots ?? [],
    networkDefault: effective.network?.default ?? "deny",
    networkAllow: effective.network?.allow ?? [],
    hookErrors: effective.guardrails?.onHookError ?? "allow",
    autoInstallLightTools: effective.install?.autoInstallLightTools ?? false,
    allowNetworkInstall: effective.install?.allowNetworkInstall ?? "approval-only",
    requirePinnedDigests: Boolean(effective.install?.requirePinnedDigests),
    rulePack: {
      present: Boolean(rulePack),
      schemaVersion: rulePack?.schemaVersion ?? rulePack?.version ?? null,
      ruleCount: rulePack?.rules?.length ?? 0
    }
  };

  return {
    ok: nodeDeps.ok,
    pluginRoot: PLUGIN_ROOT,
    nodeDeps,
    mcpServers,
    lsp,
    policy
  };
}

function printReport(report) {
  const mark = (b) => (b ? "✓" : "✗");
  console.log("kuzushi doctor");
  console.log("==============");
  console.log("");
  console.log(`Node deps: ${report.nodeDeps.ok ? "✓ all present" : "✗ missing: " + report.nodeDeps.missing.join(", ") + " (run: npm install)"}`);
  console.log("");
  console.log("MCP servers (server = plugin Node server; CLI = the external tool it drives):");
  for (const s of report.mcpServers) {
    const cli = s.name === "tree-sitter" ? "bundled" : `${mark(s.cliInstalled)} CLI`;
    const tail = s.serverReady ? `${s.toolCount} tools` : `not ready: ${s.reason}`;
    const hint = !s.cliInstalled && s.name !== "tree-sitter" ? `   install: ${s.installHint}` : "";
    console.log(`  ${mark(s.serverReady)} server  ${cli.padEnd(10)} ${s.name.padEnd(12)} ${tail}${hint}`);
  }
  console.log("");
  console.log("LSP servers (auto-start per file extension; binaries must be installed):");
  for (const l of report.lsp) {
    const hint = l.installed ? "" : `   install: ${l.installHint}`;
    console.log(`  ${mark(l.installed)} ${l.name.padEnd(28)} ${l.languages.join("/")}${l.bundled ? " (bundled)" : ""}${hint}`);
  }
  if (report.policy) {
    const p = report.policy;
    console.log("");
    console.log(`Tool-boundary policy (profile ${p.activeProfile}, digest ${p.digest}${p.overridden ? ", overridden by .kuzushi/policy.json" : ", default"}):`);
    console.log(`  raw analyzer queries: ${p.rawQuery}   (path-confinement: ${p.confineQueryPaths ? "on" : "off"}, max inline script: ${p.maxQueryBytes} bytes)`);
    console.log(`  git apply (working-tree writes): ${p.gitApply}`);
    console.log(`  guardrail hook errors: ${p.hookErrors}`);
    console.log(`  network: default ${p.networkDefault}; allowlist: ${p.networkAllow.join(", ") || "(none)"}`);
    console.log(`  installs: auto-light=${p.autoInstallLightTools}; network=${p.allowNetworkInstall}; pinned-digests=${p.requirePinnedDigests}`);
    console.log(`  write roots: ${p.writeRoots.join(", ") || "(none)"}`);
    console.log(`  rule pack: ${p.rulePack.present ? `${p.rulePack.ruleCount} rules (${p.rulePack.schemaVersion ?? "unversioned"})` : "not present"}`);
  }
}

async function main() {
  if (process.argv.includes("--help")) {
    console.log("doctor [--json]: report Node deps, MCP server health, and CLI/LSP install status.");
    process.exit(0);
  }
  const report = await gather();
  if (process.argv.includes("--json")) {
    emitResult(report);
  } else {
    printReport(report);
  }
  process.exit(0);
}

main().catch((error) => {
  console.error(`doctor failed: ${error.stack ?? error.message}`);
  process.exit(1);
});
