#!/usr/bin/env node
// Native CodeQL MCP server. Thin shim over the `codeql` CLI. If the CLI is
// not installed, every tool returns a structured "missing" response.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

if (process.argv.includes("--help")) {
  console.log("codeql MCP server. Tools: codeql:health, codeql:databases, codeql:query.");
  process.exit(0);
}

const DB_INFO_MAX_BUFFER = 20 * 1024 * 1024;
const QUERY_MAX_BUFFER = 100 * 1024 * 1024;
const QUERY_STDOUT_LIMIT = 200_000;
const QUERY_STDERR_LIMIT = 5_000;
const INSTALL_URL = "https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli";

function codeqlAvailable() {
  const result = spawnSync("codeql", ["version", "--format=json"], { encoding: "utf8" });
  return !result.error && result.status === 0;
}

function codeqlMissing() {
  return { ok: false, missing: "codeql", install: INSTALL_URL };
}

function tryParseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function health() {
  if (!codeqlAvailable()) return codeqlMissing();

  const result = spawnSync("codeql", ["version", "--format=json"], { encoding: "utf8" });
  const parsed = tryParseJson(result.stdout);
  return parsed ? { ok: true, version: parsed.version } : { ok: true, raw: (result.stdout ?? "").trim() };
}

async function databases({ root = "." }) {
  if (!codeqlAvailable()) return codeqlMissing();

  const dir = resolve(root);
  if (!existsSync(dir)) return { ok: false, reason: `root not found: ${dir}` };

  const result = spawnSync("codeql", ["database", "info", dir, "--format=json"], {
    encoding: "utf8",
    maxBuffer: DB_INFO_MAX_BUFFER
  });
  if (result.status !== 0) {
    return { ok: false, status: result.status, stderr: (result.stderr ?? "").slice(0, 2000) };
  }
  const parsed = tryParseJson(result.stdout);
  return parsed ? { ok: true, info: parsed } : { ok: true, raw: result.stdout };
}

async function query({ database, query: ql, format = "json" }) {
  if (!codeqlAvailable()) return codeqlMissing();
  if (!database || !ql) return { ok: false, reason: "database and query are required" };

  const result = spawnSync(
    "codeql",
    ["query", "run", "--database", database, ql, `--format=${format}`],
    { encoding: "utf8", maxBuffer: QUERY_MAX_BUFFER }
  );
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: (result.stdout ?? "").slice(0, QUERY_STDOUT_LIMIT),
    stderr: (result.stderr ?? "").slice(0, QUERY_STDERR_LIMIT)
  };
}

// ---------------------------------------------------------------------------
// MCP server wiring
// ---------------------------------------------------------------------------

function asTextResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function main() {
  const server = new McpServer(
    { name: "kuzushi-codeql", version: "0.2.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "codeql_health",
    { title: "codeql:health", description: "Report codeql CLI availability and version." },
    async () => asTextResult(await health())
  );

  server.registerTool(
    "codeql_databases",
    {
      title: "codeql:databases",
      description: "Inspect a CodeQL database directory.",
      inputSchema: { root: z.string().optional() }
    },
    async (args) => asTextResult(await databases(args ?? {}))
  );

  server.registerTool(
    "codeql_query",
    {
      title: "codeql:query",
      description: "Run a CodeQL query against a database. Requires codeql CLI on PATH.",
      inputSchema: {
        database: z.string(),
        query: z.string(),
        format: z.string().optional()
      }
    },
    async (args) => asTextResult(await query(args ?? {}))
  );

  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error(`codeql MCP server failed: ${error.message}`);
  process.exit(1);
});
