#!/usr/bin/env node
// Native CodeQL MCP server. Thin shim over the `codeql` CLI. If the CLI is
// not installed, every tool returns a structured "missing" response.

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, join, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { assertQueryAllowed } from "../../scripts/lib/policy.mjs";
import { assertPackRunnable } from "../../scripts/lib/rule-pack.mjs";

if (process.argv.includes("--help")) {
  console.log("codeql MCP server. Tools: codeql:health, codeql:databases, codeql:query.");
  process.exit(0);
}

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

function parseSimpleYaml(text) {
  const out = {};
  const stack = [{ indent: -1, value: out }];

  for (const rawLine of text.split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trim() === "---" || rawLine.trim().startsWith("#")) continue;

    const indent = rawLine.match(/^\s*/)?.[0].length ?? 0;
    const trimmed = rawLine.trim();
    const match = /^([^:]+):(.*)$/.exec(trimmed);
    if (!match) continue;

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop();

    const parent = stack[stack.length - 1].value;
    const key = match[1].trim();
    const rest = match[2].trim();

    if (!rest) {
      const child = {};
      parent[key] = child;
      stack.push({ indent, value: child });
    } else if (rest === "true" || rest === "false") {
      parent[key] = rest === "true";
    } else if (/^-?\d+$/.test(rest)) {
      parent[key] = Number(rest);
    } else {
      parent[key] = rest.replace(/^["']|["']$/g, "");
    }
  }

  return out;
}

function databaseMetadata(dir) {
  const metadataPath = join(dir, "codeql-database.yml");
  if (!existsSync(metadataPath)) return null;

  const metadata = parseSimpleYaml(readFileSync(metadataPath, "utf8"));
  return {
    path: dir,
    name: basename(dir),
    language: metadata.primaryLanguage,
    finalized: metadata.finalised,
    buildMode: metadata.buildMode,
    sourceLocationPrefix: metadata.sourceLocationPrefix,
    baselineLinesOfCode: metadata.baselineLinesOfCode,
    creationMetadata: metadata.creationMetadata,
    metadata
  };
}

function childDatabaseDirs(dir) {
  if (!existsSync(dir)) return [];

  return readdirSync(dir)
    .map((entry) => join(dir, entry))
    .filter((entry) => {
      try { return statSync(entry).isDirectory() && existsSync(join(entry, "codeql-database.yml")); }
      catch { return false; }
    });
}

function defaultSearchPath() {
  const candidates = [
    ...(process.env.CODEQL_SEARCH_PATH?.split(delimiter) ?? []),
    join(process.env.HOME ?? "", ".codeql", "packages", "codeql", "java-all"),
    join(process.env.HOME ?? "", ".codeql", "packages", "codeql", "javascript-all")
  ].filter(Boolean);

  return candidates.filter((candidate) => existsSync(candidate)).join(delimiter);
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

  const direct = databaseMetadata(dir);
  if (direct) return { ok: true, database: direct };

  const kuzushiDbRoot = join(dir, ".kuzushi", "codeql-db");
  const searchRoot = existsSync(kuzushiDbRoot) ? kuzushiDbRoot : dir;
  const databases = childDatabaseDirs(searchRoot).map(databaseMetadata).filter(Boolean);

  if (databases.length === 0) {
    return { ok: false, reason: `no CodeQL databases found under: ${dir}` };
  }

  return { ok: true, root: searchRoot, databases };
}

async function query({ database, query: ql, format = "json", searchPath }) {
  if (!codeqlAvailable()) return codeqlMissing();
  if (!database || !ql) return { ok: false, reason: "database and query are required" };

  // Tool-boundary policy: confine the query file to allowed roots and honor the
  // raw-query posture before executing anything.
  const gate = assertQueryAllowed({ queryPath: ql, fromPath: database });
  if (!gate.ok) return gate;
  // Attestation: a pack query (under .kuzushi/rules/) runs freely only when its
  // current bytes match the manifest digest and it compiled at synthesis time.
  if (gate.fromPack) {
    try { assertPackRunnable(gate.target, resolve(ql)); }
    catch (e) { return { ok: false, blocked: "attestation", reason: e.message }; }
  }

  const scratch = mkdtempSync(join(tmpdir(), "kuzushi-codeql-"));
  const bqrs = join(scratch, "results.bqrs");

  try {
    const runArgs = ["query", "run", "--database", resolve(database), "--output", bqrs];
    const resolvedSearchPath = searchPath || defaultSearchPath();
    if (resolvedSearchPath) runArgs.push("--search-path", resolvedSearchPath);
    runArgs.push("--", resolve(ql));

    const run = spawnSync("codeql", runArgs, { encoding: "utf8", maxBuffer: QUERY_MAX_BUFFER });
    if (run.status !== 0) {
      return {
        ok: false,
        phase: "run",
        status: run.status,
        stdout: (run.stdout ?? "").slice(0, QUERY_STDOUT_LIMIT),
        stderr: (run.stderr ?? "").slice(0, QUERY_STDERR_LIMIT)
      };
    }

    const decode = spawnSync(
      "codeql",
      ["bqrs", "decode", `--format=${format}`, "--", bqrs],
      { encoding: "utf8", maxBuffer: QUERY_MAX_BUFFER }
    );

    return {
      ok: decode.status === 0,
      phase: "decode",
      status: decode.status,
      stdout: (decode.stdout ?? "").slice(0, QUERY_STDOUT_LIMIT),
      stderr: [
        run.stderr,
        decode.stderr
      ].filter(Boolean).join("\n").slice(0, QUERY_STDERR_LIMIT)
    };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
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
        format: z.string().optional(),
        searchPath: z.string().optional()
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
