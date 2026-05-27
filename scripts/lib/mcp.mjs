// MCP launcher + health checker for the plugin-owned servers under mcp/servers/.
//
// Each backend is a plain Node script that speaks JSON-RPC over stdio using the
// @modelcontextprotocol/sdk. Health checks perform a real initialize +
// tools/list handshake so we don't just trust that a file exists.

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// The backends this plugin actually wires into .mcp.json.
export const SUPPORTED_BACKENDS = ["tree-sitter", "semgrep", "codeql", "joern", "gtags", "codegraph", "concolic"];

const DEFAULT_HEALTH_TIMEOUT_MS = 5000;

export function serverPath(name) {
  return resolve(PLUGIN_ROOT, "mcp", "servers", `${name}.mjs`);
}

export function isServerInstalled(name) {
  try {
    return existsSync(serverPath(name));
  } catch {
    return false;
  }
}

// Live readiness check: spawn the server, run initialize + tools/list, close.
// Times out after options.timeoutMs (default 5000).
export async function mcpHealth(name, options = {}) {
  if (!SUPPORTED_BACKENDS.includes(name)) {
    return { backend: name, ready: false, reason: "unsupported backend" };
  }
  const path = serverPath(name);
  if (!existsSync(path)) {
    return { backend: name, ready: false, reason: "server file not found", installable: true };
  }

  const transport = new StdioClientTransport({ command: process.execPath, args: [path] });
  const client = new Client({ name: "kuzushi-health-probe", version: "0.1.0" }, { capabilities: {} });

  const timeoutMs = Number(options.timeoutMs ?? DEFAULT_HEALTH_TIMEOUT_MS);
  let timer;
  try {
    await Promise.race([
      client.connect(transport),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`mcpHealth timed out after ${timeoutMs}ms`)), timeoutMs);
      })
    ]);
    const tools = await client.listTools();
    return { backend: name, ready: true, tools: tools.tools?.map((tool) => tool.name) ?? [] };
  } catch (error) {
    return { backend: name, ready: false, reason: error.message };
  } finally {
    if (timer) clearTimeout(timer);
    try { await client.close(); } catch {}
  }
}
