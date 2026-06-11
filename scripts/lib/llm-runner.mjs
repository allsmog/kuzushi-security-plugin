import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ANTHROPIC_ENV = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_OAUTH_TOKEN",
  "KUZUSHI_ANTHROPIC_OAUTH",
  "KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS",
];

export const DEFAULT_CODEX_MODEL = "openai-codex:gpt-5.5";

export function codexModelFromEnv(input = {}) {
  const model = String(input.model ?? process.env.KUZUSHI_MODEL ?? DEFAULT_CODEX_MODEL);
  if (!model.startsWith("openai-codex:")) {
    throw new Error(`Codex OAuth run requires an openai-codex model, got ${JSON.stringify(model)}`);
  }
  return model;
}

export function pluginRootFromHere(metaUrl) {
  return resolve(dirname(fileURLToPath(metaUrl)), "..", "..");
}

export function readCodexOauthCredential() {
  const path = process.env.KUZUSHI_OAUTH_CREDENTIALS
    || resolve(homedir(), ".kuzushi", "oauth-credentials.json");
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed?.["openai-codex"]?.access ? { path, access: parsed["openai-codex"].access } : null;
  } catch {
    return null;
  }
}

export function requireCodexOauth() {
  const credential = readCodexOauthCredential();
  if (!credential) {
    throw new Error("Codex OAuth credential not found. Run kuzushi auth login openai first.");
  }
  return credential;
}

export function bridgePathFromEnv() {
  if (process.env.KUZUSHI_LANGGRAPH_BRIDGE) return process.env.KUZUSHI_LANGGRAPH_BRIDGE;
  return resolve(homedir(), "vibe-code", "kuzushi", "scripts", "langgraph-bridge.mjs");
}

export function sanitizedBridgeEnv(extra = {}) {
  const env = { ...process.env, ...extra };
  for (const key of ANTHROPIC_ENV) delete env[key];
  return env;
}

export function runCodexBridge({
  target,
  systemPrompt,
  prompt,
  structuredOutput,
  input = {},
  runtimeOptions = {},
}) {
  const model = codexModelFromEnv(input);
  requireCodexOauth();
  const bridge = bridgePathFromEnv();
  if (!existsSync(bridge)) throw new Error(`Kuzushi LangGraph bridge not found: ${bridge}`);

  const request = {
    model,
    cwd: resolve(target),
    systemPrompt,
    prompt,
    structuredOutput,
    maxOutputTokens: Number(input.maxOutputTokens ?? input.maxTokens ?? 12000),
    toolPolicy: { mcps: input.mcps === true },
    runtimeOptions,
  };
  const result = spawnSync(process.execPath, [bridge], {
    input: JSON.stringify(request),
    encoding: "utf8",
    env: sanitizedBridgeEnv(),
    timeout: Number(input.timeoutMs ?? 900000),
    maxBuffer: Number(input.maxBuffer ?? 40 * 1024 * 1024),
  });
  if (result.error) throw result.error;
  const raw = String(result.stdout ?? "").trim();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`LangGraph bridge returned non-JSON output: ${error.message}: ${raw.slice(0, 800)}`);
  }
  if (result.status !== 0 || parsed.ok === false) {
    const stderr = String(result.stderr ?? "").trim();
    throw new Error(`LangGraph bridge failed: ${parsed.error ?? stderr ?? `exit ${result.status}`}`);
  }
  return parsed;
}

export function structuredJsonFromResponse(response) {
  if (response?.structured && typeof response.structured === "object") return response.structured;
  const text = String(response?.text ?? "").trim();
  if (!text) return {};
  const fenced = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  const candidate = fenced ? fenced[1].trim() : text;
  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) return JSON.parse(candidate.slice(start, end + 1));
    throw new Error("Model response did not contain a JSON object");
  }
}

export function safeTargetRelative(target, filePath) {
  const resolvedTarget = resolve(target);
  const abs = resolve(resolvedTarget, String(filePath ?? ""));
  const rel = relative(resolvedTarget, abs);
  if (!rel || rel.startsWith("..") || rel.startsWith("/") || rel.includes("..")) return null;
  return { abs, rel };
}

export function readTargetFile(target, filePath, maxBytes) {
  const safe = safeTargetRelative(target, filePath);
  if (!safe || !existsSync(safe.abs)) return null;
  const raw = readFileSync(safe.abs, "utf8");
  const truncated = raw.length > maxBytes;
  return {
    filePath: safe.rel,
    bytes: raw.length,
    truncated,
    content: truncated ? raw.slice(0, maxBytes) : raw,
  };
}

export function candidateDraftSchema(idField) {
  return {
    type: "object",
    required: ["candidates"],
    properties: {
      candidates: {
        type: "array",
        items: {
          type: "object",
          required: [idField, "verdict", "rationale"],
          properties: {
            [idField]: { type: "string" },
            title: { type: "string" },
            cwe: { type: "string" },
            bugClass: { type: "string" },
            severity: { type: "string" },
            accessLevel: { type: "string" },
            preconditions: { type: "array", items: { type: "string" } },
            verdict: { type: "string", enum: ["finding", "candidate", "rejected"] },
            evidenceLevel: { type: "string" },
            rationale: { type: "string" },
            selfCheck: { type: "string" },
            nextChecks: { type: "array", items: { type: "string" } },
            guards: { type: "array", items: { type: "string" } },
            evidenceAnchors: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  filePath: { type: "string" },
                  startLine: { type: "integer" },
                },
              },
            },
            source: { type: "object" },
            sink: { type: "object" },
            path: { type: "array", items: { type: "object" } },
          },
        },
      },
    },
  };
}
