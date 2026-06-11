#!/usr/bin/env node
// Provider-neutral /deep-hunt runner: prepare -> Codex OAuth bridge -> finalize.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import {
  candidateDraftSchema,
  pluginRootFromHere,
  readTargetFile,
  runCodexBridge,
  structuredJsonFromResponse,
} from "../lib/llm-runner.mjs";
import { prepareDeepHunt } from "./deep-hunt-prepare.mjs";
import { finalizeDeepHunt } from "./deep-hunt-finalize.mjs";

const DEFAULT_MAX_FILE_BYTES = 100_000;
const DEFAULT_MAX_GRAPH_BYTES = 16_000;

function deepHuntSystemPrompt(agentPrompt) {
  return [
    "You are running Kuzushi /deep-hunt through the provider-neutral Codex bridge.",
    "Use only the supplied local source excerpts, anchors, and call graph hints. This is read-only static analysis.",
    "A finding requires a confirmed path with >=2 hops spanning >=2 distinct files, a CWE, rationale >=150 chars, and selfCheck >=40 chars.",
    "If you cannot confirm a cross-file path, emit candidate or rejected. Do not fabricate missing hops.",
    "",
    agentPrompt,
  ].join("\n");
}

function deepHuntPrompt(prep, fileReads, graphHints) {
  return [
    "## Task",
    "Walk the strongest source-to-sink hypotheses from the anchors and emit deep-hunt candidates. Return JSON only.",
    "",
    "## Prep",
    JSON.stringify({
      target: prep.target,
      scopeDir: prep.scopeDir,
      budget: prep.budget,
      anchorCount: prep.anchorCount,
      byKind: prep.byKind,
      unanchoredCount: prep.unanchoredCount,
      reachability: prep.reachability,
      anchors: prep.anchors,
    }, null, 2),
    "",
    "## Call Graph Hints",
    graphHints.map(renderGraphHint).join("\n\n") || "No call graph hints captured.",
    "",
    "## Files",
    fileReads.map(renderFileRead).join("\n\n"),
    "",
    "## Output",
    "Return {\"candidates\":[...]} using verdict finding|candidate|rejected and evidenceLevel path|linked|candidate. Empty candidates is valid when no cross-file flow is supportable.",
  ].join("\n");
}

function renderFileRead(file) {
  return [
    `### ${file.filePath}`,
    `bytes=${file.bytes} truncated=${file.truncated}`,
    "```",
    file.content,
    "```",
  ].join("\n");
}

function renderGraphHint(hint) {
  return [
    `### anchor ${hint.filePath}:${hint.line} ${hint.symbol ? `symbol=${hint.symbol}` : ""}`,
    hint.callers ? `callers:\n${hint.callers}` : "callers: <not captured>",
    hint.callees ? `callees:\n${hint.callees}` : "callees: <not captured>",
  ].join("\n");
}

function normalizeDraft(value) {
  const candidates = Array.isArray(value?.candidates) ? value.candidates : [];
  return { candidates };
}

function anchorFiles(prep, maxFiles) {
  const out = [];
  const seen = new Set();
  for (const anchor of prep.anchors ?? []) {
    const filePath = anchor?.filePath;
    if (!filePath || seen.has(filePath)) continue;
    seen.add(filePath);
    out.push(filePath);
    if (out.length >= maxFiles) break;
  }
  return out;
}

function graphHintsFor(prep, maxBytes) {
  const hints = [];
  for (const anchor of (prep.anchors ?? []).slice(0, Number(prep.budget?.maxAnchors ?? 12))) {
    const symbol = anchor?.enclosingFunction?.name;
    hints.push({
      filePath: anchor.filePath,
      line: anchor.line,
      symbol,
      callers: symbol ? runHelper(prep.reachability?.callersCli, ["--target", prep.target, "--symbol", symbol], maxBytes) : "",
      callees: runHelper(prep.reachability?.calleesCli, ["--target", prep.target, "--file", anchor.filePath, "--line", String(anchor.line ?? 1)], maxBytes),
    });
  }
  return hints;
}

function runHelper(script, args, maxBytes) {
  if (!script) return "";
  const result = spawnSync(process.execPath, [script, ...args], {
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: Math.max(maxBytes * 2, 1024 * 1024),
  });
  const text = result.status === 0 ? result.stdout : `${result.stdout}\n${result.stderr}`;
  return String(text ?? "").slice(0, maxBytes);
}

export function runDeepHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const prepResult = prepareDeepHunt(resolvedTarget, input);
  const prep = JSON.parse(readFileSync(prepResult.prepPath, "utf8"));

  if (!prep.anchors?.length) {
    atomicWrite(prepResult.draftPath, `${JSON.stringify({ candidates: [] }, null, 2)}\n`);
    return {
      ...finalizeDeepHunt(resolvedTarget, prepResult.runDir),
      prep: prepResult,
      modelRun: { skipped: true, reason: "no anchors selected" },
    };
  }

  const maxReadFiles = Number(input.maxReadFiles ?? input.maxFiles ?? 12);
  const maxFileBytes = Number(input.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES);
  const maxGraphBytes = Number(input.maxGraphBytes ?? DEFAULT_MAX_GRAPH_BYTES);
  const files = anchorFiles(prep, maxReadFiles)
    .map((filePath) => readTargetFile(resolvedTarget, filePath, maxFileBytes))
    .filter(Boolean);
  const graphHints = graphHintsFor(prep, maxGraphBytes);

  const pluginRoot = pluginRootFromHere(import.meta.url);
  const agentPrompt = readFileSync(join(pluginRoot, "agents", "deep-hunter.md"), "utf8");
  const response = runCodexBridge({
    target: resolvedTarget,
    input,
    systemPrompt: deepHuntSystemPrompt(agentPrompt),
    prompt: deepHuntPrompt(prep, files, graphHints),
    structuredOutput: {
      name: "deep_hunt_draft",
      strict: true,
      schema: candidateDraftSchema("huntId"),
    },
  });
  const draft = normalizeDraft(structuredJsonFromResponse(response));
  atomicWrite(prepResult.draftPath, `${JSON.stringify(draft, null, 2)}\n`);
  const finalized = finalizeDeepHunt(resolvedTarget, prepResult.runDir);
  return {
    ...finalized,
    prep: prepResult,
    modelRun: {
      model: input.model ?? process.env.KUZUSHI_MODEL ?? "openai-codex:gpt-5.5",
      inputTokens: response.input_tokens ?? 0,
      outputTokens: response.output_tokens ?? 0,
      candidateCount: draft.candidates.length,
      readFiles: files.map((file) => ({
        filePath: file.filePath,
        bytes: file.bytes,
        truncated: file.truncated,
      })),
      graphHintCount: graphHints.length,
    },
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('deep-hunt-run --target <path> [--input \'{"maxAnchors":12,"scopeDir":"src"}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("deep-hunt-run: --target is required");
    process.exit(1);
  }
  emitResult(runDeepHunt(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
