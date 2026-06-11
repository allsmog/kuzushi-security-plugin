#!/usr/bin/env node
// Provider-neutral /deep-scan runner: prepare -> Codex OAuth bridge -> finalize.
// This keeps the model boundary in a normal command instead of a Claude-specific
// subagent launch, while preserving the deterministic prepare/finalize contract.

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
import { prepareDeepScan } from "./deep-scan-prepare.mjs";
import { finalizeDeepScan } from "./deep-scan-finalize.mjs";

const DEFAULT_MAX_FILE_BYTES = 120_000;

function deepScanSystemPrompt(agentPrompt) {
  return [
    "You are running Kuzushi /deep-scan through the provider-neutral Codex bridge.",
    "Use only the supplied local source excerpts and metadata. This is read-only static analysis.",
    "Do not invent files, line numbers, guards, or data paths. If evidence is insufficient, emit candidate or rejected.",
    "A finding requires concrete evidenceAnchors, a CWE, rationale >=150 chars, and selfCheck >=40 chars.",
    "",
    agentPrompt,
  ].join("\n");
}

function deepScanPrompt(prep, fileReads) {
  return [
    "## Task",
    "Read the risk-ranked files and emit deep-scan candidates. Return JSON only.",
    "",
    "## Prep",
    JSON.stringify({
      target: prep.target,
      scopeDir: prep.scopeDir,
      budget: prep.budget,
      unreadCount: prep.unreadCount,
      fileCount: prep.fileCount,
      obligationCount: prep.obligationCount,
      files: prep.files,
    }, null, 2),
    "",
    "## Files",
    fileReads.map(renderFileRead).join("\n\n"),
    "",
    "## Output",
    "Return {\"candidates\":[...]} using verdict finding|candidate|rejected. Empty candidates is valid when no issue is supportable from the provided files.",
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

function normalizeDraft(value) {
  const candidates = Array.isArray(value?.candidates) ? value.candidates : [];
  return { candidates };
}

export function runDeepScan(target, input = {}) {
  const resolvedTarget = resolve(target);
  const prepResult = prepareDeepScan(resolvedTarget, input);
  const prep = JSON.parse(readFileSync(prepResult.prepPath, "utf8"));

  if (!prep.files?.length) {
    atomicWrite(prepResult.draftPath, `${JSON.stringify({ candidates: [] }, null, 2)}\n`);
    return {
      ...finalizeDeepScan(resolvedTarget, prepResult.runDir),
      prep: prepResult,
      modelRun: { skipped: true, reason: "no files selected" },
    };
  }

  const maxFileBytes = Number(input.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES);
  const files = prep.files
    .map((file) => readTargetFile(resolvedTarget, file.filePath, maxFileBytes))
    .filter(Boolean);
  const pluginRoot = pluginRootFromHere(import.meta.url);
  const agentPrompt = readFileSync(join(pluginRoot, "agents", "deep-scanner.md"), "utf8");
  const response = runCodexBridge({
    target: resolvedTarget,
    input,
    systemPrompt: deepScanSystemPrompt(agentPrompt),
    prompt: deepScanPrompt(prep, files),
    structuredOutput: {
      name: "deep_scan_draft",
      strict: true,
      schema: candidateDraftSchema("deepId"),
    },
  });
  const draft = normalizeDraft(structuredJsonFromResponse(response));
  atomicWrite(prepResult.draftPath, `${JSON.stringify(draft, null, 2)}\n`);
  const finalized = finalizeDeepScan(resolvedTarget, prepResult.runDir);
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
    },
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log('deep-scan-run --target <path> [--input \'{"maxFiles":8,"scopeDir":"src"}\']');
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("deep-scan-run: --target is required");
    process.exit(1);
  }
  emitResult(runDeepScan(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
