#!/usr/bin/env node
// Finalize phase for /semgrep-rule. Validates that each rule the agent claims to
// have written actually exists under .kuzushi/rules/ and looks like a Semgrep
// rule, then writes the manifest .kuzushi/semgrep-rules.json indexing them.
// No findings promotion — rule matches are triaged by /sast or seed /variant-hunt.

import { resolve, join, relative } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";

function fail(message) {
  console.error(`semgrep-rule-finalize: ${message}`);
  process.exit(1);
}

// Light structural check (no YAML dep): a Semgrep rule file declares a `rules:`
// list with an `id:` and at least one pattern key. Semgrep itself validates on run.
function looksLikeSemgrepRule(text) {
  return /(^|\n)\s*rules\s*:/.test(text) &&
    /(^|\n)\s*-?\s*id\s*:/.test(text) &&
    /pattern(s|-either|-regex)?\s*:/.test(text);
}

export function finalizeSemgrepRule(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.semgrep-rule.json");
  if (!existsSync(draftPath)) fail(`no draft.semgrep-rule.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.semgrep-rule.json is not valid JSON"); }
  if (!Array.isArray(draft.rules)) fail("draft must have a rules[] array");

  const rules = draft.rules.map((r) => {
    const id = r.ruleId ?? r.id ?? "(unknown)";
    if (!r.seedFingerprint) fail(`rule ${id}: seedFingerprint is required`);
    const rulePath = r.rulePath ? resolve(r.rulePath) : null;
    if (!rulePath || !existsSync(rulePath)) fail(`rule ${id}: rulePath does not exist (${r.rulePath}). Write the rule file before finalizing.`);
    const text = readFileSync(rulePath, "utf8");
    if (!looksLikeSemgrepRule(text)) fail(`rule ${id}: ${r.rulePath} does not look like a Semgrep rule (needs rules:/id:/pattern*).`);
    const testStatus = String(r.testStatus ?? "");
    if (!/pass|matched|positive|ok|untested/i.test(testStatus)) {
      fail(`rule ${id}: record a testStatus (e.g. "positive matched + negative clean", or "untested: semgrep missing").`);
    }
    return {
      seedFingerprint: r.seedFingerprint,
      ruleId: id,
      cwe: (Array.isArray(r.cwe) ? r.cwe[0] : r.cwe) ?? "",
      rulePath: relative(resolvedTarget, rulePath),
      languages: Array.isArray(r.languages) ? r.languages : [],
      testStatus,
      notes: String(r.notes ?? "")
    };
  });

  const manifest = { version: "1.0", generatedAt: new Date().toISOString(), target: resolvedTarget, ruleCount: rules.length, rules };
  atomicWrite(store.semgrepRulesPath, `${JSON.stringify(manifest, null, 2)}\n`);

  const run = openRun(resolvedTarget, "semgrep-rule-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    ruleCount: rules.length, rulesDir: relative(resolvedTarget, store.rulesDir),
    semgrepRulesPath: store.semgrepRulesPath,
    rules: rules.map((r) => ({ ruleId: r.ruleId, rulePath: r.rulePath, testStatus: r.testStatus }))
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("semgrep-rule-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeSemgrepRule(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
