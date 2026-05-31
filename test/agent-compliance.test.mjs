// Structural compliance for agents/*.md against the CLAUDE.md authoring standard.
// This operationalizes the "full breadth" quality bar: the two required sections are a
// HARD gate (every security agent must teach when-not-to-use and which rationalizations
// to reject), and worked-example coverage is REPORTED (the breadth-rollout checklist)
// so we can see, run to run, how many finder/verifier agents still need one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const AGENTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "agents");
const agentFiles = readdirSync(AGENTS_DIR).filter((f) => f.endsWith(".md"));
const read = (f) => readFileSync(join(AGENTS_DIR, f), "utf8");

// The agents that promote or adjudicate a finding — these are the ones a worked example
// most helps (turning "read the right file" into "found the bug"), and the ones that must
// emit derived-severity inputs.
const FINDER_AGENTS = new Set([
  "threat-hunter.md", "deep-hunter.md", "deep-scanner.md", "systems-hunter.md",
  "authz-reviewer.md", "logic-hunter.md", "crypto-reviewer.md", "sharp-edges-analyzer.md",
  "supply-chain-auditor.md", "iac-reviewer.md", "taint-flow-tracer.md", "taint-triager.md",
  "diff-reviewer.md", "variant-hunter.md", "chain-finder.md", "sast-triager.md",
  "binary-recon.md", "verifier.md", "mem-exploit-analyst.md"
]);

test("every agent has the two required sections (When NOT to use + Rationalizations to Reject)", () => {
  const missing = [];
  for (const f of agentFiles) {
    const body = read(f).toLowerCase();
    const hasNotUse = body.includes("when not to use");
    const hasRationalizations = body.includes("rationalizations to reject");
    if (!hasNotUse || !hasRationalizations) {
      missing.push(`${f} (whenNotToUse=${hasNotUse}, rationalizations=${hasRationalizations})`);
    }
  }
  assert.deepEqual(missing, [], `agents missing a required section:\n  ${missing.join("\n  ")}`);
});

test("worked-example coverage across finder/verifier agents (reported, not yet enforced)", (t) => {
  const withExample = [];
  const without = [];
  for (const f of FINDER_AGENTS) {
    const body = read(f).toLowerCase();
    (body.includes("## worked example") ? withExample : without).push(f);
  }
  t.diagnostic(`worked-example coverage: ${withExample.length}/${FINDER_AGENTS.size} finder agents`);
  if (without.length) t.diagnostic(`still need a worked example: ${without.sort().join(", ")}`);
  // Floor ratchet: once an agent gains a worked example it must not silently lose it.
  // Bump this number as the breadth rollout proceeds; it can only go up.
  const FLOOR = 19;
  assert.ok(withExample.length >= FLOOR, `worked-example coverage regressed below ${FLOOR}`);
});
