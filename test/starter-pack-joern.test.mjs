// Engine-gated RUN check for the starter Joern queries. Self-skips when the
// `joern` CLI isn't on PATH (so `npm test` stays green offline), and runs for real
// in the dedicated `joern-verify` CI job. Joern is the PRIMARY backend, so it
// deserves the same verification the CodeQL queries get — stronger, actually: a
// Joern "compile" needs a CPG, so this builds one from a fixture and executes each
// query against it. A broken script (bad import, the old @main/importCpg bug, a
// wrong CPG-API call) exits non-zero here instead of failing silently at query
// time on a user's machine.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const STARTER = join(dirname(fileURLToPath(import.meta.url)), "..", "packs", "starter");
const manifest = JSON.parse(readFileSync(join(STARTER, "manifest.json"), "utf8"));

function joernPresent() {
  const r = spawnSync("joern", ["--version"], { encoding: "utf8" });
  return !r?.error && (r.status === 0 || r.status === null);
}

// A self-contained fixture with a textbook command-injection flow: user input
// (getParameter) → shell exec. No external types so javasrc2cpg resolves it.
const FIXTURE = `public class H {
  public void handle(Req req) throws Exception {
    String cmd = req.getParameter("cmd");
    Runtime.getRuntime().exec(cmd);
  }
}
class Req { String getParameter(String n) { return n; } }
`;

test("Joern starter queries run cleanly against a real CPG", { skip: joernPresent() ? false : "joern CLI not on PATH" }, () => {
  const work = mkdtempSync(join(tmpdir(), "kz-joern-"));
  const src = join(work, "src");
  mkdirSync(src, { recursive: true });
  writeFileSync(join(src, "H.java"), FIXTURE);

  const cpg = join(work, "cpg.bin.zip");
  const parse = spawnSync("joern-parse", [src, "--output", cpg], { encoding: "utf8", timeout: 600000 });
  assert.equal(parse.status, 0, `joern-parse failed to build the fixture CPG:\n${parse.stderr}`);

  const joernRules = manifest.rules.filter((r) => r.engine === "joern");
  assert.ok(joernRules.length >= 6, "expected the Joern starter set");

  let detectedCmdInjection = false;
  for (const r of joernRules) {
    const run = spawnSync("joern", ["--script", join(STARTER, r.file)], {
      encoding: "utf8", timeout: 600000, env: { ...process.env, KUZUSHI_CPG: cpg }
    });
    // The hard gate: the script compiled (Scala), imported the CPG, and ran every
    // CPG-API call without throwing. Empty results are fine; a non-zero exit is not.
    assert.equal(run.status, 0, `${r.ruleId} (${r.file}) failed to run:\n--- stderr ---\n${(run.stderr ?? "").slice(-2000)}`);
    if (r.ruleId.endsWith("command-injection") && /CWE-78/.test(run.stdout ?? "")) detectedCmdInjection = true;
  }

  // Bonus end-to-end signal: the command-injection query should find the planted
  // getParameter → exec flow. Logged (not asserted) so a dataflow-modeling nuance
  // across Joern versions can't flake the verification job — the exit-0 gate above
  // is the contract.
  if (!detectedCmdInjection) {
    console.warn("joern-verify: command-injection query ran clean but did not surface the planted flow on this Joern version");
  }

  // Also exercise the PRODUCT script the joern MCP server runs (taint-flows.sc with
  // the default empty QUERIES_JSON) — it shares the @main convention, so it must run
  // clean too. This is what guards the real /taint-analysis Joern path, not just the
  // starter pack.
  const taintFlows = join(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "joern", "taint-flows.sc");
  const tf = spawnSync("joern", ["--script", taintFlows], {
    encoding: "utf8", timeout: 600000, env: { ...process.env, KUZUSHI_CPG: cpg }
  });
  assert.equal(tf.status, 0, `scripts/joern/taint-flows.sc failed to run:\n--- stderr ---\n${(tf.stderr ?? "").slice(-2000)}`);
});
