// Offline structural validation of the shipped starter query pack. The engines
// aren't in CI, so these checks — runnable everywhere — are the safety net that
// catches authoring mistakes a compile would otherwise be the only guard for.
// They would have caught the original bug where a Joern query used `@main` and
// never called importCpg (so it could never run against a CPG).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const STARTER = join(dirname(fileURLToPath(import.meta.url)), "..", "packs", "starter");
const manifest = JSON.parse(readFileSync(join(STARTER, "manifest.json"), "utf8"));

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

test("every manifest rule has well-formed metadata and an on-disk file", () => {
  assert.ok(manifest.rules.length >= 15, `expected the deepened pack (got ${manifest.rules.length})`);
  for (const r of manifest.rules) {
    assert.ok(["codeql", "joern"].includes(r.engine), `${r.ruleId}: engine`);
    assert.match(r.cwe, /^CWE-\d+$/, `${r.ruleId}: cwe`);
    assert.ok(r.ruleId && r.title && r.language, `${r.ruleId}: required fields`);
    assert.ok(existsSync(join(STARTER, r.file)), `${r.ruleId}: file ${r.file} missing`);
  }
});

test("no orphan query files — every .ql/.sc is registered in the manifest", () => {
  const registered = new Set(manifest.rules.map((r) => join(STARTER, r.file)));
  const onDisk = walk(STARTER).filter((p) => p.endsWith(".ql") || p.endsWith(".sc"));
  for (const f of onDisk) assert.ok(registered.has(f), `unregistered query file: ${f}`);
});

test("the pack spans a broad CWE set (deepened coverage)", () => {
  const cwes = new Set(manifest.rules.map((r) => r.cwe));
  for (const cwe of ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-94", "CWE-502", "CWE-601", "CWE-611", "CWE-918", "CWE-943", "CWE-1336"]) {
    assert.ok(cwes.has(cwe), `expected coverage for ${cwe}`);
  }
});

test("Joern queries follow the KUZUSHI_CPG convention (and never the @main pitfall)", () => {
  for (const r of manifest.rules.filter((x) => x.engine === "joern")) {
    const src = readFileSync(join(STARTER, r.file), "utf8");
    assert.match(src, /importCpg\(/, `${r.ruleId}: must load the CPG via importCpg`);
    assert.match(src, /io\.joern\.dataflowengineoss\.language/, `${r.ruleId}: missing dataflow import`);
    assert.match(src, /io\.shiftleft\.semanticcpg\.language/, `${r.ruleId}: missing semanticcpg import`);
    assert.match(src, /reachableByFlows/, `${r.ruleId}: not a dataflow query`);
    assert.match(src, /KUZUSHI_CPG/, `${r.ruleId}: must read KUZUSHI_CPG`);
    // Modern Joern's --script runner requires an @main entrypoint that calls
    // importCpg (the real contract — the original bug was a missing importCpg, not
    // the @main). joern-verify executes these against a real CPG to confirm.
    assert.match(src, /@main\s+def/, `${r.ruleId}: needs an @main entrypoint for modern Joern --script`);
  }
});

test("CodeQL queries use the standard-library security flow modules", () => {
  for (const r of manifest.rules.filter((x) => x.engine === "codeql")) {
    const src = readFileSync(join(STARTER, r.file), "utf8");
    assert.match(src, /@kind path-problem/, `${r.ruleId}: should be a path-problem`);
    assert.match(src, /@id\s+kuzushi\/starter\//, `${r.ruleId}: needs a kuzushi/starter @id`);
    assert.match(src, /import semmle\.\w+\.security\.dataflow\./, `${r.ruleId}: missing security dataflow import`);
    assert.match(src, /Flow::PathGraph/, `${r.ruleId}: missing the <Name>Flow::PathGraph import`);
    assert.match(src, /Flow::flowPath\(/, `${r.ruleId}: missing flowPath predicate`);
    assert.match(src, /^select /m, `${r.ruleId}: missing select clause`);
  }
});
