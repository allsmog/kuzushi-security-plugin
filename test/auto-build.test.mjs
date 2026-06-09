// autoBuildDecision is the deep-by-default gate: build the heavy semantic index
// automatically only when it's a free, local operation (CLI already installed),
// source exists, nothing is built/building, and policy permits. These pin that it
// never triggers a surprise network install and that ci-locked ("off") stays quiet.

import { test } from "node:test";
import assert from "node:assert/strict";
import { autoBuildDecision, effectiveAutoBuildSetting } from "../scripts/lib/auto-build.mjs";

test("CLI present + source + not built + when-installed → build, no network", () => {
  const d = autoBuildDecision({ setting: "when-installed", sourcePresent: true, codeqlCli: true, joernCli: true });
  assert.equal(d.codeql, "build");
  assert.equal(d.joern, "build");
  assert.equal(d.which, "both");
  assert.equal(d.anyBuild, true);
});

test("CLI absent → OFFER (an install needs approval), never an auto-build", () => {
  const d = autoBuildDecision({ setting: "when-installed", sourcePresent: true, codeqlCli: false, joernCli: false });
  assert.equal(d.codeql, "offer");
  assert.equal(d.anyBuild, false);
  assert.equal(d.anyOffer, true);
});

test("only the installed engine builds; the missing one is offered", () => {
  const d = autoBuildDecision({ setting: "when-installed", sourcePresent: true, codeqlCli: true, joernCli: false });
  assert.equal(d.codeql, "build");
  assert.equal(d.joern, "offer");
  assert.equal(d.which, "codeql");
});

test('setting "off" (ci-locked) never builds even with the CLI present', () => {
  const d = autoBuildDecision({ setting: "off", sourcePresent: true, codeqlCli: true, joernCli: true });
  assert.equal(d.anyBuild, false);
  assert.equal(d.codeql, "skip");
});

test('setting "offer" always asks first, never auto-builds', () => {
  const d = autoBuildDecision({ setting: "offer", sourcePresent: true, codeqlCli: true, joernCli: true });
  assert.equal(d.anyBuild, false);
  assert.equal(d.codeql, "offer");
});

test("a build already in flight short-circuits to 'building' (no double-spawn)", () => {
  const d = autoBuildDecision({ setting: "when-installed", sourcePresent: true, dbBuilding: true, codeqlCli: true });
  assert.equal(d.codeql, "building");
  assert.equal(d.anyBuild, false);
});

test("already-built DBs report 'present', no rebuild", () => {
  const d = autoBuildDecision({ setting: "when-installed", sourcePresent: true, codeqlCli: true, codeqlDbBuilt: true, joernCli: true, joernCpgBuilt: true });
  assert.equal(d.codeql, "present");
  assert.equal(d.joern, "present");
  assert.equal(d.anyBuild, false);
});

test("no source → skip (nothing to index)", () => {
  const d = autoBuildDecision({ setting: "when-installed", sourcePresent: false, codeqlCli: true });
  assert.equal(d.codeql, "skip");
});

test("effectiveAutoBuildSetting reads the active profile, defaults to when-installed", () => {
  const policy = { activeProfile: "ci-locked", profiles: { "ci-locked": { analysis: { autoBuildDatabases: "off" } }, "developer-fast": { analysis: { autoBuildDatabases: "when-installed" } } } };
  assert.equal(effectiveAutoBuildSetting(policy), "off");
  assert.equal(effectiveAutoBuildSetting({ activeProfile: "developer-fast", profiles: {} }), "when-installed");
  assert.equal(effectiveAutoBuildSetting({ activeProfile: "x", profiles: { x: { analysis: { autoBuildDatabases: "bogus" } } } }), "when-installed");
});
