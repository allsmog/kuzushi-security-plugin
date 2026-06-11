// Engine-gated compile check for the starter CodeQL queries. Self-skips when the
// `codeql` CLI isn't on PATH (so `npm test` stays green offline and in the normal
// CI job), and runs for real in the dedicated `codeql-verify` CI job that installs
// the CodeQL bundle. This is what turns validated.compileVerified into a true
// signal: a wrong standard-library module name (e.g. a renamed *Flow module) fails
// here loudly instead of erroring at MCP query time on a user's machine.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, copyFileSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const STARTER = join(dirname(fileURLToPath(import.meta.url)), "..", "packs", "starter");
const manifest = JSON.parse(readFileSync(join(STARTER, "manifest.json"), "utf8"));

function codeqlPresent() {
  const r = spawnSync("codeql", ["version", "--format=terse"], { encoding: "utf8" });
  return !r?.error && r?.status === 0;
}

// The standard-library pack each language query depends on (shipped in the bundle).
const PACK_DEP = {
  javascript: "codeql/javascript-all",
  python: "codeql/python-all",
  java: "codeql/java-all",
  go: "codeql/go-all"
};

test("CodeQL starter queries compile against the standard library", { skip: codeqlPresent() ? false : "codeql CLI not on PATH" }, () => {
  const byLang = {};
  for (const r of manifest.rules.filter((r) => r.engine === "codeql")) {
    (byLang[r.language] ??= []).push(r);
  }
  for (const [lang, rules] of Object.entries(byLang)) {
    assert.ok(PACK_DEP[lang], `no standard-library pack mapping for language ${lang}`);
    const dir = mkdtempSync(join(tmpdir(), `kz-ql-${lang}-`));
    writeFileSync(join(dir, "qlpack.yml"),
      `name: kuzushi/starter-verify\nversion: 0.0.1\ndependencies:\n  ${PACK_DEP[lang]}: "*"\n`);
    for (const r of rules) copyFileSync(join(STARTER, r.file), join(dir, basename(r.file)));
    // Resolve deps from the bundled packs (best-effort; compile is the real gate).
    const install = spawnSync("codeql", ["pack", "install"], { cwd: dir, encoding: "utf8", timeout: 300000 });
    for (const r of rules) {
      const c = spawnSync("codeql", ["query", "compile", "--threads=0", "--", join(dir, basename(r.file))],
        { cwd: dir, encoding: "utf8", timeout: 300000 });
      assert.equal(c.status, 0,
        `${r.ruleId} (${r.file}) failed to compile:\n--- compile stderr ---\n${c.stderr}\n--- pack install stderr ---\n${install.stderr ?? ""}`);
    }
  }
});
