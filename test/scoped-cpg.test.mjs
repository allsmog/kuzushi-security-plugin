// Scoped (light) CPG — the scalable cross-function memory lane. The pure scope-selection
// is always tested; the build+query path is gated on the `joern` CLI (skips offline, runs
// in the joern-verify job) and uses a tiny fixture so it stays fast.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scopeForFile, buildScopedCpg, runJoernQuery, investigateFile, joernAvailable } from "../scripts/lib/scoped-cpg.mjs";

const STARTER = join(dirname(fileURLToPath(import.meta.url)), "..", "packs", "starter");

test("scopeForFile dir mode bounds the CPG to the file's subsystem (pure, always runs)", () => {
  const s = scopeForFile("/repo", "deps/lua/src/lbaselib.c", { mode: "dir" });
  assert.equal(s.scopeDir, "deps/lua/src", "dir scope is the subsystem directory");
  assert.equal(s.files, null);
  // a top-level file scopes to '.'
  assert.equal(scopeForFile("/repo", "main.c", { mode: "dir" }).scopeDir, ".");
});

const skip = joernAvailable() ? false : "joern CLI not on PATH";

test("scoped CPG builds over a bounded file set and a memory query runs (light + scalable)", { skip }, () => {
  // A tiny 2-file fixture with a textbook double-free across the file.
  const repo = mkdtempSync(join(tmpdir(), "kz-scoped-fx-"));
  mkdirSync(join(repo, "sub"), { recursive: true });
  writeFileSync(join(repo, "sub", "a.c"),
    "void g(char*p);\nvoid f(char *p){\n  free(p);\n  g(p);\n  free(p);\n}\n");
  writeFileSync(join(repo, "sub", "b.c"), "void g(char *p){ (void)p; }\n");

  // Build scoped to the subsystem dir — cost scales with the 2-file scope, not a repo.
  const built = buildScopedCpg(repo, { scopeDir: "sub" });
  assert.ok(built.ok, `scoped build failed: ${built.reason ?? ""}`);
  assert.ok(built.cpgPath, "produced a cpg path");
  assert.ok(built.buildMs >= 0, "records build time");

  // The double-free query runs cleanly against the scoped CPG (exit 0; results optional).
  const q = runJoernQuery(built.cpgPath, join(STARTER, "joern", "double-free.sc"));
  assert.ok(q.ok, `query failed to run: ${q.stderr ?? ""}`);
  assert.ok(Array.isArray(q.flows), "returns a flows array");
});

test("investigateFile does scope→build→query in one call for a file under investigation", { skip }, () => {
  const repo = mkdtempSync(join(tmpdir(), "kz-scoped-inv-"));
  mkdirSync(join(repo, "lib"), { recursive: true });
  writeFileSync(join(repo, "lib", "x.c"),
    "void f(char *p){\n  free(p);\n  use(p);\n}\n");
  const r = investigateFile(repo, "lib/x.c", join(STARTER, "joern", "use-after-free.sc"), { mode: "dir" });
  assert.ok(r.ok, `investigate failed: ${r.reason ?? ""}`);
  assert.equal(r.scope.scopeDir, "lib", "scoped to the file's subsystem");
  assert.ok(Array.isArray(r.flows));
});

test("verify-prepare auto-attaches cpgLeads to a memory finding, not to a non-memory one", { skip }, async () => {
  const { storeFor } = await import("../scripts/lib/artifact-store.mjs");
  const { prepareVerify } = await import("../scripts/cmd/verify-prepare.mjs");
  const repo = mkdtempSync(join(tmpdir(), "kz-vcpg-"));
  mkdirSync(join(repo, ".kuzushi"), { recursive: true });
  mkdirSync(join(repo, "core"), { recursive: true });
  // A cross-function UAF: free in f(), use in the same subsystem.
  writeFileSync(join(repo, "core", "obj.c"), "void use(char*p);\nvoid f(char *p){\n  free(p);\n  use(p);\n}\n");
  writeFileSync(join(repo, "core", "use.c"), "void use(char *p){ (void)p; }\n");
  const findings = (cwe) => ({ version: "1.0", schemaVersion: "findings.v1", target: repo, findings: [
    { schemaVersion: "finding.v1", fingerprint: cwe.replace(/\D/g, "").padEnd(16, "0"), source: "deep-scan", cwe, status: "open",
      title: `${cwe} lead`, evidence: [{ filePath: "core/obj.c", startLine: 3 }] }
  ] });

  // Memory class (CWE-416) → cpgLeads attached.
  writeFileSync(storeFor(repo).findingsPath, JSON.stringify(findings("CWE-416")) + "\n");
  let prep = JSON.parse(readFileSync(prepareVerify(repo, { maxCandidates: 3 }).prepPath, "utf8"));
  assert.equal(prep.candidates[0].recommendedProofLane, "sanitize-pov");
  assert.ok(Array.isArray(prep.candidates[0].cpgLeads) && prep.candidates[0].cpgLeads.length > 0, "memory finding gets cpgLeads");

  // Non-memory class (CWE-89) → no cpgLeads (the lane is memory-only).
  writeFileSync(storeFor(repo).findingsPath, JSON.stringify(findings("CWE-89")) + "\n");
  prep = JSON.parse(readFileSync(prepareVerify(repo, { maxCandidates: 3 }).prepPath, "utf8"));
  assert.equal(prep.candidates[0].recommendedProofLane, "verify");
  assert.ok(!prep.candidates[0].cpgLeads, "non-memory finding is not CPG-enriched");
});
