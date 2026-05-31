// fuzz-triage must turn a raw fuzzer crash into a classified bug: read the crash log,
// run it through the sanitizer oracle, and group by exact error class with the CWE
// attached. This is the discovery-via-execution loop — a fuzzer find is only useful
// once triaged to "heap-use-after-free / CWE-416". Deterministic (no compiler).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { fuzzTriage } from "../scripts/cmd/fuzz-triage.mjs";
import { fuzzInit } from "../scripts/cmd/fuzz-init.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-fz-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}

test("fuzz-triage classifies a crash via the sanitizer report → exact CWE", () => {
  const t = repo();
  const store = storeFor(t);
  mkdirSync(store.fuzzDir, { recursive: true });
  // A crash log as a sanitized libFuzzer run would emit.
  const logA = join(t, ".kuzushi", "crashA.log");
  writeFileSync(logA, "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0xdead\n READ of size 8\n    #0 0x1 in use_it /src/cache.c:88\n");
  // A run doc as fuzz-run would write.
  writeFileSync(store.fuzzRunPath, JSON.stringify({
    schemaVersion: "fuzz-run.v1", target: t,
    results: [
      { findingFingerprint: "fp-uaf", engine: "libfuzzer", language: "c", proofVerdict: "exploited", proofLevel: 4, logPath: logA, harnessDir: join(t, "h") }
    ]
  }) + "\n");

  const res = fuzzTriage(t);
  assert.equal(res.status, "completed");
  const doc = JSON.parse(readFileSync(store.fuzzTriagePath, "utf8"));
  assert.equal(doc.groups.length, 1);
  const g = doc.groups[0];
  assert.equal(g.cwe, "CWE-416", "the fuzz crash is triaged to use-after-free");
  assert.equal(g.sanitizer.errorClass, "heap-use-after-free");
  assert.equal(g.sanitizer.frame0.line, 88);
});

test("fuzz-init instruments native libFuzzer targets with sanitizers", () => {
  const t = repo();
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/parse.c"), "void p(char*s){}\n");
  upsertFindings(t, [{ source: "systems-hunt", refId: "n1", title: "oob", severity: "high",
    cwe: "CWE-787", verdict: "exploitable", status: "confirmed", evidence: [{ filePath: "src/parse.c", startLine: 1 }], rationale: "x" }]);
  const res = fuzzInit(t, {});
  const plan = JSON.parse(readFileSync(storeFor(t).fuzzPlanPath, "utf8"));
  const c = plan.candidates.find((x) => x.language === "c");
  assert.ok(c, "a C candidate was planned");
  assert.ok(c.sanitize, "C candidate carries sanitizer build instrumentation");
  assert.match(c.sanitize.cflags, /-fsanitize=address/, "always ASan-instrumented");
  assert.ok(c.sanitize.buildRunCommand, "carries a build+run command");
  // Engine is environment-dependent: libFuzzer when its runtime links, else the
  // portable ASan dumb-fuzz driver. Both are valid; assert the right shape per engine.
  // Engine ladder (environment-dependent): local libFuzzer → docker libFuzzer → portable
  // ASan dumb-fuzz driver. Assert the right shape per engine.
  assert.ok(["libfuzzer", "libfuzzer-docker", "asan-dumbfuzz"].includes(c.sanitize.engine), `engine ${c.sanitize.engine}`);
  if (c.sanitize.engine === "asan-dumbfuzz") assert.match(c.sanitize.buildRunCommand, /fuzz-driver\.c/, "dumb-fuzz links the portable driver");
  else assert.match(c.sanitize.buildRunCommand, /-fsanitize=fuzzer/, "libfuzzer engines build with -fsanitize=fuzzer");
});

test("fuzz-init harvests gate-clearing seeds (path-solve + verify) into the corpus", () => {
  const t = repo();
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/parse.c"), "void p(char*s){}\n");
  // a finding carrying concrete inputs from path-solve and verify
  upsertFindings(t, [{ source: "systems-hunt", refId: "n1", title: "oob", severity: "high",
    cwe: "CWE-787", verdict: "exploitable", status: "confirmed",
    evidence: [{ filePath: "src/parse.c", startLine: 1 }], rationale: "x",
    pathSolution: { solvedInput: { payload: "RXAAAA" } },
    verification: { verdict: "confirmed-exploitable", confidence: 0.9, verifiedAt: "2026-01-01T00:00:00Z", pocSketch: { payload: "RX-BBBBBBBBBBBBBBBBBBBB" } } }]);
  const res = fuzzInit(t, {});
  const plan = JSON.parse(readFileSync(storeFor(t).fuzzPlanPath, "utf8"));
  const c = plan.candidates.find((x) => x.language === "c");
  assert.ok(c, "C candidate planned");
  assert.equal(c.seedCorpusCount, 2, "both path-solve and verify payloads seeded");
  const files = readdirSync(c.corpusDir);
  assert.equal(files.length, 2, "two seed files written to corpus/");
  // the dumb-fuzz buildRunCommand passes the corpus dir to the driver
  assert.match(c.sanitize.buildRunCommand, /corpus/);
});
