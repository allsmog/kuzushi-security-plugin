// Spine proof for the discovery-by-execution lane (Phase 2). The PROMOTION boundary —
// "a sanitizer-confirmed crash becomes a NEW proven finding with the sanitizer's exact
// CWE" — is tested here from CAPTURED sanitizer reports, with no compiler in the loop, so
// the spine is provable for free. (The compile+run half reuses sandbox.mjs, already
// covered by the gated sanitize-pov / sanitizers end-to-end tests.)

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSanitizerReport, detectToolchain } from "../scripts/lib/sanitizers.mjs";
import { buildDiscoveryFinding, finalizeFuzzDiscover, crashOffTargetOnly, WEAK_TIER } from "../scripts/cmd/fuzz-discover-finalize.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";

const tc = detectToolchain();
// Only meaningful when AddressSanitizer actually LINKS here (gcc with libasan, or a clang
// with compiler-rt). detectToolchain prefers such a compiler; gate on it being verified.
const ASAN_OK = Boolean(tc.cc && tc.asanVerified);

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-disc-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
  return t;
}
function readFindings(t) { return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings; }

// A real ASan stack-buffer-overflow report (the xackdel shape, CWE-121).
const OVERFLOW_REPORT = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x16 at pc 0x10\n WRITE of size 64\n    #0 0x100 in xackdelCommand /src/t_stream.c:3538";
// A real ASan heap-use-after-free report (CWE-416).
const UAF_REPORT = "ERROR: AddressSanitizer: heap-use-after-free on address 0xdeadbeef\n READ of size 8\n    #0 0x1 in freeClient /src/networking.c:1422";

test("spine: a captured overflow report ⇒ a proven finding with the sanitizer's CWE", () => {
  const report = parseSanitizerReport(OVERFLOW_REPORT);
  const f = buildDiscoveryFinding({
    discovery: { title: "stack overflow in xackdelCommand", language: "c", evidence: [{ filePath: "src/t_stream.c", startLine: 3537 }] },
    report, backend: "local", provenAt: new Date().toISOString()
  });
  assert.equal(f.source, "fuzz-discover");
  assert.equal(f.status, "proven");
  assert.equal(f.cwe, "CWE-121", "CWE comes from the sanitizer report, not the agent");
  assert.equal(f.severity, "critical", "a controllable overflow is critical");
  assert.equal(f.poc.proofVerdict, "exploited");
  assert.equal(f.poc.sanitizer.errorClass, "stack-buffer-overflow");
});

test("spine: promotion persists a proven finding via upsertFindings", () => {
  const t = repo();
  const report = parseSanitizerReport(UAF_REPORT);
  const f = buildDiscoveryFinding({ discovery: { title: "UAF in freeClient", language: "c", evidence: [{ filePath: "src/networking.c", startLine: 1422 }] }, report, backend: "docker", provenAt: new Date().toISOString() });
  const { _crashKey, ...clean } = f;
  upsertFindings(t, [clean]);
  const fs = readFindings(t);
  assert.equal(fs.length, 1);
  assert.equal(fs[0].status, "proven");
  assert.equal(fs[0].proofState, "proven");
  assert.equal(fs[0].cwe, "CWE-416");
  assert.equal(fs[0].source, "fuzz-discover");
});

test("spine: NO sanitizer report ⇒ nothing promoted (never a false proof)", () => {
  const report = parseSanitizerReport("all good, exit 0");
  assert.equal(report, null);
  assert.equal(buildDiscoveryFinding({ discovery: { title: "x", language: "c" }, report, provenAt: new Date().toISOString() }), null);
});

test("end-to-end: finalize compiles a crafted overflow, runs it, and promotes a NEW proven finding", { skip: ASAN_OK ? false : "no ASan-linking toolchain" }, async () => {
  const t = repo();
  const runDir = join(storeFor(t).runsDir, "disc-e2e");
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(runDir, "draft.fuzz-discover.json"), JSON.stringify({
    backend: "local", trustLocal: true, discoveries: [{
      title: "crafted stack overflow", language: "c",
      evidence: [{ filePath: "vuln.c", startLine: 1 }],
      // The overflow lives in target code (vuln.c) that the harness DRIVES — not in the
      // harness itself. The finalize's first-party-frame gate requires the crash to land in
      // real target source (a self-crash inside harness.c would be rejected as scaffolding).
      harnessFiles: [
        { name: "vuln.c", content: "void vuln(volatile int n){char b[8];for(volatile int i=0;i<n;i++)b[i]=(char)65;}\n" },
        { name: "harness.c", content: "void vuln(volatile int);int main(){vuln(64);return 0;}\n" }
      ],
      buildRunCommand: `${tc.cc} -fsanitize=address,undefined -g -O0 vuln.c harness.c -o h && ./h`
    }]
  }));
  const res = await finalizeFuzzDiscover(t, runDir, { trustLocal: true, backend: "local" });
  assert.equal(res.status, "completed");
  assert.equal(res.provenCount, 1, "the overflow must be sanitizer-proven by execution");
  assert.equal(res.promotedCount, 1, "and promoted as a NEW finding");
  const fs = readFindings(t).filter((f) => f.source === "fuzz-discover");
  assert.equal(fs.length, 1);
  assert.equal(fs[0].status, "proven");
  assert.match(fs[0].cwe, /CWE-(121|787)/, "CWE recovered from the real abort");
});

// --- precision gates (the eval forensics: a benign signed-overflow in a vendored client
// parser, reached only by a standalone leaf, was wrongly promoted `proven/high`) -----------

test("gate: a crash whose frames are ALL vendored/harness is off-target (not promotable)", () => {
  // The exact failure shape: the crash is in deps/hiredis reached from a standalone harness.
  const vendored = "ERROR: AddressSanitizer: ...\n #0 0x1 in processBulkItem deps/hiredis/read.c:432\n #1 0x2 in main harness.c:10";
  assert.equal(crashOffTargetOnly(vendored), true, "vendored-deps + harness frames only ⇒ off-target");
});

test("gate: a crash reaching first-party code is NOT off-target (promotable)", () => {
  // A bug in an embedded interpreter reached via the real entry keeps a first-party frame.
  const reached = "ERROR: AddressSanitizer: heap-use-after-free\n #0 0x1 in lua_parse deps/lua/lparser.c:383\n #1 0x2 in evalCommand src/eval.c:550";
  assert.equal(crashOffTargetOnly(reached), false, "a src/ frame on the stack ⇒ reachable from a real entry");
  const direct = "ERROR: AddressSanitizer: stack-buffer-overflow\n #0 0x1 in xackdelCommand src/t_stream.c:3538";
  assert.equal(crashOffTargetOnly(direct), false);
});

test("gate: a bare signed-integer-overflow is weak-tier (candidate, not proven)", () => {
  // The hiredis false positive: a UBSan signed overflow with no memory-corruption consequence.
  const report = parseSanitizerReport("read.c:432:21: runtime error: signed integer overflow: 9223372036854775807 + 2 cannot be represented in type 'long long'\n #0 in processBulkItem read.c:432");
  assert.equal(report.errorClass, "integer-overflow");
  assert.equal(WEAK_TIER.has(report.errorClass), true, "bare integer-overflow must not auto-promote to proven");
  // A real memory class is NOT weak-tier.
  assert.equal(WEAK_TIER.has(parseSanitizerReport(OVERFLOW_REPORT).errorClass), false);
  assert.equal(WEAK_TIER.has(parseSanitizerReport(UAF_REPORT).errorClass), false);
});

// --- invariant oracle (non-crash classes): prototype pollution via a FRAMEWORK-owned check.
// The agent declares only the target; it writes no oracle code, so the proof is ungameable. ----

test("oracle: a vulnerable JS parser ⇒ proven CWE-1321 via the framework invariant oracle", async () => {
  const t = repo();
  // The minimist bug shape: a path-walk setter that descends through __proto__.
  writeFileSync(join(t, "vuln.js"), "module.exports=function(a){var o={};for(var i=0;i<a.length;i++){var m=/^--(.+)=(.*)$/.exec(a[i]);if(!m)continue;var p=m[1].split('.'),c=o;for(var j=0;j<p.length-1;j++){if(c[p[j]]===undefined)c[p[j]]={};c=c[p[j]];}c[p[p.length-1]]=m[2];}return o;};\n");
  const runDir = join(storeFor(t).runsDir, "disc-oracle");
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(runDir, "draft.fuzz-discover.json"), JSON.stringify({ discoveries: [{
    title: "prototype pollution", language: "javascript", oracle: "prototype-pollution",
    targetModule: "vuln.js", inputShape: "argv-array", evidence: [{ filePath: "vuln.js", startLine: 1 }]
  }] }));
  const res = await finalizeFuzzDiscover(t, runDir, { trustLocal: true, backend: "local" });
  assert.equal(res.provenCount, 1, "the framework oracle must prove the pollution");
  const fs = readFindings(t).filter((f) => f.source === "fuzz-discover");
  assert.equal(fs[0].status, "proven");
  assert.equal(fs[0].cwe, "CWE-1321");
});

test("oracle: a SAFE parser ⇒ nothing promoted (no false proof)", async () => {
  const t = repo();
  writeFileSync(join(t, "safe.js"), "module.exports=function(a){var o={};for(var i=0;i<a.length;i++){var m=/^--(.+)=(.*)$/.exec(a[i]);if(!m)continue;var k=m[1];if(k==='__proto__'||k==='constructor'||k==='prototype')continue;o[k]=m[2];}return o;};\n");
  const runDir = join(storeFor(t).runsDir, "disc-oracle-safe");
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(runDir, "draft.fuzz-discover.json"), JSON.stringify({ discoveries: [{
    title: "x", language: "javascript", oracle: "prototype-pollution", targetModule: "safe.js",
    inputShape: "auto", evidence: [{ filePath: "safe.js", startLine: 1 }]
  }] }));
  const res = await finalizeFuzzDiscover(t, runDir, { trustLocal: true, backend: "local" });
  assert.equal(res.provenCount, 0, "a parser that blocks __proto__ yields no proof");
});

test("spine: re-discovering the same crash dedupes to one finding (stable refId)", () => {
  const t = repo();
  const report = parseSanitizerReport(OVERFLOW_REPORT);
  const mk = () => { const { _crashKey, ...c } = buildDiscoveryFinding({ discovery: { title: "overflow", language: "c", evidence: [{ filePath: "src/t_stream.c", startLine: 3538 }] }, report, backend: "local", provenAt: new Date().toISOString() }); return c; };
  upsertFindings(t, [mk()]);
  upsertFindings(t, [mk()]);
  assert.equal(readFindings(t).length, 1, "same crash class + site ⇒ one finding, not two");
});
