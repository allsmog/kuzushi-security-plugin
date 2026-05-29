// The sanitizer oracle is the empirical-proof core: a sanitizer report is ground
// truth, and its error class must map to the right CWE deterministically. The parser
// test is universal (no toolchain). The end-to-end compile test is gated on a C
// compiler being present — when it runs, it proves the whole loop: compile a known
// stack overflow WITH AddressSanitizer, run it, and recover CWE-121 from the abort.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { parseSanitizerReport, detectToolchain, SANITIZE_CFLAGS, SANITIZE_ENV } from "../scripts/lib/sanitizers.mjs";

test("parse: ASan stack-buffer-overflow → CWE-121", () => {
  const r = parseSanitizerReport("==97402==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x16 at pc 0x10\n    #0 0x100 in parse_name /src/t_stream.c:3538");
  assert.equal(r.tool, "AddressSanitizer");
  assert.equal(r.errorClass, "stack-buffer-overflow");
  assert.equal(r.cwe, "CWE-121");
  assert.deepEqual(r.frame0, { file: "/src/t_stream.c", line: 3538 });
});

test("parse: ASan heap-use-after-free → CWE-416", () => {
  const r = parseSanitizerReport("ERROR: AddressSanitizer: heap-use-after-free on address 0xdeadbeef\n READ of size 8");
  assert.equal(r.errorClass, "heap-use-after-free");
  assert.equal(r.cwe, "CWE-416");
});

test("parse: UBSan out-of-bounds → CWE-125", () => {
  const r = parseSanitizerReport("foo.c:42:10: runtime error: index 8 out of bounds for type 'int [8]'");
  assert.equal(r.tool, "UndefinedBehaviorSanitizer");
  assert.equal(r.cwe, "CWE-125");
});

// Real captured report from Redis CVE-2025-46817 (luaB_unpack integer overflow → wild OOB
// write). The int-overflow corrupts the stack-alloc SIZE, so the write lands in UNMAPPED
// memory past every redzone — the sanitizer can only trap the signal, printing a DEADLYSIGNAL
// + "BUS on unknown address" + SUMMARY (no "heap-buffer-overflow" redzone line, no UBSan
// "runtime error:" line). This exact report used to parse to NULL → /sanitize-pov would have
// silently missed a real CVE. The oracle must classify it.
const CVE_2025_46817_REPORT = [
  "UndefinedBehaviorSanitizer:DEADLYSIGNAL",
  "==94544==ERROR: UndefinedBehaviorSanitizer: BUS on unknown address (pc 0x000100d39774 bp 0x00016f0cdec0 sp 0x00016f0cdeb0 T67022030)",
  "==94544==The signal is caused by a WRITE memory access.",
  "==94544==Hint: this fault was caused by a dereference of a high value address (see register values below).",
  "    #0 0x000100d39774 in lua_rawgeti+0x60 (redis-server:arm64+0x100009774)",
  "    #1 0x000100d4f1f4 in luaB_unpack+0xb4 (redis-server:arm64+0x10001f1f4)",
  "SUMMARY: UndefinedBehaviorSanitizer: BUS (redis-server:arm64+0x100009774) in lua_rawgeti+0x60"
].join("\n");

test("parse: sanitizer DEADLYSIGNAL with a WRITE hint → OOB-write CWE-787 (real CVE-2025-46817)", () => {
  const r = parseSanitizerReport(CVE_2025_46817_REPORT);
  assert.ok(r, "a sanitizer-caught deadly signal must NOT parse to null");
  assert.equal(r.tool, "UndefinedBehaviorSanitizer");
  assert.equal(r.errorClass, "oob-write");
  assert.equal(r.cwe, "CWE-787");
  assert.equal(r.frame0?.symbol, "lua_rawgeti", "frame falls back to the symbol when the binary has no source line");
});

test("parse: deadly-signal READ access → OOB-read CWE-125", () => {
  const r = parseSanitizerReport("UndefinedBehaviorSanitizer:DEADLYSIGNAL\n==1==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x7fffffff\n==1==The signal is caused by a READ memory access.\n    #0 0x1 in reader+0x4 (a.out+0x1)\nSUMMARY: UndefinedBehaviorSanitizer: SEGV in reader");
  assert.equal(r.errorClass, "oob-read");
  assert.equal(r.cwe, "CWE-125");
});

test("parse: deadly-signal NULL-page deref stays SEGV/CWE-476 (not mislabeled OOB)", () => {
  const r = parseSanitizerReport("UndefinedBehaviorSanitizer:DEADLYSIGNAL\n==1==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000\n==1==The signal is caused by a WRITE memory access.\n    #0 0x1 in f+0x4 (a.out+0x1)\nSUMMARY: UndefinedBehaviorSanitizer: SEGV in f");
  assert.equal(r.cwe, "CWE-476", "a write to the null page is a null-deref, not an OOB write");
});

test("parse: clean output → null (no false proof)", () => {
  assert.equal(parseSanitizerReport("all tests passed\nexit 0"), null);
  assert.equal(parseSanitizerReport(""), null);
  assert.equal(parseSanitizerReport("dumbfuzz: 500000 iterations, 0 seeds, no crash"), null);
});

const tc = detectToolchain();
test("end-to-end: compile a stack overflow with ASan, run it, recover the CWE from the abort", { skip: tc.cc ? false : "no C compiler" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "kz-san-"));
  // A textbook stack-buffer-overflow driven by an out-of-range index.
  writeFileSync(join(dir, "vuln.c"),
    "#include <string.h>\nint main(int argc,char**argv){char buf[8];volatile int n=64;memset(buf,'A',n);return buf[0];}\n");
  const build = spawnSync("sh", ["-c", `${tc.cc} ${SANITIZE_CFLAGS} vuln.c -o vuln`], { cwd: dir, encoding: "utf8" });
  assert.equal(build.status, 0, `sanitized build should succeed: ${build.stderr}`);
  const run = spawnSync(join(dir, "vuln"), [], { cwd: dir, encoding: "utf8", env: { ...process.env, ...SANITIZE_ENV } });
  const report = parseSanitizerReport(`${run.stdout}\n${run.stderr}`);
  assert.ok(report, "a sanitizer report must be produced by the overflow");
  assert.equal(report.tool, "AddressSanitizer");
  assert.ok(["stack-buffer-overflow", "dynamic-stack-buffer-overflow", "global-buffer-overflow"].includes(report.errorClass), `got ${report.errorClass}`);
  assert.match(report.cwe, /CWE-(121|787)/);
});
