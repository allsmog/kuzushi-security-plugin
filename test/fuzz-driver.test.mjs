// The portable ASan dumb-fuzz driver is the discovery-by-execution path where libFuzzer
// isn't available (Apple clang, etc.). Contract: a libFuzzer-API harness linked with the
// driver and built with ASan must DISCOVER a memory bug by running mutated inputs — the
// crash is found by the loop, not handed in — and the report classifies to a CWE. Gated
// on a C compiler. Uses a shallow bug (any input >16 bytes) + fixed seed so it's reliably
// found in a few iterations (the loop's discovery is what's under test, not its luck).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { detectToolchain, parseSanitizerReport, FUZZ_DRIVER, hasLibFuzzer, SANITIZE_ENV } from "../scripts/lib/sanitizers.mjs";

const cc = detectToolchain().cc;

test("hasLibFuzzer returns a boolean without throwing", () => {
  assert.equal(typeof hasLibFuzzer(cc ?? undefined), "boolean");
});

test("the shipped fuzz-driver.c exists", () => {
  assert.ok(existsSync(FUZZ_DRIVER), "fuzz-driver.c must ship with the plugin");
});

test("dumb-fuzz driver DISCOVERS a memory bug under ASan and it classifies to a CWE", { skip: cc ? false : "no C compiler" }, () => {
  const d = mkdtempSync(join(tmpdir(), "kz-fd-"));
  writeFileSync(join(d, "harness.c"),
    "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\nint LLVMFuzzerTestOneInput(const uint8_t*x,size_t n){char b[16]; if(n>16) memcpy(b,x,n); return (int)b[0];}\n");
  const build = spawnSync(cc, ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-g", "-O0", join(d, "harness.c"), FUZZ_DRIVER, "-o", join(d, "fuzz")], { encoding: "utf8" });
  assert.equal(build.status, 0, `driver+harness must link: ${build.stderr}`);
  // Bounded run with a fixed seed; a >16-byte input is generated within a few iters.
  const run = spawnSync(join(d, "fuzz"), ["100000", "7"], { cwd: d, encoding: "utf8", env: { ...process.env, ...SANITIZE_ENV } });
  const report = parseSanitizerReport(`${run.stdout}\n${run.stderr}`);
  assert.ok(report, "the fuzzer must discover a crash (non-null sanitizer report)");
  assert.equal(report.tool, "AddressSanitizer");
  assert.match(report.cwe, /CWE-(121|122|787)/, `overflow class, got ${report.errorClass}`);
});
