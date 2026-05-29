// The portable ASan dumb-fuzz driver is the discovery-by-execution path where libFuzzer
// isn't available (Apple clang, etc.). Contract: a libFuzzer-API harness linked with the
// driver and built with ASan must DISCOVER a memory bug by running mutated inputs — the
// crash is found by the loop, not handed in — and the report classifies to a CWE. Gated
// on a C compiler. Uses a shallow bug (any input >16 bytes) + fixed seed so it's reliably
// found in a few iterations (the loop's discovery is what's under test, not its luck).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
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

test("seed corpus: a gate-clearing seed lets the dumb-fuzzer find a DEEP-gated bug it misses unseeded", { skip: cc ? false : "no C compiler" }, () => {
  const d = mkdtempSync(join(tmpdir(), "kz-seed-"));
  // Deep 2-byte magic gate ('R','X') then a length byte → overflow. Unseeded random
  // clears 'RX' only ~1/65536 per iter, so a small budget misses it; a seed that already
  // says 'RX...' lets mutation grow the length and trip it fast.
  writeFileSync(join(d, "harness.c"),
    "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\nint LLVMFuzzerTestOneInput(const uint8_t*x,size_t n){ if(n<3||x[0]!='R'||x[1]!='X') return 0; unsigned len=x[2]; char b[16]; if(n>=3u+len) memcpy(b,x+3,len); return (int)b[0]; }\n");
  const build = spawnSync(cc, ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-g", "-O0", join(d, "harness.c"), FUZZ_DRIVER, "-o", join(d, "fuzz")], { encoding: "utf8" });
  assert.equal(build.status, 0, build.stderr);
  const corpus = join(d, "corpus"); mkdirSync(corpus);
  // A VALID, non-crashing gate-clearing seed: 'R','X', small length, a few bytes.
  writeFileSync(join(corpus, "seed-pathsolve"), "RX\x05hello");

  // Small budget WITHOUT seeds → should miss the deep gate (exit clean).
  const unseeded = spawnSync(join(d, "fuzz"), ["3000", "1"], { cwd: d, encoding: "utf8", env: { ...process.env, ...SANITIZE_ENV } });
  assert.equal(parseSanitizerReport(`${unseeded.stdout}\n${unseeded.stderr}`), null, "unseeded small budget misses the deep gate");

  // Same small budget WITH the seed corpus → mutation grows the length past 16 → crash.
  const seeded = spawnSync(join(d, "fuzz"), ["3000", "1", "4096", "corpus"], { cwd: d, encoding: "utf8", env: { ...process.env, ...SANITIZE_ENV } });
  const report = parseSanitizerReport(`${seeded.stdout}\n${seeded.stderr}`);
  assert.ok(report, "seeded fuzz discovers the gated overflow at a budget where unseeded didn't");
  assert.match(report.cwe, /CWE-(121|122|787)/);
});
