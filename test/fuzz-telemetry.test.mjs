// The fuzz telemetry parser turns a black-box run into a visible one: coverage,
// exec count, whether it was still growing, and the crash artifact to minimize.
// These pin the libFuzzer-family parsing, the go-fuzz branch, the coverage
// recommendation, and the per-engine minimizer command.

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseFuzzTelemetry, coverageRecommendation, minimizeCommandFor } from "../scripts/lib/fuzz-telemetry.mjs";

const LIBFUZZER_CLEAN = [
  "INFO: Seed: 123",
  "#2\tINITED cov: 100 ft: 200 corp: 1/1b exec/s: 0 rss: 30Mb",
  "#16\tNEW    cov: 140 ft: 280 corp: 5/40b lim: 4 exec/s: 8000 rss: 31Mb L: 8/8 MS: 2",
  "#1024\tNEW    cov: 410 ft: 902 corp: 57/3Kb lim: 33 exec/s: 5120 rss: 33Mb",
  "#99999\tDONE   cov: 410 ft: 902 corp: 57/3Kb exec/s: 5000 rss: 33Mb"
].join("\n");

const LIBFUZZER_CRASH = [
  "#16\tNEW    cov: 140 ft: 280 corp: 5/40b exec/s: 8000",
  "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef",
  "SUMMARY: AddressSanitizer: heap-buffer-overflow harness.c:42 in parse",
  "artifact_prefix='./'; Test unit written to ./crash-0a1b2c3d",
  "Base64: ..."
].join("\n");

test("parses libFuzzer coverage, exec count, and NEW events from a clean run", () => {
  const t = parseFuzzTelemetry(LIBFUZZER_CLEAN, "libfuzzer");
  assert.equal(t.peakCov, 410);
  assert.equal(t.peakFeatures, 902);
  assert.equal(t.execs, 99999);
  assert.equal(t.newCoverageEvents, 2);
  assert.equal(t.endedWith, "done");
  assert.equal(t.execsPerSec, 5000);
});

test("parses a crash: artifact path + summary + endedWith=crash", () => {
  const t = parseFuzzTelemetry(LIBFUZZER_CRASH, "libfuzzer");
  assert.equal(t.crashArtifact, "./crash-0a1b2c3d");
  assert.match(t.summary, /heap-buffer-overflow/);
  assert.equal(t.endedWith, "crash");
});

test("go-fuzz branch reads corpus + crashers", () => {
  const out = "workers: 8, corpus: 245 (3m ago), crashers: 1, restarts: 1/1000";
  const t = parseFuzzTelemetry(out, "go-fuzz");
  assert.equal(t.corpusSize, 245);
  assert.equal(t.crashers, 1);
  assert.equal(t.endedWith, "crash");
});

test("coverageRecommendation distinguishes interrupted vs saturating vs crashed", () => {
  assert.equal(coverageRecommendation(parseFuzzTelemetry(LIBFUZZER_CRASH, "libfuzzer")).signal, "crashed");
  assert.equal(coverageRecommendation(parseFuzzTelemetry(LIBFUZZER_CLEAN, "libfuzzer")).signal, "saturating");
  // A run with coverage but no DONE line = interrupted (budget hit, may still grow).
  const interrupted = parseFuzzTelemetry("#16\tNEW    cov: 140 ft: 280 exec/s: 8000", "libfuzzer");
  assert.equal(coverageRecommendation(interrupted).signal, "interrupted");
  assert.equal(coverageRecommendation(parseFuzzTelemetry("no coverage here", "libfuzzer")).signal, "no-coverage-data");
});

test("minimizeCommandFor builds the right per-engine command, or null when none", () => {
  assert.match(minimizeCommandFor("libfuzzer", { crashArtifact: "./crash-x", target: "./fuzz_target" }), /-minimize_crash=1 -runs=5000 \.\/crash-x/);
  assert.match(minimizeCommandFor("cargo-fuzz", { crashArtifact: "crash-y", target: "parse_target" }), /cargo fuzz tmin parse_target crash-y/);
  assert.equal(minimizeCommandFor("go-fuzz", { crashArtifact: "x" }), null); // auto-minimizes
  assert.equal(minimizeCommandFor("libfuzzer", {}), null); // no artifact → no command
});
