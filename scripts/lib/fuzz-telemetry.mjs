// Fuzz telemetry parser + minimizer command builder.
//
// A fixed wall-clock fuzz run with no coverage read is a black box: you learn
// "crashed" or "didn't", but not whether the campaign was still discovering new
// code (stop too early) or had plateaued (stop, it's saturated), and a crash that
// reproduces from a 100 KB input is far less useful than its 12-byte minimization.
// This pure module reads what the engines already print so the loop can SEE the
// run: peak coverage, exec count, whether new coverage was still landing at the
// end, and the crash artifact path to feed the minimizer. No engine is run here —
// fuzz-run/fuzz-minimize pass the captured output in.

// libFuzzer and everything built on it (cargo-fuzz for Rust, atheris for Python,
// Jazzer for Java) print the same status lines:
//   #1234  NEW    cov: 410 ft: 902 corp: 57/3Kb exec/s: 5000 ...
//   #99999 DONE   cov: 410 ft: 902 ...
//   artifact_prefix='./'; Test unit written to ./crash-deadbeef
const LF_STATUS = /^#(\d+)\s+(NEW|REDUCE|pulse|INITED|DONE)\b.*?\bcov:\s*(\d+).*?\bft:\s*(\d+)/i;
const LF_EXECS_PER_SEC = /\bexec\/s:\s*(\d+)/i;
const LF_CRASH_ARTIFACT = /Test unit written to (\S+)/i;
const LF_SUMMARY = /SUMMARY:\s*(?:libFuzzer|AddressSanitizer|UndefinedBehaviorSanitizer):\s*(.+)/i;
// go-fuzz / Go native fuzzing print a different shape:
//   workers: 8, corpus: 245 (3m ago), crashers: 1, restarts: ...
const GO_STATUS = /\bcorpus:\s*(\d+).*?\bcrashers?:\s*(\d+)/i;

const LIBFUZZER_ENGINES = new Set(["libfuzzer", "cargo-fuzz", "atheris", "jazzer", "node-property"]);

function lastMatch(lines, re) {
  let found = null;
  for (const line of lines) {
    const m = line.match(re);
    if (m) found = m;
  }
  return found;
}

// Parse captured fuzzer output into a coverage/telemetry block. Best-effort and
// engine-aware; unknown engines still get crash-artifact + summary extraction.
export function parseFuzzTelemetry(output, engine = "unknown") {
  const text = String(output ?? "");
  const lines = text.split(/\r?\n/);
  const telemetry = {
    engine,
    execs: null,
    peakCov: null,
    peakFeatures: null,
    newCoverageEvents: 0,
    execsPerSec: null,
    corpusSize: null,
    crashers: null,
    endedWith: "unknown",
    crashArtifact: null,
    summary: null
  };

  if (GO_STATUS.test(text) && !LF_STATUS.test(text)) {
    const m = lastMatch(lines, GO_STATUS);
    if (m) { telemetry.corpusSize = Number(m[1]); telemetry.crashers = Number(m[2]); }
  }

  // libFuzzer-family status lines (the common case).
  let lastStatus = null;
  for (const line of lines) {
    const m = line.match(LF_STATUS);
    if (!m) continue;
    lastStatus = m;
    const kind = m[2].toUpperCase();
    if (kind === "NEW" || kind === "REDUCE") telemetry.newCoverageEvents += 1;
  }
  if (lastStatus) {
    telemetry.execs = Number(lastStatus[1]);
    telemetry.peakCov = Number(lastStatus[3]);
    telemetry.peakFeatures = Number(lastStatus[4]);
    if (lastStatus[2].toUpperCase() === "DONE") telemetry.endedWith = "done";
  }
  const eps = lastMatch(lines, LF_EXECS_PER_SEC);
  if (eps) telemetry.execsPerSec = Number(eps[1]);

  const artifact = text.match(LF_CRASH_ARTIFACT);
  if (artifact) telemetry.crashArtifact = artifact[1];
  const summary = text.match(LF_SUMMARY);
  if (summary) { telemetry.summary = summary[1].trim(); telemetry.endedWith = "crash"; }
  if (telemetry.crashers > 0) telemetry.endedWith = "crash";

  return telemetry;
}

// Did the run still find new coverage near the end (under-fuzzed → run longer), or
// has it plateaued (saturated → stop / minimize)? Heuristic: any NEW event with a
// reasonable exec count but ending cleanly suggests saturation only if DONE. We
// expose the raw signal and a coarse recommendation.
export function coverageRecommendation(telemetry) {
  if (!telemetry || telemetry.peakCov == null) return { signal: "no-coverage-data", advice: "engine printed no coverage; ensure a sanitizer/coverage build" };
  if (telemetry.endedWith === "crash") return { signal: "crashed", advice: "crash found — triage and minimize the artifact" };
  if (telemetry.endedWith === "done" && telemetry.newCoverageEvents > 0) {
    return { signal: "saturating", advice: "coverage growth slowed by end of budget; a longer run is unlikely to pay off much" };
  }
  if (telemetry.endedWith !== "done") {
    return { signal: "interrupted", advice: "run did not reach DONE (timeout/budget); coverage may still be growing — extend the budget" };
  }
  return { signal: "completed", advice: "campaign completed its budget" };
}

// Build the engine-specific command that minimizes a crashing input. Returns null
// when the engine has no first-class minimizer or no crash artifact is known —
// the caller then records "not-minimized" rather than inventing a command.
export function minimizeCommandFor(engine, { crashArtifact, target, runs = 5000 } = {}) {
  if (!crashArtifact) return null;
  switch (engine) {
    case "libfuzzer":
    case "atheris":
    case "jazzer":
    case "node-property":
      // libFuzzer's own crash minimizer; `target` is the built fuzz binary.
      return target
        ? `${target} -minimize_crash=1 -runs=${runs} ${crashArtifact}`
        : `<fuzz-binary> -minimize_crash=1 -runs=${runs} ${crashArtifact}`;
    case "cargo-fuzz":
      // cargo-fuzz wraps libFuzzer; tmin is its crash minimizer.
      return target
        ? `cargo fuzz tmin ${target} ${crashArtifact}`
        : `cargo fuzz tmin <target_name> ${crashArtifact}`;
    case "go-fuzz":
      // Go's native fuzzer minimizes automatically and writes the minimized input
      // into testdata/fuzz/<Fuzz>/ — there is no separate minimize command.
      return null;
    default:
      return null;
  }
}

export const _internals = { LF_STATUS, LIBFUZZER_ENGINES };
