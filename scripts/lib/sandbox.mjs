// Deterministic sandbox runner for /poc — the empirical "verify:exploit" backend.
//
// The PoC agent writes a minimal harness; this library runs it and classifies the
// result. No LLM here on purpose: the empirical run must be reproducible, so a
// native executor does it rather than the agent. Two backends:
//   - docker (preferred): `docker run --rm --network none` mounting the harness
//     dir, with a per-language base image and a hard timeout. Network is cut so a
//     PoC can't phone home or pull anything.
//   - local (gated): spawn the run command directly in the harness dir, only when
//     the caller passes trustLocal:true. This runs the harness on the host, so it
//     is opt-in. Without docker and without trustLocal we return a skipped result
//     and the caller records backend:"none" (the harness still persists for a
//     manual run).
//
// classifyResult() maps the run into a proof verdict + level (1-4), mirroring the
// reference app's crash-signal detection.

import { spawn, spawnSync } from "node:child_process";

// Per-language base image for the docker backend. Kept to widely-available
// official images; the harness's runCommand does the build+run inside.
export const LANG_IMAGES = {
  rust: "rust:slim",
  python: "python:slim",
  javascript: "node:slim",
  typescript: "node:slim",
  c: "gcc",
  cpp: "gcc",
  go: "golang:alpine",
  java: "eclipse-temurin:21"
};

// Is a usable sandbox backend available? docker wins when the daemon answers;
// otherwise we fall back to local (gated by trustLocal at run time) or none.
export function detectBackend() {
  const probe = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 8000 });
  if (!probe.error && probe.status === 0) {
    return { backend: "docker", reason: "docker daemon reachable" };
  }
  if (probe.error && probe.error.code === "ENOENT") {
    return { backend: "local", reason: "docker not installed; local run available only with consent" };
  }
  return { backend: "local", reason: "docker present but daemon unreachable; local run available only with consent" };
}

function imageFor(language) {
  return LANG_IMAGES[language] ?? "debian:stable-slim";
}

// Single-quote a string for safe interpolation into an `sh -c` line.
function shq(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

// Spawn a child process, capturing stdout/stderr and enforcing a wall-clock
// timeout (SIGKILL on expiry). Resolves with {exitCode, signal, stdout, stderr,
// durationMs, timedOut}.
function spawnCapture(command, args, options, timeoutMs) {
  return new Promise((resolvePromise) => {
    const started = Date.now();
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (d) => { stdout += d.toString(); });
    child.stderr.on("data", (d) => { stderr += d.toString(); });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolvePromise({ exitCode: null, signal: null, stdout, stderr: `${stderr}${err.message}`, durationMs: Date.now() - started, timedOut, spawnError: true });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolvePromise({ exitCode: code, signal, stdout, stderr, durationMs: Date.now() - started, timedOut });
    });
  });
}

// Run a PoC harness. harnessDir is mounted (docker) or used as cwd (local); the
// runCommand is the shell line that builds + runs the harness. Returns a run
// result object (see spawnCapture) plus {backend}. When no backend is usable the
// result is {backend:"none", skipped:true}.
export async function runInSandbox({ backend, language, harnessDir, runCommand, timeoutMs = 60000, trustLocal = false }) {
  if (backend === "docker") {
    const image = imageFor(language);
    // Stage the harness by streaming a tar of harnessDir into the container over
    // stdin (`docker run -i` + `tar -x`), NOT by bind-mounting it. A bind mount
    // (`-v harnessDir:/work`) silently arrives EMPTY when harnessDir lives under a
    // path Docker Desktop doesn't share (e.g. /private/tmp on macOS) — the harness
    // then fails to load and the run is wasted. Streaming works regardless of the
    // host's Docker file-sharing config, and --network none still holds.
    const inner = `mkdir -p /work && tar -x -C /work -f - && cd /work && ${runCommand}`;
    const pipeline = `tar -c -C ${shq(harnessDir)} . | docker run -i --rm --network none -w /work ${shq(image)} sh -c ${shq(inner)}`;
    const result = await spawnCapture("sh", ["-c", pipeline], {}, timeoutMs);
    return { ...result, backend: "docker", image };
  }
  if (backend === "local" && trustLocal) {
    const result = await spawnCapture("sh", ["-c", runCommand], { cwd: harnessDir }, timeoutMs);
    return { ...result, backend: "local" };
  }
  return { backend: "none", skipped: true, reason: backend === "local" ? "local run requires trustLocal" : "no sandbox backend available" };
}

const CRASH_SIGNALS = new Set(["SIGABRT", "SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE"]);
// Crash/exploit evidence in textual output (panics, sanitizer reports, asserts).
const CRASH_PATTERNS = /panic|AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|assertion failed|Segmentation fault|stack overflow|heap-buffer-overflow|core dumped|RUST_BACKTRACE|Traceback \(most recent call last\)/i;
const BUILD_FAIL_PATTERNS = /error\[E\d+\]|cannot find|undefined reference|SyntaxError|ModuleNotFoundError|No such file|compilation terminated|command not found|cargo: not found|could not compile/i;

// Map a run result into { proofLevel (1-4), proofVerdict }. expectedSignal lets
// the harness say what "success" looks like ("crash" is the default — the bug
// fires; "nonzero" — a non-zero exit is the proof). proofLevel: 4 hard crash
// signal, 3 textual crash/expected nonzero, 2 ran-but-no-repro, 1 couldn't run.
export function classifyResult(result, expectedSignal = "crash") {
  if (!result || result.skipped) {
    return { proofLevel: 1, proofVerdict: "error", note: result?.reason ?? "not executed" };
  }
  if (result.timedOut) {
    return { proofLevel: 1, proofVerdict: "timeout" };
  }
  if (result.spawnError) {
    return { proofLevel: 1, proofVerdict: "error" };
  }
  const out = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  // Hard crash signal from the sandboxed process is the strongest proof — a real
  // signal death is unambiguous, so it outranks everything below.
  if (CRASH_SIGNALS.has(result.signal)) {
    return { proofLevel: 4, proofVerdict: "exploited" };
  }
  // Docker reports the child's signal death as exit code 128+N.
  if (typeof result.exitCode === "number" && result.exitCode > 128) {
    return { proofLevel: 4, proofVerdict: "exploited" };
  }
  // A harness that never built/loaded must NOT be read as a proof. This gate has
  // to run BEFORE the textual-crash and expected-nonzero heuristics below: a load
  // failure (MODULE_NOT_FOUND, missing file, syntax/compile error) exits non-zero
  // and prints a stack trace, which those heuristics would otherwise mis-score as
  // "exploited" — a false proof. Only a genuine signal death (above) outranks it.
  if (BUILD_FAIL_PATTERNS.test(out)) {
    return { proofLevel: 1, proofVerdict: "harness-failed-build" };
  }
  if (CRASH_PATTERNS.test(out)) {
    return { proofLevel: 3, proofVerdict: "exploited" };
  }
  if (expectedSignal === "nonzero" && typeof result.exitCode === "number" && result.exitCode !== 0) {
    return { proofLevel: 3, proofVerdict: "exploited" };
  }
  return { proofLevel: 2, proofVerdict: "not-reproduced" };
}

// Differential proof gate. A single attack run that fires only proves the harness
// exits with the success signal — NOT that it discriminates the vulnerability. A
// harness that aborts on *any* input (attack or benign) is a false proof. The
// verifier always drafts a `negativePoc` (an in-spec input that must be handled
// safely); when the builder wires it as a second run, this gate demands the
// negative control STAY CLEAN while the attack fires. Outcomes:
//   - attack fires + benign clean        → proofLevel 5 "exploited" (discriminated)
//   - attack fires + benign ALSO fires   → proofLevel 2 "non-discriminating" (NOT a proof)
//   - attack fires + benign couldn't run → attack's own level, differential inconclusive
//   - attack didn't fire                 → the attack verdict unchanged
// proofLevel 5 is the only rung that survives an executed negative control, so it
// is strictly stronger than a level-4 attack-only crash.
export function classifyDifferential(attackResult, benignResult, expectedSignal = "crash") {
  const attack = classifyResult(attackResult, expectedSignal);
  if (attack.proofVerdict !== "exploited") {
    return { ...attack, differential: "attack-did-not-fire" };
  }
  const benign = classifyResult(benignResult, expectedSignal);
  if (benign.proofVerdict === "exploited") {
    return {
      proofLevel: 2,
      proofVerdict: "non-discriminating",
      differential: "benign-also-fired",
      note: "negative control (negativePoc) also fired — the harness does not discriminate the vulnerability, so the attack run is not a proof"
    };
  }
  if (benign.proofVerdict === "not-reproduced") {
    return { proofLevel: 5, proofVerdict: "exploited", differential: "discriminated" };
  }
  // Benign run errored / failed to build / timed out — we can't confirm the
  // control is clean, so we keep the attack's level but flag it as untested.
  return { ...attack, differential: "benign-inconclusive", note: `negative control did not run cleanly (${benign.proofVerdict})` };
}

// Reproducibility-aware proof gate (the harness "3/3" standard). A crash that
// fires 1-in-10 is far weaker evidence than one that fires every time — models
// and memory bugs are stochastic, so a single fire can be luck. Run the attack N
// times and fold the reproduction rate into the verdict: the top tier (5) now
// requires BOTH a clean negative control AND full reproducibility; a flaky crash
// (0 < rate < 1) is still a real bug but caps below it and carries the rate.
//   attackResults: array of N run results; benignResult: optional negative control.
export function classifyRuns({ attackResults, benignResult = null, expectedSignal = "crash" }) {
  const runs = (attackResults ?? []).map((r) => classifyResult(r, expectedSignal));
  const total = runs.length;
  const fired = runs.filter((v) => v.proofVerdict === "exploited").length;
  const rate = total ? Number((fired / total).toFixed(3)) : 0;
  const reproductions = { fired, total, rate };

  if (fired === 0) {
    // Nothing fired across N runs — report the strongest single verdict (e.g. a
    // build failure or timeout) so the reason survives, with the repro evidence.
    const best = runs.reduce((a, b) => (b.proofLevel >= a.proofLevel ? b : a), runs[0] ?? { proofLevel: 1, proofVerdict: "error" });
    return { ...best, reproductions, differential: "attack-did-not-fire" };
  }
  if (benignResult) {
    const benign = classifyResult(benignResult, expectedSignal);
    if (benign.proofVerdict === "exploited") {
      return { proofLevel: 2, proofVerdict: "non-discriminating", differential: "benign-also-fired", reproductions, note: "negative control also fired" };
    }
    if (benign.proofVerdict === "not-reproduced") {
      // Discriminated. proofLevel 5 only when fully reproducible; flaky caps at 4.
      return { proofLevel: rate === 1 ? 5 : 4, proofVerdict: "exploited", differential: "discriminated", reproductions };
    }
    return { proofLevel: rate === 1 ? 4 : 3, proofVerdict: "exploited", differential: "benign-inconclusive", reproductions };
  }
  // No negative control: a fire is a proof, level modulated by reproducibility.
  return { proofLevel: rate === 1 ? 4 : 3, proofVerdict: "exploited", differential: "not-tested", reproductions };
}
