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
