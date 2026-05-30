// Sanitizer oracle — the AIxCC "prove by execution" core.
//
// Static LLM reading misses subtle memory bugs (our eval: the Redis GC-UAF survived
// even a focused read). The fix the winning CRSs use: compile with AddressSanitizer /
// UndefinedBehaviorSanitizer and RUN the suspect path — a sanitizer abort is
// ground-truth proof, and its error class names the exact bug. This library is the
// deterministic oracle: detect the toolchain, supply sanitizer build flags, and parse a
// sanitizer report into { tool, errorClass, cwe }. The actual run reuses sandbox.mjs
// (`--network none`); the verdict is decided here from the report, never by an LLM.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// AddressSanitizer / UBSan error class → CWE. The sanitizer says exactly what went
// wrong; this maps it to the canonical weakness so the promoted finding is precise.
const ASAN_CWE = [
  [/heap-use-after-free|use-after-poison/, "heap-use-after-free", "CWE-416"],
  [/stack-use-after-return/, "stack-use-after-return", "CWE-562"],
  [/stack-use-after-scope/, "stack-use-after-scope", "CWE-562"],
  [/attempting double-free|double-free/, "double-free", "CWE-415"],
  [/heap-buffer-overflow/, "heap-buffer-overflow", "CWE-122"],
  [/stack-buffer-overflow|stack-buffer-underflow/, "stack-buffer-overflow", "CWE-121"],
  [/global-buffer-overflow/, "global-buffer-overflow", "CWE-787"],
  [/dynamic-stack-buffer-overflow/, "dynamic-stack-buffer-overflow", "CWE-787"],
  [/stack-overflow/, "stack-overflow", "CWE-674"],
  [/SEGV on unknown address|SEGV/, "segv", "CWE-476"],
  [/memory leak|LeakSanitizer/, "memory-leak", "CWE-401"],
  [/alloc-dealloc-mismatch/, "alloc-dealloc-mismatch", "CWE-762"]
];
// A sanitizer-caught DEADLY SIGNAL → CWE. When a bug corrupts an allocation SIZE (classic
// integer-overflow → undersized alloc) the bad write lands far past any ASan redzone in
// UNMAPPED memory, so neither a "heap-buffer-overflow" redzone report nor a UBSan "runtime
// error:" line is printed — the sanitizer runtime just traps the SIGSEGV/SIGBUS and prints
// `<San>:DEADLYSIGNAL` + a backtrace + `SUMMARY: <San>: SEGV|BUS ... in <frame>`. Real bugs
// crash this way (e.g. Redis CVE-2025-46817, luaB_unpack), so the oracle must classify them.
const SIGNAL_CWE = {
  SEGV: ["segv", "CWE-476"],
  BUS: ["bus-error", "CWE-119"],
  ABRT: ["abort", "CWE-617"],
  ILL: ["illegal-instruction", "CWE-119"],
  FPE: ["fp-exception", "CWE-369"]
};
// UBSan "runtime error:" sub-messages → CWE.
const UBSAN_CWE = [
  [/out of bounds|index .* out of bounds/, "out-of-bounds", "CWE-125"],
  [/signed integer overflow|unsigned integer overflow/, "integer-overflow", "CWE-190"],
  [/shift exponent|shift of negative/, "bad-shift", "CWE-190"],
  [/null pointer|member access within null/, "null-deref", "CWE-476"],
  [/load of misaligned|misaligned address/, "misaligned-access", "CWE-1319"],
  [/division by zero/, "div-by-zero", "CWE-369"]
];

// Parse a captured ASan/UBSan report into { tool, errorClass, cwe, summary, frame0 }
// or null if no sanitizer error is present. Deterministic — this IS the oracle.
export function parseSanitizerReport(text) {
  const s = String(text ?? "");
  const asan = /ERROR:\s*AddressSanitizer:\s*([a-z0-9-]+)/i.exec(s) || /(LeakSanitizer):/i.exec(s);
  if (asan) {
    const blob = s.slice(Math.max(0, asan.index - 40), asan.index + 400);
    for (const [re, errorClass, cwe] of ASAN_CWE) {
      if (re.test(blob) || re.test(asan[1] ?? "")) {
        return { tool: "AddressSanitizer", errorClass, cwe, summary: firstLine(s, /ERROR:\s*AddressSanitizer|LeakSanitizer/i), frame0: firstFrame(s) };
      }
    }
    return { tool: "AddressSanitizer", errorClass: asan[1] ?? "unknown", cwe: "CWE-119", summary: firstLine(s, /ERROR:\s*AddressSanitizer/i), frame0: firstFrame(s) };
  }
  const ub = /runtime error:\s*(.+)/i.exec(s);
  if (ub) {
    for (const [re, errorClass, cwe] of UBSAN_CWE) {
      if (re.test(ub[1])) {
        return { tool: "UndefinedBehaviorSanitizer", errorClass, cwe, summary: ub[1].slice(0, 200).trim(), frame0: firstFrame(s) };
      }
    }
    return { tool: "UndefinedBehaviorSanitizer", errorClass: "undefined-behavior", cwe: "CWE-758", summary: ub[1].slice(0, 200).trim(), frame0: firstFrame(s) };
  }
  // Sanitizer-caught deadly signal (no redzone / no "runtime error:" line). Prefer the
  // SUMMARY line (names the signal), else the `<San>:DEADLYSIGNAL` marker + the first frame.
  const summ = /SUMMARY:\s*(\w*Sanitizer):\s*(SEGV|BUS|ABRT|ILL|FPE)\b/i.exec(s);
  const deadly = summ || /(\w*Sanitizer):\s*DEADLYSIGNAL/i.exec(s);
  if (deadly) {
    const toolRaw = deadly[1] ?? "";
    const tool = /Address/i.test(toolRaw) ? "AddressSanitizer"
      : /Undefined/i.test(toolRaw) ? "UndefinedBehaviorSanitizer"
      : (toolRaw || "Sanitizer");
    // Signal from the SUMMARY if present, else scan the body (DEADLYSIGNAL has no signal token).
    const sigName = (summ?.[2] ?? (/\b(SEGV|BUS|ABRT|ILL|FPE)\b/.exec(s)?.[1]) ?? "SEGV").toUpperCase();
    let [errorClass, cwe] = SIGNAL_CWE[sigName] ?? ["deadly-signal", "CWE-119"];
    // Sharpen with the faulting access-type the sanitizer prints ("caused by a WRITE/READ
    // memory access" / "WRITE|READ of size N") — a wild WRITE is an OOB write, a wild READ an
    // OOB read — UNLESS it's a null-page deref (that stays the bare signal → CWE-476).
    const nullDeref = /unknown address 0x0{6,}|address 0x0{6,}\b/i.test(s);
    if (!nullDeref && /caused by a WRITE memory access|\bWRITE of size\b/i.test(s)) { errorClass = "oob-write"; cwe = "CWE-787"; }
    else if (!nullDeref && /caused by a READ memory access|\bREAD of size\b/i.test(s)) { errorClass = "oob-read"; cwe = "CWE-125"; }
    return { tool, errorClass, cwe, summary: (firstLine(s, /SUMMARY:/i) || `${tool}: ${sigName}`).slice(0, 240), frame0: firstFrame(s) };
  }
  return null;
}

function firstLine(s, re) {
  const line = s.split(/\r?\n/).find((l) => re.test(l));
  return (line ?? "").trim().slice(0, 240);
}
// First frame from the sanitizer backtrace. Prefer a source `file:line`; if the binary is
// optimized/stripped (frames are `#0 0x.. in <symbol>+0x.. (binary+0x..)` with no source
// location — the common case for a deadly-signal report), fall back to the symbol name so
// the finding still points at the crashing function (e.g. lua_rawgeti for CVE-2025-46817).
function firstFrame(s) {
  const m = /#0[^\n]*?(\/[^\s:]+|\b[\w./-]+\.(?:c|cc|cpp|h|hpp|rs|m)):(\d+)/.exec(s);
  if (m) return { file: m[1], line: Number(m[2]) };
  const sym = /#0\s+0x[0-9a-fA-F]+\s+in\s+([A-Za-z_][\w:]*)/.exec(s);
  return sym ? { symbol: sym[1] } : null;
}

// Does this compiler actually LINK an -fsanitize=address binary? A cc can answer
// --version yet fail to link ASan when its runtime (compiler-rt / libasan) isn't
// installed — common for a clang without compiler-rt. Probed once per cc via a trivial
// link; the result decides which toolchain detectToolchain prefers, so an execution
// proof isn't silently lost to a build failure on a half-installed compiler.
const _asanLink = new Map();
function ccLinksAsan(cc) {
  if (_asanLink.has(cc)) return _asanLink.get(cc);
  let ok = false;
  try {
    const d = mkdtempSync(join(tmpdir(), "kz-asan-"));
    writeFileSync(join(d, "p.c"), "int main(void){return 0;}\n");
    const r = spawnSync(cc, ["-fsanitize=address", "-g", join(d, "p.c"), "-o", join(d, "p")], { encoding: "utf8" });
    ok = !r.error && r.status === 0;
  } catch { ok = false; }
  _asanLink.set(cc, ok);
  return ok;
}

// Toolchain detection. Returns { cc, kind, asan, ubsan, asanVerified, rust }. Prefers a
// compiler whose AddressSanitizer runtime actually links over one that merely answers
// --version; falls back to the first responding cc (the prior behavior) if none link,
// so this never returns null where the old code found a compiler.
export function detectToolchain() {
  const responding = [];
  for (const cc of ["clang", "gcc", "cc"]) {
    const r = spawnSync(cc, ["--version"], { encoding: "utf8" });
    if (!r.error && r.status === 0) responding.push({ cc, kind: /clang/i.test(r.stdout) ? "clang" : "gcc" });
  }
  const linkable = responding.find((c) => ccLinksAsan(c.cc));
  const chosen = linkable ?? responding[0];
  if (chosen) return { cc: chosen.cc, kind: chosen.kind, asan: true, ubsan: true, asanVerified: Boolean(linkable) };
  const cargo = spawnSync("cargo", ["--version"], { stdio: "ignore" });
  return { cc: null, kind: null, asan: false, ubsan: false, asanVerified: false, rust: !cargo.error && cargo.status === 0 };
}

// Recommended sanitizer build flags for a C/C++ compile. ODR-safe, frame pointers on
// for readable backtraces, abort-on-error so a finding can't be swallowed.
export const SANITIZE_CFLAGS =
  "-fsanitize=address,undefined -fno-sanitize-recover=all -g -O0 -fno-omit-frame-pointer";
// Print the report and _exit(66) on the first error — do NOT abort(). abort() raises
// SIGABRT, which on macOS hands the process to the OS crash reporter and can stall for
// ~100s; the sanitizer REPORT is our oracle, so a clean exit with the report is all we
// need (and a distinct exit code is a secondary signal). Leaks off — we prove corruption.
export const SANITIZE_EXITCODE = 66;
export const SANITIZE_ENV = {
  ASAN_OPTIONS: `halt_on_error=1:abort_on_error=0:exitcode=${SANITIZE_EXITCODE}:detect_leaks=0`,
  UBSAN_OPTIONS: `halt_on_error=1:abort_on_error=0:print_stacktrace=1:exitcode=${SANITIZE_EXITCODE}`
};

// The portable dumb-fuzz driver (used when libFuzzer is unavailable). Same harness API.
export const FUZZ_DRIVER = join(dirname(fileURLToPath(import.meta.url)), "fuzz-driver.c");

// Is coverage-guided libFuzzer linkable here? (`-fsanitize=fuzzer` needs the runtime,
// which Apple clang and some others don't ship.) Probed once by trying a trivial link;
// determines whether /fuzz uses the libFuzzer engine or the portable ASan driver.
let _libfuzzer = null;
export function hasLibFuzzer(cc) {
  if (_libfuzzer !== null) return _libfuzzer;
  const c = cc || detectToolchain().cc;
  if (!c) { _libfuzzer = false; return false; }
  try {
    const d = mkdtempSync(join(tmpdir(), "kz-lf-"));
    writeFileSync(join(d, "p.c"), "#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput(const uint8_t*x,size_t n){return (int)(n&&x[0]);}\n");
    const r = spawnSync(c, ["-fsanitize=address,fuzzer", "-g", join(d, "p.c"), "-o", join(d, "p")], { encoding: "utf8" });
    _libfuzzer = !r.error && r.status === 0;
  } catch { _libfuzzer = false; }
  return _libfuzzer;
}

// Coverage-guided libFuzzer in a container — the engine that clears magic-byte gates the
// portable dumb-fuzzer can't (its coverage feedback walks the gate). Available when Docker
// is up AND the clang+libFuzzer image is built (docker/fuzz/Dockerfile → `kuzushi-fuzz`).
export const FUZZ_IMAGE = "kuzushi-fuzz:latest";
let _dockerLF = null;
export function hasDockerLibFuzzer(image = FUZZ_IMAGE) {
  if (_dockerLF !== null) return _dockerLF;
  try {
    const up = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 8000 });
    if (up.error || up.status !== 0) { _dockerLF = false; return false; }
    const img = spawnSync("docker", ["image", "inspect", image], { stdio: "ignore" });
    _dockerLF = !img.error && img.status === 0;
  } catch { _dockerLF = false; }
  return _dockerLF;
}
