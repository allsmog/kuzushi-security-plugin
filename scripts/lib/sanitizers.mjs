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
  return null;
}

function firstLine(s, re) {
  const line = s.split(/\r?\n/).find((l) => re.test(l));
  return (line ?? "").trim().slice(0, 240);
}
// First `#0 ... file:line` frame from the sanitizer backtrace, if any.
function firstFrame(s) {
  const m = /#0[^\n]*?(\/[^\s:]+|\b[\w./-]+\.(?:c|cc|cpp|h|hpp|rs|m)):(\d+)/.exec(s);
  return m ? { file: m[1], line: Number(m[2]) } : null;
}

// Toolchain detection. Returns { cc, kind, asan, ubsan, rust } — best-effort; we trust
// clang/gcc to support -fsanitize=address,undefined on Linux/macOS (the common case).
export function detectToolchain() {
  for (const cc of ["clang", "gcc", "cc"]) {
    const r = spawnSync(cc, ["--version"], { encoding: "utf8" });
    if (!r.error && r.status === 0) {
      return { cc, kind: /clang/i.test(r.stdout) ? "clang" : "gcc", asan: true, ubsan: true };
    }
  }
  const cargo = spawnSync("cargo", ["--version"], { stdio: "ignore" });
  return { cc: null, kind: null, asan: false, ubsan: false, rust: !cargo.error && cargo.status === 0 };
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
