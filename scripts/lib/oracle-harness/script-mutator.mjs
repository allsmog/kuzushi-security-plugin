// Framework-owned grammar-stress mutator for SCRIPT / interpreter entries (an `EVAL`-style
// command, a query language, a config/template DSL). When an entry's argument is itself a
// PROGRAM, the input space is a grammar, not a flat byte string — so the discovery agent
// declares the script entry + seeds, and THIS file (not agent code) generates parser/lexer/
// GC-stressing variants of the seed programs. The framework owning the mutator keeps the
// verdict ungameable (the agent never injects the input that "happens" to crash — it only
// names the entry and the seed corpus; the sanitizer still decides truth).
//
// Anti-overfit: every operator is a TEXTBOOK parser-fuzzing transform (boundary integers,
// deep nesting, unbounded delimiters, malformed/truncated tokens, duplication, splice) —
// nothing names a language, function, or CVE. Seeds are the TARGET's own bundled programs.
// Deterministic given (seeds, runSeed, index) — a seeded xorshift PRNG mirroring fuzz-driver.c
// — so the finalize reproduces a crashing script exactly.

// Boundary integers — the classic driver of integer-overflow-in-range / size-calc bugs.
const BOUNDARY_INTS = [
  "0", "1", "-1", "2", "255", "256", "65535", "65536",
  "2147483647", "-2147483648", "2147483648", "4294967295",
  "9223372036854775807", "-9223372036854775808"
];

function rng(seed) {
  let s = (seed >>> 0) || 0x9e3779b9;
  return () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return (s >>> 0) / 0x100000000; };
}

// Apply one general grammar-stress operator to a program string.
function applyOp(op, s, rand, pick, seeds) {
  switch (op) {
    case 0: { // boundary-int substitution: push an integer literal to an overflow boundary
      let done = false;
      return s.replace(/-?\b\d+\b/, (m) => (done ? m : (done = true, pick(BOUNDARY_INTS))));
    }
    case 1: { // deep nesting: recursive-descent / stack-depth stress
      const d = 64 + Math.floor(rand() * 8000);
      return "(".repeat(d) + s + ")".repeat(d);
    }
    case 2: { // delimiter stress: long AND MALFORMED long-brackets — the states that drive
      // lexer length/underflow bugs (read_long_string computing a buffer span from the level).
      // Valid-only long strings just parse; the bug lives in the malformed/edge shapes.
      const n = 16 + Math.floor(rand() * 4096);
      const m = Math.floor(rand() * (n + 1));            // a DIFFERENT close level (mismatch)
      const eq = "=".repeat(n);
      switch (Math.floor(rand() * 6)) {
        case 0: return `[${eq}[${s}]${eq}]`;             // valid long string
        case 1: return `[${eq}[${s}`;                    // UNTERMINATED long bracket
        case 2: return `[${eq}[${s}]${"=".repeat(m)}]`;  // MISMATCHED close level
        case 3: return `[${eq}[]${eq}]`;                 // empty body, varied level
        case 4: return `--[${eq}[${s}]${eq}]`;           // long COMMENT (same read path)
        default: return `[${eq}[`;                        // bare opener, no body, no close
      }
    }
    case 3: // truncation: cut to a prefix (premature-EOF / unterminated-token lexer states)
      return s.slice(0, Math.max(1, Math.floor(s.length * rand())));
    case 4: { // long token: a very long numeric/identifier run (token-buffer stress)
      const n = 512 + Math.floor(rand() * 16384);
      return `${s} ${"9".repeat(n)}`;
    }
    case 5: { // duplication: repeat the program (allocation / table-growth stress)
      const k = 2 + Math.floor(rand() * 64);
      return Array.from({ length: k }, () => s).join("\n");
    }
    case 6: // splice: concatenate another seed (cross-pollinate valid constructs)
      return `${s}\n${seeds.length ? String(pick(seeds)) : s}`;
    default:
      return s;
  }
}

// Generate the index-th mutated program from the seed corpus. Deterministic.
export function scriptMutate(seeds, runSeed, index) {
  const list = Array.isArray(seeds) && seeds.length ? seeds : ["return 1"];
  const rand = rng(((runSeed >>> 0) ^ (Math.imul(index + 1, 2654435761) >>> 0)) >>> 0);
  const pick = (arr) => arr[Math.floor(rand() * arr.length) % arr.length];
  let s = String(pick(list));
  const ops = 1 + Math.floor(rand() * 3);            // 1–3 stacked operators
  for (let i = 0; i < ops; i++) s = applyOp(Math.floor(rand() * 7), s, rand, pick, list);
  // Cap so one pathological mutation can't blow the wire / the server's read buffer in a way
  // that just OOMs (we want a memory-safety abort, not allocation-too-big noise).
  return s.length > 200000 ? s.slice(0, 200000) : s;
}

// Deterministically materialize a batch of N mutated programs (used by the driver loop).
export function scriptCorpusBatch(seeds, runSeed, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(scriptMutate(seeds, runSeed, i));
  return out;
}
