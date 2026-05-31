// Framework-owned portable coverage-guided fuzzing engine — the AIxCC "last-mile" borrow, done
// without libFuzzer or Docker so it runs on a stock toolchain (validated on Apple clang). It is the
// deterministic kernel the reference harnesses lacked: keep inputs that reach NEW edges, mutate
// them, run the target entry under a sanitizer; a sanitizer abort is the find.
//
// DETERMINISM BOUNDARY: this engine never decides a verdict. It only produces a crashing input; the
// sanitizer's own report (parsed by parseSanitizerReport in the finalize) is the verdict. The search
// is seeded (runSeed argv) and the crashing input is dumped (crash-input) so the finalize reproduces.
//
// The harness around the target entry point is supplied separately as `LLVMFuzzerTestOneInput`
// (the agent DECLARES that one-input wrapper; the framework owns this driver and the oracle). Build:
//   clang -O1 -g -fsanitize=address -fsanitize-coverage=trace-pc-guard cov-fuzz.c harness.c <target srcs>
// Run:  ./fuzzer <seconds> <seedDir> <runSeed>
//
// SCOPE (honest): this reaches bugs whose trigger is a reasonable-size STRUCTURED input — the class
// fuzzing is good at. It does NOT reach bugs gated behind a huge-operand integer overflow (a 32-bit
// counter that only wraps past ~2^30 of input, e.g. a lexer's long-bracket length math): no practical
// fuzzer emits gigabyte inputs. Those belong to the static int-overflow obligation (deep-scan), not here.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern void __asan_set_death_callback(void (*cb)(void));

// Coverage feedback: a guard fires the first time its edge executes, then we zero it — so a firing
// means a never-before-seen edge. new_edges>0 after a run == that input expanded coverage.
static volatile unsigned new_edges = 0;
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  static uint32_t n = 0; for (uint32_t *p = start; p < stop; p++) *p = ++n;
}
void __sanitizer_cov_trace_pc_guard(uint32_t *g) { if (*g) { new_edges++; *g = 0; } }

#define MAXC 8192
static uint8_t *corp[MAXC]; static size_t corl[MAXC]; static int ncorp = 0;
static void add(const uint8_t *d, size_t n) {
  if (ncorp >= MAXC || n > 200000) return;
  uint8_t *c = malloc(n ? n : 1); if (!c) return; memcpy(c, d, n); corp[ncorp] = c; corl[ncorp] = n; ncorp++;
}

static uint64_t rs = 0x9e3779b97f4a7c15ULL;          // overwritten by runSeed argv for reproducibility
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

// Mutation byte set, biased toward delimiters/digits/idents so structural mutation explores grammar,
// not just noise. General to any text/binary entry — the engine is grammar-agnostic.
static const char BYT[] = "[]{}()=\"'.,;:-+*/%#0123456789 \n\tabcdefghijklmnopqrstuvwxyz_";
static const size_t NBYT = sizeof(BYT) - 1;
static size_t mutate(const uint8_t *s, size_t sn, uint8_t *out, size_t cap) {
  size_t n = sn > cap ? cap : sn; memcpy(out, s, n);
  int ops = 1 + rnd() % 5;
  for (int i = 0; i < ops; i++) {
    int op = rnd() % 7;
    if (op == 0 && n > 0) out[rnd() % n] = BYT[rnd() % NBYT];                                   // set byte
    else if (op == 1 && n < cap) { size_t p = n ? rnd() % n : 0; memmove(out+p+1, out+p, n-p); out[p] = BYT[rnd()%NBYT]; n++; } // insert
    else if (op == 2 && n > 1) { size_t p = rnd() % n; memmove(out+p, out+p+1, n-p-1); n--; }   // delete
    else if (op == 3 && n && n*2 < cap) { memcpy(out+n, out, n); n *= 2; }                      // double
    else if (op == 4 && n < cap) { size_t k = 1 + rnd() % (cap-n > 256 ? 256 : cap-n); char c = BYT[rnd()%NBYT]; memset(out+n, c, k); n += k; } // long run
    else if (op == 5 && ncorp > 0) { int j = rnd() % ncorp; if (n+corl[j] < cap) { memcpy(out+n, corp[j], corl[j]); n += corl[j]; } } // splice
    else if (op == 6 && n > 0) { size_t p = rnd() % n, q = rnd() % n; uint8_t t = out[p]; out[p] = out[q]; out[q] = t; } // swap
  }
  return n;
}

static const uint8_t *g_cur = NULL; static size_t g_curn = 0;
static void death_cb(void) { FILE *f = fopen("crash-input", "wb"); if (f) { if (g_cur) fwrite(g_cur, 1, g_curn, f); fclose(f); } }
static void run_one(const uint8_t *d, size_t n) { new_edges = 0; g_cur = d; g_curn = n; LLVMFuzzerTestOneInput(d, n); }

int main(int argc, char **argv) {
  int secs = argc > 1 ? atoi(argv[1]) : 60;
  const char *seeddir = argc > 2 ? argv[2] : NULL;
  if (argc > 3) { uint64_t seed = strtoull(argv[3], NULL, 0); if (seed) rs = seed; }   // reproducible search
  __asan_set_death_callback(death_cb);

  if (seeddir) {
    DIR *dp = opendir(seeddir); struct dirent *e;
    while (dp && (e = readdir(dp))) {
      if (e->d_name[0] == '.') continue;
      char p[2048]; snprintf(p, sizeof p, "%s/%s", seeddir, e->d_name);
      FILE *f = fopen(p, "rb"); if (!f) continue;
      fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
      if (sz > 0 && sz < 200000) { uint8_t *b = malloc(sz); if (b && fread(b, 1, sz, f) == (size_t)sz) { run_one(b, sz); add(b, sz); } free(b); }
      fclose(f);
    }
    if (dp) closedir(dp);
  }
  if (ncorp == 0) { const uint8_t z[1] = {0}; run_one(z, 1); add(z, 1); }

  fprintf(stderr, "[cov-fuzz] seeded corpus=%d, fuzzing %ds (coverage-guided, seed=0x%llx)...\n",
          ncorp, secs, (unsigned long long)rs);
  static uint8_t buf[262144];
  time_t start = time(NULL); unsigned long iters = 0, covwins = 0;
  while (time(NULL) - start < secs) {
    int j = rnd() % ncorp;
    size_t n = mutate(corp[j], corl[j], buf, sizeof buf);
    run_one(buf, n);                       // sanitizer aborts here on a memory bug -> death_cb dumps crash-input
    if (new_edges) { add(buf, n); covwins++; }
    if (++iters % 100000 == 0) fprintf(stderr, "[cov-fuzz] iters=%lu corpus=%d cov-expanding=%lu\n", iters, ncorp, covwins);
  }
  fprintf(stderr, "[cov-fuzz] DONE: %lu iters, corpus %d, no crash in %ds\n", iters, ncorp, secs);
  return 0;
}
