/* Portable ASan dumb-fuzz driver — discovery-by-execution without libFuzzer.
 *
 * Coverage-guided libFuzzer needs libclang_rt.fuzzer, which several toolchains
 * (notably Apple clang) don't ship. This driver provides the SAME entry-point API
 * (LLVMFuzzerTestOneInput) with our own bounded loop, so one harness works whether or
 * not libFuzzer is present. Compile WITH -fsanitize=address,undefined — a generated
 * input that trips a memory bug aborts mid-loop (the abort IS the discovery; kuzushi's
 * fuzz-triage then maps the report to a CWE).
 *
 * SEED CORPUS (the floor-lifter): pure random rarely clears a gate like
 * `if (data[0] != 'R') return;`. Pass a corpus dir of concrete inputs that already
 * clear such gates — kuzushi seeds it from /path-solve solvedInput and /verify pocSketch
 * payloads — and the loop MUTATES around those seeds (preserving the gate bytes,
 * perturbing the rest), so it explores past the gate instead of re-rolling 1/256 every
 * iteration. Still not coverage-guided; seeded mutation is the laptop-scale middle ground.
 *
 * Usage: cc -fsanitize=address,undefined -g harness.c fuzz-driver.c -o fuzz
 *        ./fuzz [iterations] [seed] [maxlen] [corpusDir]   (500000, time(0), 4096, none)
 * The harness defines: int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dirent.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_SEEDS 256

static unsigned char *g_seeds[MAX_SEEDS];
static size_t g_seed_len[MAX_SEEDS];
static int g_nseeds = 0;

static void load_corpus(const char *dir, size_t maxlen) {
  DIR *d = opendir(dir);
  if (!d) return;
  struct dirent *e;
  char path[4096];
  while ((e = readdir(d)) && g_nseeds < MAX_SEEDS) {
    if (e->d_name[0] == '.') continue;
    snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
    FILE *f = fopen(path, "rb");
    if (!f) continue;
    unsigned char *buf = (unsigned char *)malloc(maxlen ? maxlen : 1);
    size_t n = fread(buf, 1, maxlen, f);
    fclose(f);
    if (n == 0) { free(buf); continue; }
    g_seeds[g_nseeds] = buf;
    g_seed_len[g_nseeds] = n;
    g_nseeds++;
  }
  closedir(d);
}

/* Mutate a seed into buf: copy it, then apply a few random edits that perturb content
 * and length WITHOUT necessarily disturbing the leading gate bytes. Returns new length. */
static size_t mutate_from_seed(unsigned char *buf, size_t maxlen) {
  int s = rand() % g_nseeds;
  size_t n = g_seed_len[s];
  if (n > maxlen) n = maxlen;
  memcpy(buf, g_seeds[s], n);
  int edits = 1 + rand() % 6;
  for (int k = 0; k < edits; k++) {
    int op = rand() % 4;
    if (op == 0 && n > 0) {                         /* flip a bit (skip byte 0 often: keep gate) */
      size_t p = (n > 1) ? 1 + (size_t)rand() % (n - 1) : 0;
      buf[p] ^= (unsigned char)(1 << (rand() % 8));
    } else if (op == 1 && n > 1) {                  /* set a non-leading byte */
      size_t p = 1 + (size_t)rand() % (n - 1);
      buf[p] = (unsigned char)(rand() & 0xff);
    } else if (op == 2 && n < maxlen) {             /* grow (drives length-based overflows) */
      size_t add = 1 + (size_t)rand() % (maxlen - n);
      for (size_t i = 0; i < add; i++) buf[n + i] = (unsigned char)(rand() & 0xff);
      n += add;
    } else if (op == 3 && n > 1) {                  /* shrink */
      n = 1 + (size_t)rand() % n;
    }
  }
  return n;
}

static size_t gen_random(unsigned char *buf, size_t maxlen) {
  size_t n = (size_t)(rand() % (int)(maxlen + 1));
  for (size_t j = 0; j < n; j++) {
    int r = rand();
    buf[j] = (r & 7) == 0 ? (unsigned char)(r >> 8)
           : (r & 1) ? (unsigned char)(0x20 + (r >> 8) % 95)
           : (unsigned char)((r >> 8) & 0xff);
  }
  return n;
}

int main(int argc, char **argv) {
  unsigned long iters = argc > 1 ? strtoul(argv[1], 0, 10) : 500000UL;
  unsigned int seed  = argc > 2 ? (unsigned)strtoul(argv[2], 0, 10) : (unsigned)time(0);
  size_t maxlen      = argc > 3 ? (size_t)strtoul(argv[3], 0, 10) : 4096;
  const char *corpus = argc > 4 ? argv[4] : 0;
  srand(seed);
  if (corpus) load_corpus(corpus, maxlen);

  unsigned char *buf = (unsigned char *)malloc(maxlen ? maxlen : 1);

  /* Run every seed as-is first — a corpus entry might already trip the bug. */
  for (int s = 0; s < g_nseeds; s++) LLVMFuzzerTestOneInput(g_seeds[s], g_seed_len[s]);

  for (unsigned long i = 0; i < iters; i++) {
    /* 80% mutate-from-seed when seeds exist (explore past gates), else pure random. */
    size_t n = (g_nseeds > 0 && (rand() % 5) != 0) ? mutate_from_seed(buf, maxlen) : gen_random(buf, maxlen);
    LLVMFuzzerTestOneInput(buf, n);
  }
  free(buf);
  printf("dumbfuzz: %lu iterations, %d seeds, no crash (seed=%u, maxlen=%zu)\n", iters, g_nseeds, seed, maxlen);
  return 0;
}
