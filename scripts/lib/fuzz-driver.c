/* Portable ASan dumb-fuzz driver — discovery-by-execution without libFuzzer.
 *
 * Coverage-guided libFuzzer needs libclang_rt.fuzzer, which several toolchains
 * (notably Apple clang) don't ship. This driver provides the SAME entry-point API
 * (LLVMFuzzerTestOneInput) with our own bounded random/mutation loop, so one harness
 * works whether or not libFuzzer is present: link it with libFuzzer for coverage-guided
 * fuzzing, or with this driver for dependency-free dumb fuzzing. Compile the whole thing
 * WITH -fsanitize=address,undefined — a generated input that trips a memory bug makes the
 * sanitizer abort mid-loop, which IS the discovery (kuzushi's fuzz-triage then maps the
 * report to a CWE). Not coverage-guided, so it's weakest on deep magic-value gates; it's
 * the laptop-scale floor, honest about that.
 *
 * Usage: cc -fsanitize=address,undefined -g harness.c fuzz-driver.c -o fuzz
 *        ./fuzz [iterations] [seed] [maxlen]      (defaults: 500000, time(0), 4096)
 * The harness defines: int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  unsigned long iters = argc > 1 ? strtoul(argv[1], 0, 10) : 500000UL;
  unsigned int seed  = argc > 2 ? (unsigned)strtoul(argv[2], 0, 10) : (unsigned)time(0);
  size_t maxlen      = argc > 3 ? (size_t)strtoul(argv[3], 0, 10) : 4096;
  srand(seed);
  unsigned char *buf = (unsigned char *)malloc(maxlen ? maxlen : 1);
  for (unsigned long i = 0; i < iters; i++) {
    size_t n = (size_t)(rand() % (int)(maxlen + 1));
    /* Bias some bytes to common gate values (0x00/0xff/ASCII) to clear shallow checks. */
    for (size_t j = 0; j < n; j++) {
      int r = rand();
      buf[j] = (r & 7) == 0 ? (unsigned char)(r >> 8) /* random */
             : (r & 1) ? (unsigned char)(0x20 + (r >> 8) % 95) /* printable */
             : (unsigned char)((r >> 8) & 0xff);
    }
    LLVMFuzzerTestOneInput(buf, n);
  }
  free(buf);
  printf("dumbfuzz: %lu iterations, no crash (seed=%u, maxlen=%zu)\n", iters, seed, maxlen);
  return 0;
}
