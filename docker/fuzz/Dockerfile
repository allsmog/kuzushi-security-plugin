# Minimal clang+libFuzzer image for coverage-guided fuzzing in the kuzushi sandbox.
# clang from Ubuntu ships compiler-rt's libFuzzer (libclang_rt.fuzzer), which Apple
# clang lacks — so this is how /fuzz gets a real coverage-guided engine. Built once
# from the cached ubuntu base; runs with --network none.
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm && rm -rf /var/lib/apt/lists/*
WORKDIR /work
