---
name: build-databases
description: Build the heavy semantic indexes the codeql/joern backends query — a CodeQL database (per detected language) and a Joern CPG — under .kuzushi/. Runs asynchronously in the background (doesn't block the session); installs the CLI first if missing. Pass "codeql" or "joern" to build just one.
argument-hint: "[codeql|joern]"
allowed-tools: Bash
---

# Build codeql DB / joern CPG

Kick off the (slow, multi-minute) build of the semantic indexes that `codeql:query` /
`joern:query` need — so `/threat-hunt` and `/invariant-test` can use those backends.

Run, using the project working directory as `<cwd>` and `$ARGUMENTS` (`codeql`, `joern`, or
empty = both) as `--which`:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/build-databases.mjs" --target "<cwd>" --which ${ARGUMENTS:-both} --background --include-install
```

It spawns the build **in the background** and returns immediately with `{ status:"started",
pid, logPath }`. Tell the user it's building (progress in `.kuzushi/db-build.log`), that it
installs the codeql/joern CLI first if missing (~1–3 GB), and that the indexes will be ready
for codeql/joern queries once it finishes (artifacts: `.kuzushi/codeql-db/<lang>`,
`.kuzushi/joern/cpg.bin.zip`). Note: CodeQL uses buildless extraction (`--build-mode=none`)
for Java/C#, so quality is lower than a full build and may be incomplete on some projects.
