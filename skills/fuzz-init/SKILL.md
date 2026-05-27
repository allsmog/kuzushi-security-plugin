---
name: fuzz-init
description: Initialize a local fuzzing campaign plan from confirmed/proven findings. Creates .kuzushi/fuzz/fuzz-plan.json with engine recommendations, harness directories, run commands to review, and semantic-oracle guidance. Requires /verify first.
allowed-tools: Bash, Read, Write, Edit
user-invocable: true
---

# Fuzz init

Create the campaign plan and harness workspaces:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-init.mjs" --target "<repo root>"`

If it returns `no-seeds`, tell the user to run `/verify` first. If it returns `prepared`, read
`.kuzushi/fuzz/fuzz-plan.json`, write or refine the harness files only inside each candidate's
`harnessDir`, and keep the `runCommand` concrete enough for `/fuzz-run` to execute. Do not edit
application source from this command.
