#!/usr/bin/env node
// PreToolUse guardrail for Bash. Blocks two classes of irreversible/footgun
// commands by exiting with code 2 and writing the reason to stderr — Claude Code
// feeds that message back to the model so it can correct course:
//
//   1. `rm -rf` (recursive + force) — suggest `trash` so deletes are recoverable.
//   2. `git push` to main/master    — require a feature branch + PR instead.
//
// Adapted from the Trail of Bits claude-code-config PreToolUse hooks. This is a
// guardrail, not a sandbox: it catches the common dangerous shapes, not every
// obfuscation. It must FAIL OPEN — any internal error exits 0 (allow) so the
// guardrail can never wedge a session.

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => { data += c; });
    process.stdin.on("end", () => resolve(data));
    if (process.stdin.isTTY) resolve("");
  });
}

// `rm` invocation (anywhere in a pipeline) carrying both a recursive and a force
// flag, in short-cluster (-rf, -fr, -r -f) or long (--recursive --force) form.
function isDangerousRm(cmd) {
  const rmRe = /(?:^|[|;&\n]|&&|\|\|)\s*(?:sudo\s+)?rm\b([^|;&\n]*)/g;
  let m;
  while ((m = rmRe.exec(cmd))) {
    const tokens = m[1].split(/\s+/).filter(Boolean);
    let hasR = false, hasF = false;
    for (const t of tokens) {
      if (t === "--recursive") hasR = true;
      else if (t === "--force") hasF = true;
      else if (/^-[a-zA-Z]+$/.test(t)) {
        if (/[rR]/.test(t)) hasR = true;
        if (t.includes("f")) hasF = true;
      }
    }
    if (hasR && hasF) return true;
  }
  return false;
}

// `git push` that names main/master as the destination ref (incl. HEAD:main,
// force pushes). Bare `git push` is allowed — the branch isn't knowable here.
function isPushToProtected(cmd) {
  return /\bgit\s+push\b[^|;&\n]*\b(?:main|master)\b/.test(cmd);
}

async function run() {
  const raw = await readStdin();
  let cmd = "";
  try {
    cmd = String(JSON.parse(raw || "{}")?.tool_input?.command ?? "");
  } catch {
    process.exit(0); // unparseable input → fail open
  }
  if (!cmd) process.exit(0);

  if (isDangerousRm(cmd)) {
    process.stderr.write(
      "Blocked by kuzushi guardrail: `rm -rf` is irreversible. Use `trash` (recoverable) " +
      "or delete specific paths explicitly. If you truly need this, ask the user to run it.\n"
    );
    process.exit(2);
  }
  if (isPushToProtected(cmd)) {
    process.stderr.write(
      "Blocked by kuzushi guardrail: direct push to main/master. Create a feature branch " +
      "and open a PR (`git checkout -b <branch>` then push that branch).\n"
    );
    process.exit(2);
  }
  process.exit(0);
}

run().catch(() => process.exit(0)); // fail open on any error
