#!/usr/bin/env node
// PreToolUse guardrail for Read / Edit / Bash. Blocks access to credential and
// secret files so the agent — which routinely opens UNTRUSTED target repos — can
// never be steered into exfiltrating the operator's keys. Blocks by exiting with
// code 2 and writing the reason to stderr (fed back to the model).
//
// Covers Read/Edit `file_path` and Bash command strings that reference well-known
// secret locations: SSH/GPG keys, cloud + kube creds, package-registry tokens,
// git credentials, the macOS Keychain, and crypto wallets.
//
// Adapted from the Trail of Bits claude-code-config permission deny-list. This is
// defense in depth alongside the documented settings.json `permissions.deny`
// (docs/HARDENING.md) — a plugin cannot set user permissions, but it can hook.
// Must FAIL OPEN: any internal error exits 0 (allow).

import { homedir } from "node:os";

// Substrings that mark a secret path. Matched against the absolute, ~-expanded
// path (Read/Edit) and against the raw Bash command (so `cat ~/.ssh/id_rsa` is
// caught too). Kept as path fragments to limit false positives on normal files.
const SECRET_MARKERS = [
  "/.ssh/", "/.gnupg/", "/.aws/", "/.azure/", "/.kube/",
  "/.config/gcloud/", "/.docker/config.json",
  "/.npmrc", "/.pypirc", "/.netrc", "/.git-credentials",
  "/library/keychains/", "/.gnupg", "/.password-store/",
  "/.electrum/", "/.bitcoin/", "/wallet.dat", "/.ethereum/keystore",
  "id_rsa", "id_ed25519", "id_ecdsa", ".pem",
];

function expandHome(p) {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return homedir() + p.slice(1);
  return p;
}

function hits(haystack) {
  const h = haystack.toLowerCase();
  return SECRET_MARKERS.find((m) => h.includes(m));
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => { data += c; });
    process.stdin.on("end", () => resolve(data));
    if (process.stdin.isTTY) resolve("");
  });
}

async function run() {
  const raw = await readStdin();
  let input;
  try { input = JSON.parse(raw || "{}"); } catch { process.exit(0); }

  const tool = input?.tool_name;
  const ti = input?.tool_input ?? {};
  let target = "";
  if (tool === "Read" || tool === "Edit" || tool === "Write" || tool === "NotebookEdit") {
    target = expandHome(String(ti.file_path ?? ti.notebook_path ?? ""));
  } else if (tool === "Bash") {
    target = String(ti.command ?? "");
  }
  if (!target) process.exit(0);

  const marker = hits(target);
  if (marker) {
    process.stderr.write(
      `Blocked by kuzushi guardrail: access to a secret/credential path (matched "${marker}"). ` +
      "The agent does not read keys, cloud creds, registry tokens, keychains, or wallets. " +
      "If this is intentional, the user should do it themselves.\n"
    );
    process.exit(2);
  }
  process.exit(0);
}

run().catch(() => process.exit(0)); // fail open on any error
