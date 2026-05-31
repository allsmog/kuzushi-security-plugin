#!/usr/bin/env node
// Framework-owned DAEMON driver — the memory-class analog of the prototype-pollution oracle.
//
// The eval probe proved the discoverer can diagnose the exact bug and construct the exact
// trigger (XADD→XGROUP→XACKDEL IDS 9) — but its HAND-ROLLED run.sh kept losing the crash:
// it routed the server's AddressSanitizer report to a side file the finalize never read, used
// hardcoded paths, and raced the server's startup. So the agent now declares only WHAT to send;
// this script owns the fragile plumbing and does the one thing that matters: it captures the
// server's sanitizer abort and prints it to STDOUT, where parseSanitizerReport (and the
// first-party / weak-tier gates) read it. General for any socket daemon.
//
// Config (JSON file, argv[2]):
//   { repo, buildCommand?, serverCommand (with {PORT}), protocol: resp|inline|raw,
//     readyProbe?: [args], sequence: [[args]...], sanitizeEnv: {...}, settleMs? }

import { readFileSync } from "node:fs";
import { spawn, execSync } from "node:child_process";
import { Socket } from "node:net";

// Frame one command's args for the wire. Exported for unit testing.
export function frameCommand(protocol, args) {
  const a = (Array.isArray(args) ? args : [args]).map((x) => String(x));
  if (protocol === "resp") {
    return `*${a.length}\r\n` + a.map((s) => `$${Buffer.byteLength(s)}\r\n${s}\r\n`).join("");
  }
  if (protocol === "raw") return a.join("");
  return `${a.join(" ")}\r\n`; // inline / line protocols
}

function freePortFor(pid) { return 20000 + (pid % 40000); } // deterministic, no RNG, collision-light

async function connectWithRetry(port, deadlineMs) {
  const start = Date.now();
  while (Date.now() - start < deadlineMs) {
    const sock = await new Promise((res) => {
      const s = new Socket();
      s.once("connect", () => res(s));
      s.once("error", () => { s.destroy(); res(null); });
      s.connect(port, "127.0.0.1");
    });
    if (sock) return sock;
    await new Promise((r) => setTimeout(r, 150));
  }
  return null;
}

async function main() {
  const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
  const repo = cfg.repo || process.cwd();
  const protocol = cfg.protocol || "resp";
  const PORT = freePortFor(process.pid);

  if (cfg.buildCommand) {
    try { execSync(cfg.buildCommand, { cwd: repo, stdio: ["ignore", "ignore", "inherit"], timeout: 1200000 }); }
    catch { console.log("daemon-driver: build failed"); process.exit(2); } // → harness-failed-build
  }

  const serverCmd = String(cfg.serverCommand || "").replaceAll("{PORT}", String(PORT));
  if (!serverCmd) { console.error("daemon-driver: serverCommand required"); process.exit(2); }

  // Start the server, CAPTURING its stderr+stdout — this is the whole point (the abort prints here).
  const env = { ...process.env, ...(cfg.sanitizeEnv || {}) };
  const srv = spawn("sh", ["-c", serverCmd], { cwd: repo, env });
  let captured = "";
  let exited = null;
  srv.stdout.on("data", (d) => { captured += d.toString(); });
  srv.stderr.on("data", (d) => { captured += d.toString(); });
  srv.on("exit", (code, sig) => { exited = { code, sig }; });

  const sanitizerSeen = () => /ERROR:\s*(?:Address|Undefined|Leak)Sanitizer|runtime error:|SUMMARY:\s*\w*Sanitizer|DEADLYSIGNAL/i.test(captured);

  // Wait for the server to accept connections (poll, don't sleep-and-pray).
  const sock = await connectWithRetry(PORT, 30000);
  if (!sock) {
    // It may have crashed on startup — surface whatever it printed.
    console.log(captured || "daemon-driver: server never became ready");
    try { srv.kill("SIGKILL"); } catch {}
    process.exit(sanitizerSeen() ? 66 : 2);
  }

  // Optional readiness handshake, then drive the sequence.
  const send = (args) => new Promise((res) => { sock.write(frameCommand(protocol, args)); setTimeout(res, 60); });
  if (Array.isArray(cfg.readyProbe) && cfg.readyProbe.length) { await send(cfg.readyProbe); }
  for (const cmd of cfg.sequence || []) {
    if (exited) break;          // server already died (the crash) — stop sending
    await send(cmd);
  }
  try { sock.end(); } catch {}

  // Let the abort settle, then report. The crash manifests as: server exit on the sanitizer
  // exitcode, or a sanitizer signature already in the captured stream.
  await new Promise((r) => setTimeout(r, cfg.settleMs ?? 1200));
  try { srv.kill("SIGKILL"); } catch {}
  await new Promise((r) => setTimeout(r, 150));

  // The crucial line: print the captured server output (carrying any ASan/UBSan report) to STDOUT.
  console.log(captured);
  process.exit(sanitizerSeen() ? 66 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) { main(); }
