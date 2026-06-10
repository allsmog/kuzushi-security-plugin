import { exec, execFile } from "node:child_process";
import express from "express";

const app = express();

// VULN (CWE-78): the user-controlled `host` flows into a shell command string.
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => res.send(stdout));
});

// SAFE decoy: same shape, but args go through execFile as an array — no shell is
// spawned, so `host` cannot break out. A correct triager must NOT flag this.
app.get("/lookup", (req, res) => {
  const host = req.query.host;
  execFile("nslookup", [host], (err, stdout) => res.send(stdout));
});

app.listen(3000);
