// Shared, append-only crash log for the discovery-by-execution lane. Parallel
// discoverers all write here so a second discoverer that rediscovers the same bug can
// see it's already logged (a real dup_check) instead of promoting a duplicate finding.
// Top-frame dedup: the key is the sanitizer's "<errorClass>:<file>:<line>" — the same
// shape /fuzz-triage groups by — so two crashes with the same class at the same site
// are one bug even if the inputs differ. Inspired by the defending-code reference's
// found-bugs log; our own wording + format.

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { storeFor } from "./artifact-store.mjs";

// Stable crash identity from a parsed sanitizer report. Falls back to the error class
// alone, then to a caller-supplied label, so a report with no frame still has a key.
export function crashKey(sanitizer, fallback = "unknown") {
  if (!sanitizer) return `none:${fallback}`;
  const f = sanitizer.frame0 ?? {};
  const site = f.file ? `${f.file}:${f.line ?? ""}` : (f.symbol ?? "");
  return `${sanitizer.errorClass ?? "crash"}:${site || fallback}`;
}

function readKeys(path) {
  const keys = new Set();
  if (!existsSync(path)) return keys;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { const e = JSON.parse(line); if (e.crashKey) keys.add(e.crashKey); } catch { /* skip a torn line */ }
  }
  return keys;
}

// Has this crash key already been logged for the target?
export function seenCrash(target, key) {
  return readKeys(storeFor(target).crashLogPath).has(key);
}

// Append a crash record. Returns { appended, duplicate } — duplicate:true means the key
// was already present (the caller should not promote a second finding for it). The
// append itself is idempotent-ish: we still write the record (for provenance) but flag
// the dup so promotion can skip. Append is atomic enough for the line sizes here; the
// findings index keeps the real cross-process lock.
export function appendCrash(target, { crashKey: key, fingerprint = null, title = null, cwe = null, source = "fuzz-discover" }) {
  const path = storeFor(target).crashLogPath;
  const duplicate = readKeys(path).has(key);
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify({ crashKey: key, fingerprint, title, cwe, source, at: new Date().toISOString() })}\n`);
  return { appended: true, duplicate };
}
