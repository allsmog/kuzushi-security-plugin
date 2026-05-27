#!/usr/bin/env node
// Prepare phase for /traffic-map (offline Burp/HAR import). Parses a captured
// traffic export — HAR (JSON) or a Burp "Save items" XML export — into observed
// endpoints (method, path, params, cookies), and gathers the source-side handler
// hints (x-ray entry points + code-graph entry points) so the traffic-mapper
// agent can correlate observed requests to source handlers. Offline, read-only,
// deterministic. Does NOT proxy or send anything.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join, basename } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { listFiles } from "../lib/ripgrep.mjs";

function pathOf(url) {
  try { return new URL(url).pathname; } catch { return String(url).split("?")[0].replace(/^https?:\/\/[^/]+/, "") || url; }
}
function queryNames(url) {
  try { return [...new URL(url).searchParams.keys()]; } catch {
    const q = String(url).split("?")[1];
    return q ? q.split("&").map((kv) => kv.split("=")[0]).filter(Boolean) : [];
  }
}

// HAR: log.entries[].request → method/url/headers/postData/queryString.
function parseHar(text) {
  const endpoints = [];
  let har; try { har = JSON.parse(text); } catch { return endpoints; }
  for (const e of har?.log?.entries ?? []) {
    const req = e.request; if (!req?.url) continue;
    const headers = req.headers ?? [];
    const bodyParams = (req.postData?.params ?? []).map((p) => p.name).filter(Boolean);
    endpoints.push({
      method: req.method ?? "GET", path: pathOf(req.url),
      query: (req.queryString ?? []).map((q) => q.name).filter(Boolean).concat(queryNames(req.url)),
      bodyParams,
      hasCookies: Boolean((req.cookies ?? []).length || headers.some((h) => /^cookie$/i.test(h.name))),
      source: "har"
    });
  }
  return endpoints;
}

// Burp "Save items" XML export: <item><method/><url/><request base64?>…</request>.
function parseBurpXml(text) {
  const endpoints = [];
  const items = text.split(/<item>/i).slice(1);
  for (const item of items) {
    const url = (item.match(/<url>(?:<!\[CDATA\[)?([^<\]]+)/i) ?? [])[1];
    const method = (item.match(/<method>(?:<!\[CDATA\[)?([A-Z]+)/i) ?? [])[1] ?? "GET";
    if (!url) continue;
    let body = "";
    const reqM = item.match(/<request(\s+base64="true")?>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/request>/i);
    if (reqM) {
      const raw = reqM[1] ? Buffer.from(reqM[2].trim(), "base64").toString("utf8") : reqM[2];
      body = raw.split(/\r?\n\r?\n/).slice(1).join("\n"); // after headers
    }
    endpoints.push({
      method, path: pathOf(url), query: queryNames(url),
      bodyParams: body.includes("=") && !body.trim().startsWith("{") ? body.split("&").map((kv) => kv.split("=")[0]).filter((n) => n && n.length < 60) : [],
      hasCookies: /(^|\n)cookie:/i.test(item),
      source: "burp"
    });
  }
  return endpoints;
}

// Find a capture: explicit input.file, else auto-discover *.har / Burp XML.
function findCaptures(target, input) {
  if (input.file) {
    const abs = resolve(target, input.file);
    return existsSync(abs) ? [input.file] : [];
  }
  return listFiles(target, { includeGlobs: ["*.har", "**/*.har", "*.xml", "**/*.xml"] })
    .filter((rel) => {
      if (rel.endsWith(".har")) return true;
      try { return /<items[\s>]|burpVersion/i.test(readFileSync(resolve(target, rel), "utf8").slice(0, 4000)); } catch { return false; }
    }).slice(0, 5);
}

// Dedupe endpoints by method+path; tally how many times each was observed.
function dedupe(endpoints) {
  const byKey = new Map();
  for (const e of endpoints) {
    const key = `${e.method} ${e.path}`;
    const prev = byKey.get(key);
    if (prev) {
      prev.count += 1;
      prev.query = [...new Set([...prev.query, ...e.query])];
      prev.bodyParams = [...new Set([...prev.bodyParams, ...e.bodyParams])];
      prev.hasCookies = prev.hasCookies || e.hasCookies;
    } else {
      byKey.set(key, { ...e, query: [...new Set(e.query)], bodyParams: [...new Set(e.bodyParams)], count: 1 });
    }
  }
  return [...byKey.values()];
}

export function prepareTrafficMap(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const captures = findCaptures(resolvedTarget, input);

  let endpoints = [];
  for (const rel of captures) {
    const text = readFileSync(resolve(resolvedTarget, rel), "utf8");
    endpoints.push(...(rel.endsWith(".har") ? parseHar(text) : parseBurpXml(text)));
  }
  endpoints = dedupe(endpoints).slice(0, Number(input.maxEndpoints ?? 120));

  // Source-side handler hints for correlation.
  const entryPoints = readJsonIfPresent(join(store.xRayDir, "entry-points.json")) ?? [];
  const codeGraph = readJsonIfPresent(store.codeGraphPath);

  const run = openRun(resolvedTarget, "traffic-map");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    captures, endpointCount: endpoints.length, endpoints,
    handlerHints: {
      xrayEntryPoints: Array.isArray(entryPoints) ? entryPoints.slice(0, 80) : [],
      codeGraphEntryPoints: codeGraph?.entryPoints ?? []
    },
    input
  });

  return {
    ok: true,
    status: captures.length ? (endpoints.length ? "prepared" : "no-endpoints") : "no-capture",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.traffic-map.json"),
    captures, endpointCount: endpoints.length,
    note: captures.length ? undefined : "no HAR/Burp export found — pass --input '{\"file\":\"capture.har\"}'",
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "traffic-map-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("traffic-map-prepare --target <path> [--input '{\"file\":\"capture.har\"}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("traffic-map-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareTrafficMap(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
