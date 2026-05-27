#!/usr/bin/env node
// Repository X-Ray: a deterministic static pass (ripgrep + fs, no LLM/MCP). It
// builds a file inventory, collects entry-point boundaries via pattern search,
// and writes <target>/x-ray/{x-ray.md,entry-points.md,invariants.md,architecture.svg}
// plus the run JSONs. Faithful port of kuzushi's host-x-ray.
//
// Importable: call runXray(target, input) directly. Runnable:
// `x-ray --target <path> [--input <json>]`.

import { existsSync, mkdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import {
  storeFor,
  openRun,
  atomicWrite,
  artifactSnapshot,
  emitResult
} from "../lib/artifact-store.mjs";
import { listFiles, runRg, parseJsonMatches, rankHit } from "../lib/ripgrep.mjs";

// Cap evidence-line length. Decompiled / minified targets (jadx, RN bundles)
// have "lines" that are hundreds of KB (e.g. a Kotlin `@Metadata(...)` blob), and
// emitting them verbatim bloated entry-points.md to 500KB+ and buried the real
// boundaries. A short, collapsed snippet is enough to locate the hit (file:line
// is the real anchor).
export const MAX_EVIDENCE_CHARS = 240;
export function clipEvidence(text) {
  const oneLine = String(text ?? "").replace(/\s+/g, " ").trim();
  return oneLine.length > MAX_EVIDENCE_CHARS ? `${oneLine.slice(0, MAX_EVIDENCE_CHARS)}… [truncated ${oneLine.length} chars]` : oneLine;
}

function languageFromPath(path) {
  if (path.endsWith(".java")) return "Java";
  if (path.endsWith(".kt") || path.endsWith(".kts")) return "Kotlin";
  if (path.endsWith(".smali")) return "Smali";
  if (path.endsWith(".js") || path.endsWith(".jsx")) return "JavaScript";
  if (path.endsWith(".ts") || path.endsWith(".tsx")) return "TypeScript";
  if (path.endsWith(".c") || path.endsWith(".h")) return "C";
  if (path.endsWith(".cc") || path.endsWith(".cpp") || path.endsWith(".hpp")) return "C++";
  if (path.endsWith(".rs")) return "Rust";
  if (path.endsWith(".rb") || path.endsWith(".erb")) return "Ruby";
  if (path.endsWith(".py")) return "Python";
  if (path.endsWith(".go")) return "Go";
  if (path.endsWith(".php")) return "PHP";
  return "Other";
}

function collectInventory(target, limit) {
  const files = listFiles(target);
  const byLanguage = {};
  for (const file of files) {
    const language = languageFromPath(file);
    byLanguage[language] = (byLanguage[language] ?? 0) + 1;
  }
  return { files: files.slice(0, limit), totalFiles: files.length, byLanguage };
}

const ENTRY_POINT_PATTERNS = [
  {
    id: "android-component",
    query: "Activity|Service|BroadcastReceiver|ContentProvider|onCreate\\(|onReceive\\(",
    boundary: "Android component or lifecycle boundary"
  },
  {
    id: "webview",
    query: "WebView|addJavascriptInterface|evaluateJavascript|setJavaScriptEnabled|loadUrl\\(",
    boundary: "WebView or JavaScript bridge boundary"
  },
  {
    id: "network",
    query: "Retrofit|OkHttpClient|HttpURLConnection|new URL\\(|@GET|@POST|fetch\\(",
    boundary: "Network request or response boundary"
  },
  {
    id: "payment-auth",
    query: "TokenizeCard|FIRST_DATA_URL|ChaseNetKeyApi|BraintreeClient|PayPal|Venmo|redirectUri|approvalUrl",
    boundary: "Payment, browser-return, or tokenization boundary"
  },
  {
    id: "native",
    query: "System\\.loadLibrary|JNIEXPORT|native\\s+|external fun",
    boundary: "Native or JNI boundary"
  },
  {
    id: "parser",
    query: "ObjectInputStream|readObject\\(|Parcelable|Serializable|JsonAdapter|ProtoAdapter|ZipInputStream",
    boundary: "Parser or deserialization boundary"
  },
  {
    id: "rails-controller",
    query: "class\\s+\\w+Controller\\s*<|before_action|skip_before_action|protect_from_forgery|params\\[",
    boundary: "Rails request boundary or controller authorization gate"
  }
];

const ENTRY_POINT_GLOBS = [
  "*.java", "*.kt", "*.kts", "*.js", "*.ts", "*.tsx", "*.jsx", "*.rb", "*.erb",
  "*.c", "*.cc", "*.cpp", "*.h", "*.hpp", "*.smali"
];

const ENTRY_POINT_EXCLUDES = [
  "!**/.git/**", "!**/.kuzushi/**", "!**/.joern/**", "!**/poc/**",
  "!**/apktool_out/**", "!**/androidx/**", "!**/org/chromium/**",
  "!**/io/sentry/**", "!**/com/google/**"
];

function collectEntryPoints(target, maxHits) {
  const globArgs = [];
  for (const glob of ENTRY_POINT_GLOBS) globArgs.push("-g", glob);
  for (const glob of ENTRY_POINT_EXCLUDES) globArgs.push("-g", glob);

  const hits = [];
  for (const pattern of ENTRY_POINT_PATTERNS) {
    const result = runRg(target, [
      "--json", "-n", "-S", "--max-count", "5",
      "-e", pattern.query,
      ...globArgs,
      "."
    ]);
    const matches = result.ok
      ? parseJsonMatches(result.stdout, Math.max(20, maxHits))
          .sort((left, right) => rankHit(right, "payment-android") - rankHit(left, "payment-android"))
          .slice(0, 20)
      : [];
    for (const match of matches) {
      hits.push({ ...match, text: clipEvidence(match.text), kind: pattern.id, boundary: pattern.boundary });
    }
  }
  return hits
    .sort((left, right) => rankHit(right, "payment-android") - rankHit(left, "payment-android"))
    .slice(0, maxHits);
}

function attackSurfaceAndContextPaths(target) {
  const store = storeFor(target);
  const paths = { attackSurface: null, context: null };
  if (!existsSync(store.runsDir)) return paths;
  const result = runRg(store.runsDir, ["--files", "-g", "attack-surface.json", "-g", "context.json"]);
  if (!result.ok) return paths;
  for (const path of result.stdout.split(/\r?\n/).filter(Boolean)) {
    if (path.endsWith("attack-surface.json") && !paths.attackSurface) paths.attackSurface = resolve(store.runsDir, path);
    if (path.endsWith("context.json") && !paths.context) paths.context = resolve(store.runsDir, path);
  }
  for (const key of ["attackSurface", "context"]) {
    if (paths[key] && existsSync(paths[key])) {
      paths[key] = { path: paths[key], mtime: statSync(paths[key]).mtime.toISOString() };
    } else {
      paths[key] = null;
    }
  }
  return paths;
}

function xRayMarkdown({ target, runId, inventory, entryPoints, artifacts }) {
  const verdict = entryPoints.length >= 20 ? "WATCH" : "READY";
  const lines = [
    "# X-Ray",
    "",
    "## X-Ray Verdict",
    verdict,
    "",
    `Run: ${runId}`,
    `Target: ${target}`,
    `Files indexed: ${inventory.totalFiles}`,
    `Languages: ${Object.entries(inventory.byLanguage).map(([key, value]) => `${key}=${value}`).join(", ") || "n/a"}`,
    "",
    "## Artifact Context",
    "",
    `Threat model: ${artifacts.threatModel?.path ?? "not present"}`,
    `Threat leads: ${artifacts.threatLeads?.path ?? "not present"}`,
    `Attack surface: ${artifacts.attackSurface?.path ?? "not present"}`,
    `Context: ${artifacts.context?.path ?? "not present"}`,
    "",
    "## Review Focus",
    "",
    "This X-Ray is generated by the host plugin from repository structure, attack-surface artifacts, threat-model artifacts, and bounded source evidence. It prepares the active agent for deeper tracing; it does not claim exploitability by itself.",
    "",
    "High-signal focus areas:",
    ...entryPoints.slice(0, 12).map((hit) => `- ${hit.boundary}: ${hit.filePath}:${hit.line}`)
  ];
  return `${lines.join("\n")}\n`;
}

function entryPointsMarkdown({ entryPoints }) {
  const counts = {};
  for (const hit of entryPoints) counts[hit.kind] = (counts[hit.kind] ?? 0) + 1;
  const lines = [
    "# Entry Points",
    "",
    `Summary: total=${entryPoints.length}, ${Object.entries(counts).map(([key, value]) => `${key}=${value}`).join(", ") || "none"}`,
    "",
    "## Boundaries"
  ];
  for (const hit of entryPoints) {
    lines.push(
      "",
      `### ${hit.kind}`,
      `${hit.filePath}:${hit.line}`,
      "",
      hit.boundary,
      "",
      `Evidence: \`${String(hit.text ?? "").replaceAll("`", "'")}\``
    );
  }
  return `${lines.join("\n")}\n`;
}

function invariantsMarkdown({ entryPoints, artifacts }) {
  const lines = [
    "# Invariants",
    "",
    "G-1. Source-derived findings require an attacker-controlled path and file/line evidence.",
    "I-1. Payment, OAuth, and browser-return flows must preserve state, origin, and token boundary invariants.",
    "X-1. WebView and JavaScript bridge flows must not allow untrusted script to cross into privileged native methods.",
    "E-1. Native/JNI and parser boundaries require separate reachability and memory-safety review.",
    "",
    "## Context Inputs",
    "",
    `Threat model present: ${Boolean(artifacts.threatModel)}`,
    `Threat leads present: ${Boolean(artifacts.threatLeads)}`,
    `Attack surface present: ${Boolean(artifacts.attackSurface)}`,
    `Candidate boundary count: ${entryPoints.length}`
  ];
  return `${lines.join("\n")}\n`;
}

function architectureSvg({ entryPoints }) {
  const labels = [...new Set(entryPoints.map((hit) => hit.kind))].slice(0, 5);
  const nodes = labels.length > 0 ? labels : ["repository", "threat-model", "active-agent"];
  const height = 120 + nodes.length * 56;
  const nodeSvg = nodes
    .map((label, index) => {
      const y = 40 + index * 56;
      return `<rect x="40" y="${y}" width="260" height="32" rx="4" fill="#f7fafc" stroke="#334155"/><text x="54" y="${y + 21}" font-family="Arial" font-size="13" fill="#111827">${label}</text>`;
    })
    .join("\n");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="360" height="${height}" viewBox="0 0 360 ${height}">\n<rect width="360" height="${height}" fill="#ffffff"/>\n<text x="40" y="24" font-family="Arial" font-size="16" font-weight="700" fill="#111827">Host X-Ray Architecture</text>\n${nodeSvg}\n</svg>\n`;
}

// Core x-ray pass. Writes artifacts under <target>/x-ray/ and the run JSONs,
// returns the result envelope. Throws only on unexpected I/O failure.
export function runXray(target, input = {}) {
  const resolved = resolve(target);
  const store = storeFor(resolved);
  const run = openRun(resolved, "x-ray");
  mkdirSync(store.xRayDir, { recursive: true });

  const inventory = collectInventory(resolved, Number(input.inventoryLimit ?? 200));
  const entryPoints = collectEntryPoints(resolved, Number(input.maxEntryPoints ?? 80));
  const baseSnapshot = artifactSnapshot(resolved);
  const extra = attackSurfaceAndContextPaths(resolved);
  const artifacts = { ...baseSnapshot, ...extra };

  const result = {
    ok: true,
    status: "completed",
    summary: `host-x-ray generated ${entryPoints.length} entry point leads`,
    target: resolved,
    runId: run.runId,
    runDir: run.runDir,
    artifactPaths: {
      xRay: join(".kuzushi", "x-ray", "x-ray.md"),
      entryPoints: join(".kuzushi", "x-ray", "entry-points.md"),
      invariants: join(".kuzushi", "x-ray", "invariants.md"),
      architecture: join(".kuzushi", "x-ray", "architecture.svg")
    },
    contextArtifacts: artifacts,
    inventory,
    entryPointCount: entryPoints.length,
    entryPoints
  };

  atomicWrite(join(store.xRayDir, "x-ray.md"), xRayMarkdown({ target: resolved, runId: run.runId, inventory, entryPoints, artifacts }));
  atomicWrite(join(store.xRayDir, "entry-points.md"), entryPointsMarkdown({ entryPoints }));
  atomicWrite(join(store.xRayDir, "invariants.md"), invariantsMarkdown({ entryPoints, artifacts }));
  atomicWrite(join(store.xRayDir, "architecture.svg"), architectureSvg({ entryPoints }));
  run.writeJson("input.json", input);
  run.writeJson("artifact-context.json", artifacts);
  run.writeJson("inventory.json", { ...inventory, relativeRunDir: relative(resolved, run.runDir) });
  run.writeJson("entry-points.json", entryPoints);
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("x-ray --target <path> [--input <json>]: run the deterministic repository X-Ray pass.");
    process.exit(0);
  }

  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["json", "help"],
    value: ["target", "input", "input-file"]
  });

  if (!flags.target) {
    console.error("x-ray: --target is required");
    process.exit(1);
  }

  const input = loadInput(flags);
  emitResult(runXray(flags.target, input));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
