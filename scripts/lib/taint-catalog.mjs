// Typed CWE catalog for /taint-analysis, ported from kuzushi taint-iris-next
// (src/modules/taint-iris-next/cwe-reference.ts). Loads the JSON catalog and
// provides the deterministic ranking + structural-query seeding the prepare
// step runs before any LLM work. The agent-facing "CWE Candidate Catalog" is
// rendered from the ranked output so subagents cite real signals.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CATALOG_PATH = join(__dirname, "..", "data", "taint-cwe-catalog.json");

let cached = null;
export function loadCatalog() {
  if (!cached) cached = JSON.parse(readFileSync(CATALOG_PATH, "utf8")).entries;
  return cached;
}

// Normalize "cwe 89", "CWE_89", "89" → "CWE-89".
export function normalizeCweId(value) {
  const match = String(value).trim().match(/^(?:CWE[-_\s]*)?0*(\d+)$/i);
  if (!match) return String(value).trim().toUpperCase();
  return `CWE-${Number.parseInt(match[1], 10)}`;
}

function normalizeLanguageName(language) {
  const n = String(language).trim().toLowerCase();
  if (n === "js" || n === "node") return "javascript";
  if (n === "ts") return "typescript";
  if (n === "c++") return "cpp";
  if (n === "c#") return "csharp";
  return n;
}

// context-build's inventory.byLanguage uses display names ("JavaScript", "C++").
// Map them to the lowercase catalog language tokens.
const DISPLAY_LANG_TO_CATALOG = {
  Java: "java", Kotlin: "kotlin", Ruby: "ruby", Python: "python",
  JavaScript: "javascript", TypeScript: "typescript", C: "c", "C++": "cpp",
  Rust: "rust", Go: "go", PHP: "php", Scala: "scala"
};

export function languagesFromDisplayNames(byLanguage = {}) {
  const out = [];
  for (const [lang, count] of Object.entries(byLanguage)) {
    if (lang === "Other" || !(Number(count) > 0)) continue;
    out.push(DISPLAY_LANG_TO_CATALOG[lang] ?? lang.toLowerCase());
  }
  return out;
}

const WEB_TAINT_CLASSES = new Set([
  "xss", "sql-injection", "ldap-injection", "header-injection", "origin-validation",
  "csrf", "file-upload", "open-redirect", "idor", "missing-authorization",
  "incorrect-authorization", "mass-assignment", "ssrf", "nosql-injection",
  "prototype-pollution", "regex-injection", "ssti"
]);

const PYTHON_SPARSE_CONTEXT_PRIORITY = new Set([
  "command-injection", "os-command-injection", "sql-injection", "path-traversal",
  "ssrf", "xss", "deserialization", "xxe", "log-injection", "info-exposure",
  "missing-authorization", "incorrect-authorization", "hardcoded-credentials"
]);

function collectThreatCwes(threatModel) {
  const cwes = new Set();
  for (const threat of threatModel?.threats ?? []) {
    for (const cwe of threat.relatedCwe ?? []) cwes.add(normalizeCweId(cwe));
  }
  return cwes;
}

function buildRelevanceCorpus(context, threatModel) {
  const parts = [
    ...(context?.languages ?? []), ...(context?.frameworks ?? []),
    ...(context?.authPatterns ?? []), ...(context?.sanitizationLibs ?? []),
    ...(context?.ormOrDb ?? []), ...(context?.entryPoints ?? [])
  ];
  for (const threat of threatModel?.threats ?? []) {
    parts.push(threat.title ?? "", threat.description ?? "", threat.attackVector ?? "",
      ...(threat.missingMitigations ?? []), ...(threat.preconditions ?? []));
  }
  return parts.join(" ").toLowerCase();
}

function countKeywordHits(entry, corpus) {
  if (!corpus) return 0;
  let hits = 0;
  for (const token of [entry.taintClass, ...entry.sourceSignals, ...entry.sinkSignals, ...entry.structuralQueries]) {
    const t = token.toLowerCase();
    if (t.length >= 3 && corpus.includes(t)) hits += 1;
  }
  return hits;
}

function cweNumeric(cwe) {
  const m = cwe.match(/CWE-(\d+)/);
  return m ? Number.parseInt(m[1], 10) : Number.MAX_SAFE_INTEGER;
}

// Rank the catalog by detected languages, threat-model relatedCwe, DB/web
// context, and keyword overlap — a direct port of rankCatalogEntries() from
// cwe-reference.ts. Returns entries sorted by descending score.
export function rankCatalog({ context, threatModel, languages = [], entries = loadCatalog() } = {}) {
  const languageSet = new Set([...(context?.languages ?? []), ...languages].map(normalizeLanguageName));
  const threatCwes = collectThreatCwes(threatModel);
  const corpus = buildRelevanceCorpus(context, threatModel);
  const hasSqlDb = (context?.ormOrDb ?? []).some((db) => /sql|postgres|mysql|sqlite|oracle/i.test(db));
  const hasWeb = context ? (context.frameworks ?? []).length > 0 || (context.entryPoints ?? []).length > 0 : false;
  const sparsePythonContext = languageSet.has("python") &&
    (!context || (context.frameworks ?? []).length + (context.ormOrDb ?? []).length + (context.entryPoints ?? []).length < 2);

  return entries.map((entry) => {
    let score = 0;
    const reasons = [];
    if (threatCwes.has(entry.cwe)) { score += 100; reasons.push("threat-model CWE"); }
    if (entry.languages.some((l) => languageSet.has(normalizeLanguageName(l))) ||
        (languageSet.size > 0 && entry.languages.includes("any"))) {
      score += 25; reasons.push("language match");
    }
    if (entry.languages.includes("any")) { score += 5; reasons.push("language agnostic"); }
    if (hasSqlDb && /sql|nosql|second-order/i.test(entry.taintClass)) { score += 35; reasons.push("database/ORM context"); }
    if (hasWeb && WEB_TAINT_CLASSES.has(entry.taintClass)) { score += 20; reasons.push("web entrypoint context"); }
    if (sparsePythonContext && PYTHON_SPARSE_CONTEXT_PRIORITY.has(entry.taintClass)) { score += 18; reasons.push("python sparse-context priority"); }
    const keywordHits = countKeywordHits(entry, corpus);
    if (keywordHits > 0) { score += Math.min(30, keywordHits * 5); reasons.push("context keyword overlap"); }
    return { ...entry, score, reasons };
  }).sort((a, b) => (b.score !== a.score ? b.score - a.score : cweNumeric(a.cwe) - cweNumeric(b.cwe)));
}

// Flatten ranked entries into deduped structural query seeds (source/sink/
// sanitizer/structural roles). Port of buildStructuralQueriesFromCatalog().
export function buildStructuralQueries(entries) {
  const seen = new Set();
  const queries = [];
  const add = (entry, role, pattern) => {
    const trimmed = String(pattern).trim();
    if (!trimmed) return;
    const key = `${entry.cwe}:${role}:${trimmed.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    queries.push({ id: `${entry.cwe.toLowerCase()}-${role}-${queries.length + 1}`, cwe: entry.cwe, taintClass: entry.taintClass, role, pattern: trimmed, languages: entry.languages });
  };
  for (const entry of entries) {
    for (const p of entry.sourceSignals) add(entry, "source", p);
    for (const p of entry.sinkSignals) add(entry, "sink", p);
    for (const p of entry.sanitizerSignals) add(entry, "sanitizer", p);
    for (const p of entry.structuralQueries) add(entry, "structural", p);
  }
  return queries;
}
