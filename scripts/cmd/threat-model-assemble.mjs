#!/usr/bin/env node
// Assemble the four PASTA stage artifacts (pasta-s1..s4.json, pasta-narrative.json)
// produced by the threat-modeler agent into the canonical .kuzushi/threat-model.json.
//
// Faithful Node port of kuzushi's convert_randori_artifacts_to_document
// (crates/kuzushi-core/.../application/read_randori_artifacts.rs and siblings):
//   S2 scope     → DFD nodes (actors/services/databases/components) + flows
//   S3 decompose → DFD nodes/flows + trust boundaries
//   S4 threats   → normalized threat records
// then normalize + build summary. Output shape matches
// schemas/run.threat-model.schema.json (methodology "pasta", version "2.0").

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, atomicWrite, emitResult } from "../lib/artifact-store.mjs";

const STRIDE_CATEGORIES = [
  "spoofing",
  "tampering",
  "repudiation",
  "information-disclosure",
  "denial-of-service",
  "elevation-of-privilege"
];

// ---- field helpers -------------------------------------------------------

function strField(record, keys) {
  for (const key of keys) {
    const value = record?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function stringArrayField(record, keys) {
  for (const key of keys) {
    const value = record?.[key];
    if (Array.isArray(value)) {
      return value.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
    }
    if (typeof value === "string" && value.trim()) return [value.trim()];
  }
  return [];
}

function nonemptyStringArray(values, fallback) {
  return values.length ? values : [fallback];
}

// An array of objects, a single object, or nothing.
function records(raw) {
  if (Array.isArray(raw)) return raw.filter((item) => item && typeof item === "object" && !Array.isArray(item));
  if (raw && typeof raw === "object") return [raw];
  return [];
}

// Like records(), but also accepts a map of {kind: [elements]} and flattens it.
function recordsOrRecordCollections(raw) {
  if (Array.isArray(raw)) return records(raw);
  if (raw && typeof raw === "object") {
    const values = Object.values(raw);
    if (values.some(Array.isArray)) {
      return values.flatMap((value) => (Array.isArray(value) ? records(value) : []));
    }
    return [raw];
  }
  return [];
}

// ---- type maps -----------------------------------------------------------

function actorTypeToDfd(kind) {
  switch ((kind ?? "").toLowerCase()) {
    case "external-user":
    case "external-service":
    case "external":
    case "human":
      return "external-entity";
    case "automated":
    case "downstream-service":
    case "internal-service":
      return "process";
    default:
      return "external-entity";
  }
}

function componentKindToDfd(kind) {
  const lower = (kind ?? "").toLowerCase();
  if (lower.includes("database") || lower.includes("store")) return "data-store";
  if (lower.includes("flow")) return "data-flow";
  return "process";
}

function normalizeDfdType(kind) {
  switch ((kind ?? "").toLowerCase().replaceAll("_", "-")) {
    case "external-entity":
    case "externalentity":
    case "external":
      return "external-entity";
    case "data-store":
    case "datastore":
      return "data-store";
    case "data-flow":
    case "dataflow":
      return "data-flow";
    default:
      return "process";
  }
}

export function normalizeStrideCategory(kind) {
  // Agents write the STRIDE category many ways — "Information Disclosure",
  // "information_disclosure", "Elevation of Privilege". Collapse spaces AND
  // underscores to hyphens (previously only "_" → "-", so any multi-word
  // category with a space — info-disclosure, elevation-of-privilege, DoS —
  // failed to match and the whole threat was silently dropped).
  const normalized = (kind ?? "").toLowerCase().trim().replace(/[\s_]+/g, "-");
  return STRIDE_CATEGORIES.find((category) => category === normalized) ?? null;
}

export function normalizeImpact(value) {
  // The agent usually writes impact as prose led by a severity word, e.g.
  // "CRITICAL — full account takeover" or "MEDIUM-HIGH — …". Match the first
  // severity keyword instead of requiring an exact enum (which silently
  // flattened every threat to "medium").
  const m = (value ?? "").toLowerCase().match(/\b(critical|high|medium|low)\b/);
  return m ? m[1] : "medium";
}

function probabilityToLikelihood(probability) {
  if (probability >= 0.7) return "high";
  if (probability >= 0.4) return "medium";
  return "low";
}

// ---- DFD node/flow assembly ---------------------------------------------

function insertNode(nodes, id, nodeType, name, description, trustZone) {
  if (nodeType === "data-flow") return;
  if (!nodes.has(id)) {
    nodes.set(id, { id, type: nodeType, name, description, trustZone });
  }
}

function collectFlows(raw, flows) {
  for (const item of records(raw)) {
    const id = strField(item, ["id"]);
    if (!id) continue;
    const source = strField(item, ["source_id", "sourceId", "source", "from"]);
    if (!source) continue;
    const target = strField(item, ["target_id", "targetId", "target", "destination", "to"]);
    if (!target) continue;
    const name = strField(item, ["name", "label", "data"]) ?? `${source} -> ${target}`;
    if (!flows.has(id)) {
      flows.set(id, {
        id,
        name,
        description: strField(item, ["description"]) ?? name,
        sourceId: source,
        targetId: target,
        protocol: strField(item, ["protocol"]) ?? "",
        dataClassification: strField(item, ["data_classification", "dataClassification", "classification", "sensitivity"]) ?? "",
        trustBoundaryIds: stringArrayField(item, ["trust_boundary_ids", "trustBoundaryIds", "crosses"])
      });
    }
  }
}

function collectS2(s2, nodes, flows) {
  if (!s2 || typeof s2 !== "object") return;
  for (const actor of records(s2.actors)) {
    const id = strField(actor, ["id"]);
    if (!id) continue;
    const name = strField(actor, ["name"]) ?? id;
    insertNode(nodes, id, actorTypeToDfd(strField(actor, ["type"]) ?? ""), name,
      strField(actor, ["description"]) ?? name,
      strField(actor, ["trust_zone", "trustZone", "trust_level"]) ?? "external");
  }
  for (const service of records(s2.services)) {
    const id = strField(service, ["id"]);
    if (!id) continue;
    const name = strField(service, ["name"]) ?? id;
    insertNode(nodes, id, "process", name, strField(service, ["description"]) ?? name, "internal");
  }
  for (const database of records(s2.databases)) {
    const id = strField(database, ["id"]);
    if (!id) continue;
    const name = strField(database, ["name"]) ?? id;
    insertNode(nodes, id, "data-store", name, strField(database, ["description"]) ?? name, "internal");
  }
  if (s2.components && typeof s2.components === "object" && !Array.isArray(s2.components)) {
    for (const [kind, list] of Object.entries(s2.components)) {
      for (const component of records(list)) {
        const id = strField(component, ["id", "name"]);
        if (!id) continue;
        const name = strField(component, ["name"]) ?? id;
        insertNode(nodes, id, componentKindToDfd(kind), name,
          strField(component, ["description"]) ?? kind,
          strField(component, ["trust_zone", "trustZone"]) ?? "internal");
      }
    }
  }
  collectFlows(s2.data_flows, flows);
}

function collectS3(s3, nodes, flows, trustBoundaries) {
  if (!s3 || typeof s3 !== "object") return;
  // standard node buckets
  for (const [key, defaultType, defaultZone] of [
    ["external_entities", "external-entity", "external"],
    ["entry_points", "process", "entrypoint"],
    ["processes", "process", "internal"],
    ["data_stores", "data-store", "internal"]
  ]) {
    for (const item of records(s3[key])) {
      const id = strField(item, ["id"]);
      if (!id) continue;
      const name = strField(item, ["name"]) ?? id;
      insertNode(nodes, id, defaultType, name,
        strField(item, ["description", "notes"]) ?? name,
        strField(item, ["trust_zone", "trustZone"]) ?? defaultZone);
    }
  }
  // freeform dfd_elements (array or map of lists)
  for (const item of recordsOrRecordCollections(s3.dfd_elements)) {
    const id = strField(item, ["id"]);
    if (!id) continue;
    const name = strField(item, ["name"]) ?? id;
    insertNode(nodes, id, normalizeDfdType(strField(item, ["type"]) ?? "process"), name,
      strField(item, ["description"]) ?? name,
      strField(item, ["trust_zone", "trustZone", "component"]) ?? "unknown");
  }
  collectFlows(s3.data_flows, flows);
  // trust boundaries (after flows so we can backfill crossings)
  for (const boundary of records(s3.trust_boundaries)) {
    const id = strField(boundary, ["id"]);
    if (!id) continue;
    const name = strField(boundary, ["name"]) ?? id;
    const crossings = new Set(stringArrayField(boundary, ["crossing_flow_ids", "crossingFlowIds", "crossing_flows", "flows"]));
    for (const flow of flows.values()) {
      if (Array.isArray(flow.trustBoundaryIds) && flow.trustBoundaryIds.includes(id) && flow.id) {
        crossings.add(flow.id);
      }
    }
    trustBoundaries.set(id, {
      id,
      name,
      innerZone: strField(boundary, ["inner_zone", "innerZone"]) ?? "internal",
      outerZone: strField(boundary, ["outer_zone", "outerZone"]) ?? "external",
      crossingFlowIds: [...crossings].sort()
    });
  }
}

// ---- threats -------------------------------------------------------------

function parseEvidenceAnchors(raw) {
  return records(raw)
    .map((anchor) => {
      const filePath = strField(anchor, ["filePath", "file_path", "path"]);
      if (!filePath) return null;
      const startLine = Number(anchor.startLine ?? anchor.start_line ?? anchor.line ?? 1) || 1;
      return { filePath, startLine };
    })
    .filter(Boolean);
}

function buildCweList(record) {
  return stringArrayField(record, ["related_cwe", "relatedCwe", "cwe", "cwes"]);
}

function parseThreats(s4) {
  const raw = Array.isArray(s4?.threat_scenarios)
    ? s4.threat_scenarios
    : Array.isArray(s4?.threats)
      ? s4.threats
      : [];
  const out = [];
  for (const record of raw) {
    if (!record || typeof record !== "object") continue;
    const id = strField(record, ["id"]);
    if (!id) continue;
    const title = strField(record, ["title", "name"]) ?? id;
    const category = normalizeStrideCategory(strField(record, ["stride_category", "category"]) ?? "");
    if (!category) continue;
    const evidenceAnchors = parseEvidenceAnchors(record.evidence_anchors ?? record.evidenceAnchors);
    const probability = typeof record.probability === "number" ? record.probability : 0.5;
    out.push({
      id,
      targetElementIds: nonemptyStringArray(
        stringArrayField(record, ["target_element_ids", "targetElementIds", "target_assets", "affected_components"]),
        "unknown"
      ),
      actorIds: stringArrayField(record, ["actor_ids", "actorIds", "actors"]),
      entrypointIds: stringArrayField(record, ["entrypoint_ids", "entrypointIds", "entry_points"]),
      flowIds: stringArrayField(record, ["flow_ids", "flowIds", "flows"]),
      category,
      title,
      description: strField(record, ["description"]) ?? title,
      attackVector: strField(record, ["attack_technique_id", "attackTechniqueId", "mitre_attack", "attack_scenario", "attack_vector", "attackVector"]) ?? "unknown",
      preconditions: stringArrayField(record, ["gaps", "preconditions"]),
      impact: normalizeImpact(strField(record, ["impact"]) ?? "medium"),
      likelihood: probabilityToLikelihood(probability),
      probability,
      existingMitigations: stringArrayField(record, ["existing_controls", "existingMitigations", "existing_mitigations"]),
      missingMitigations: stringArrayField(record, ["recommended_mitigations", "missingMitigations", "missing_mitigations", "recommended_remediation"]),
      relatedCwe: buildCweList(record),
      affectedFiles: evidenceAnchors,
      evidenceAnchors,
      elementId: strField(record, ["element_id", "elementId"]) ?? "unknown"
    });
  }
  return out;
}

function buildSummary(threats) {
  const bySeverity = {};
  const byCategory = {};
  for (const threat of threats) {
    if (threat.impact) bySeverity[threat.impact] = (bySeverity[threat.impact] ?? 0) + 1;
    if (threat.category) byCategory[threat.category] = (byCategory[threat.category] ?? 0) + 1;
  }
  return { total: threats.length, bySeverity, byCategory };
}

// ---- ASCII data-flow diagram --------------------------------------------

const ZONE_ORDER = ["external", "entrypoint", "internal"];

function truncAscii(text, max) {
  const s = String(text ?? "");
  return s.length > max ? `${s.slice(0, max - 2)}..` : s;
}

// Draw one framed ASCII box: a zone label in the top border, node rows inside.
// Pure ASCII (+, -, |) so it survives any terminal.
function drawBox(title, rows) {
  const contentW = Math.max(title.length + 4, ...rows.map((r) => r.length));
  const top = `+-- ${title} ${"-".repeat(Math.max(1, contentW - title.length - 2))}+`;
  const body = rows.map((r) => `| ${r.padEnd(contentW)} |`);
  const bottom = `+${"-".repeat(contentW + 2)}+`;
  return [top, ...body, bottom];
}

// Render the DFD as a plain-ASCII diagram: one box per trust zone (nodes grouped
// inside), then the flows as id-based arrows, then the trust boundaries. Uses
// short node IDs in the flow lines (names live in the boxes) so nothing wraps.
function renderAsciiDfd(document) {
  const nodes = document.dfd?.nodes ?? [];
  const flows = document.dfd?.flows ?? [];
  const boundaries = document.dfd?.trustBoundaries ?? [];

  const lines = [];
  lines.push(`Data Flow Diagram - ${document.methodology} threat model`);
  lines.push("=".repeat(50));
  lines.push("");

  if (!nodes.length) {
    lines.push("(no DFD nodes)");
  } else {
    const idW = nodes.reduce((max, n) => Math.max(max, (n.id ?? "").length), 0);
    const zones = new Map();
    for (const n of nodes) {
      const zone = n.trustZone || "unknown";
      if (!zones.has(zone)) zones.set(zone, []);
      zones.get(zone).push(n);
    }
    const zoneNames = [...zones.keys()].sort((a, b) => {
      const ia = ZONE_ORDER.indexOf(a);
      const ib = ZONE_ORDER.indexOf(b);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || a.localeCompare(b);
    });
    for (const zone of zoneNames) {
      const rows = zones.get(zone).map((n) => `${(n.id ?? "").padEnd(idW)}  ${truncAscii(n.name ?? n.id, 40)}`);
      lines.push(...drawBox(zone, rows), "");
    }
  }

  lines.push(`Flows (${flows.length}):  src --[ label ]--> dst  (trust boundary)`);
  if (!flows.length) lines.push("  (none)");
  const srcW = flows.reduce((max, f) => Math.max(max, (f.sourceId ?? "?").length), 0);
  for (const f of flows) {
    const label = truncAscii([f.name, f.protocol, f.dataClassification].filter(Boolean).join(" / "), 34);
    const arrow = label ? `--[ ${label} ]-->` : "-->";
    const crosses = f.trustBoundaryIds?.length ? `  (${f.trustBoundaryIds.join(", ")})` : "";
    lines.push(`  ${(f.sourceId ?? "?").padEnd(srcW)}  ${arrow}  ${f.targetId ?? "?"}${crosses}`);
  }
  lines.push("");

  lines.push(`Trust boundaries (${boundaries.length}):`);
  if (!boundaries.length) lines.push("  (none)");
  for (const b of boundaries) {
    const crossings = b.crossingFlowIds?.length ? `   crosses: ${b.crossingFlowIds.join(", ")}` : "";
    lines.push(`  ${b.id}  ${b.name}  [${b.outerZone} | ${b.innerZone}]${crossings}`);
  }

  return `${lines.join("\n")}\n`;
}

// ---- assemble ------------------------------------------------------------

function readJson(path) {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

export function assembleThreatModel(target, runDir, methodology = "pasta") {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const s2 = readJson(join(resolvedRunDir, "pasta-s2.json"));
  const s3 = readJson(join(resolvedRunDir, "pasta-s3.json"));
  const s4 = readJson(join(resolvedRunDir, "pasta-s4.json"));
  const narrative = readJson(join(resolvedRunDir, "pasta-narrative.json"));

  if (!s2 && !s3 && !s4) {
    throw new Error(`no PASTA stage artifacts found in ${resolvedRunDir} (expected pasta-s2/s3/s4.json)`);
  }

  const nodes = new Map();
  const flows = new Map();
  const trustBoundaries = new Map();
  collectS2(s2, nodes, flows);
  collectS3(s3, nodes, flows, trustBoundaries);

  const threats = s4 ? parseThreats(s4) : [];
  const document = {
    version: "2.0",
    methodology,
    dfd: {
      nodes: [...nodes.values()],
      flows: [...flows.values()],
      trustBoundaries: [...trustBoundaries.values()]
    },
    threats,
    summary: buildSummary(threats)
  };
  if (narrative && typeof narrative === "object") {
    document.narrative = narrative;
  }

  const json = `${JSON.stringify(document, null, 2)}\n`;
  atomicWrite(store.threatModelPath, json);
  atomicWrite(join(resolvedRunDir, "threat-model.json"), json);

  // Deterministic ASCII data-flow diagram, written next to the model and in the
  // run dir so the agent / session can paste it without re-deriving it.
  const asciiDfd = renderAsciiDfd(document);
  const asciiDfdPath = join(store.root, "threat-model-dfd.txt");
  atomicWrite(asciiDfdPath, asciiDfd);
  atomicWrite(join(resolvedRunDir, "threat-model-dfd.txt"), asciiDfd);

  return {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    threatModelPath: store.threatModelPath,
    asciiDfdPath,
    runDir: resolvedRunDir,
    methodology,
    counts: {
      nodes: document.dfd.nodes.length,
      flows: document.dfd.flows.length,
      trustBoundaries: document.dfd.trustBoundaries.length,
      threats: threats.length
    },
    summary: document.summary,
    asciiDfd
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("threat-model-assemble --target <path> --run-dir <dir> [--methodology pasta]: assemble PASTA stage files into .kuzushi/threat-model.json.");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["help"],
    value: ["target", "run-dir", "methodology"]
  });
  if (!flags.target) {
    console.error("threat-model-assemble: --target is required");
    process.exit(1);
  }
  if (!flags["run-dir"]) {
    console.error("threat-model-assemble: --run-dir is required");
    process.exit(1);
  }
  emitResult(assembleThreatModel(flags.target, flags["run-dir"], flags.methodology ?? "pasta"));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
