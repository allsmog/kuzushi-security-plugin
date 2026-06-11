// Framework-aware route / endpoint extraction. Entry-point detection elsewhere is
// hand-written regex over generic shapes (risk-rank's ENTRY_DEF, x-ray's patterns),
// so framework route tables and OpenAPI specs get missed — and an uncovered handler
// is an uncovered bug. This turns concrete route declarations into structured entry
// points { framework, method, routePath, filePath, line } that feed the readers'
// anchoring and ranking. Ripgrep-backed and textual — a high-recall HINT, not a
// resolver; the agent confirms the handler.

import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { runRg, parseJsonMatches, buildGlobs } from "./ripgrep.mjs";

const norm = (p) => String(p ?? "").replace(/^\.\//, "");

// One rg pass finds candidate route lines; each line is then parsed by the first
// matching framework parser below. Order matters: the most specific (annotations,
// .route with methods) before the broad obj.method('path') form.
const ROUTE_RG = [
  "@(Get|Post|Put|Delete|Patch|Request)Mapping",
  "\\.(get|post|put|delete|patch|options|head|all|use)\\s*\\(\\s*['\"`]",
  "\\.(GET|POST|PUT|DELETE|PATCH|Any)\\s*\\(\\s*['\"`]",
  "\\.route\\s*\\(\\s*['\"]",
  "\\b(path|re_path|url)\\s*\\(\\s*r?['\"]",
  "\\b(get|post|put|patch|delete)\\s+['\"][^'\"]*['\"]\\s*(=>|,|$)",
  "\\.(HandleFunc|Handle)\\s*\\(\\s*['\"]"
].join("|");

const PARSERS = [
  // Spring: @GetMapping("/x") / @RequestMapping(value="/x")
  { framework: "spring", re: /@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)/,
    map: (m) => ({ method: m[1] === "Request" ? "ANY" : m[1].toUpperCase(), routePath: m[2] }) },
  // Flask: @app.route("/x", methods=["POST"])  (capture optional methods)
  { framework: "flask", re: /@\s*[\w.]+\.route\s*\(\s*["']([^"']+)["'](?:[^)]*methods\s*=\s*\[([^\]]*)\])?/,
    map: (m) => ({ method: m[2] ? m[2].replace(/["'\s]/g, "") || "GET" : "GET", routePath: m[1] }) },
  // Express / FastAPI / gin / echo / chi: (app|router|r|mux|e|g|api|server|bp|fastify).VERB("/x")
  { framework: "http", re: /\b(?:app|router|api|server|bp|blueprint|fastify|r|mux|e|g|srv|svc)\s*\.\s*(get|post|put|delete|patch|options|head|all|use|GET|POST|PUT|DELETE|PATCH|Any)\s*\(\s*["'`]([^"'`]+)/,
    map: (m) => { const v = m[1].toUpperCase(); return { method: v === "USE" || v === "ALL" || v === "ANY" ? "ANY" : v, routePath: m[2] }; } },
  // Django: path("x/", view) / re_path(r"^x$", view) / url(r"...", view)
  { framework: "django", re: /\b(?:path|re_path|url)\s*\(\s*r?["']([^"']*)/,
    map: (m) => ({ method: "ANY", routePath: m[1] || "/" }) },
  // Rails routes.rb: get "x" => "c#a"  /  post 'x'
  { framework: "rails", re: /\b(get|post|put|patch|delete)\s+["']([^"']+)["']/,
    map: (m) => ({ method: m[1].toUpperCase(), routePath: m[2] }) },
  // Go net/http: mux.HandleFunc("/x", h)  /  http.Handle("/x", h)
  { framework: "go-http", re: /\.(?:HandleFunc|Handle)\s*\(\s*["']([^"']+)/,
    map: (m) => ({ method: "ANY", routePath: m[1] }) }
];

function parseRouteLine(text) {
  for (const p of PARSERS) {
    const m = p.re.exec(text);
    if (m) {
      const r = p.map(m);
      if (r.routePath !== undefined) return { framework: p.framework, method: r.method || "ANY", routePath: r.routePath };
    }
  }
  return null;
}

// Code-declared routes via ripgrep + per-line parsing.
function codeRoutes(target, scopeDir) {
  const r = runRg(target, ["--json", "-n", "-S", "--max-count", "200", "-e", ROUTE_RG, ...buildGlobs(), scopeDir === "." ? "." : scopeDir]);
  if (!r.ok) return [];
  const out = [];
  for (const h of parseJsonMatches(r.stdout, 6000)) {
    const parsed = parseRouteLine(h.text ?? "");
    if (!parsed) continue;
    out.push({ ...parsed, filePath: norm(h.filePath), line: h.line ?? 1, signal: (h.text ?? "").trim().slice(0, 140) });
  }
  return out;
}

const OPENAPI_METHODS = new Set(["get", "post", "put", "delete", "patch", "options", "head", "trace"]);

// OpenAPI / Swagger spec files → endpoints. JSON is parsed structurally; YAML uses a
// light paths:-section line scan (no YAML dep). Best-effort — a hint, like the rest.
function openApiRoutes(target) {
  const find = runRg(target, ["--files",
    "-g", "*openapi*.json", "-g", "*openapi*.yaml", "-g", "*openapi*.yml",
    "-g", "*swagger*.json", "-g", "*swagger*.yaml", "-g", "*swagger*.yml",
    "-g", "openapi.*", "-g", "swagger.*", "."]);
  if (!find.ok) return [];
  const files = find.stdout.split(/\r?\n/).filter(Boolean).slice(0, 12);
  const out = [];
  for (const rel of files) {
    const abs = resolve(target, rel);
    if (!existsSync(abs) || statSync(abs).isDirectory()) continue;
    let text;
    try { text = readFileSync(abs, "utf8"); } catch { continue; }
    if (/\.json$/i.test(rel)) {
      try {
        const doc = JSON.parse(text);
        for (const [routePath, ops] of Object.entries(doc?.paths ?? {})) {
          for (const method of Object.keys(ops ?? {})) {
            if (OPENAPI_METHODS.has(method.toLowerCase())) {
              out.push({ framework: "openapi", method: method.toUpperCase(), routePath, filePath: norm(rel), line: 1, signal: `${method.toUpperCase()} ${routePath}` });
            }
          }
        }
      } catch { /* malformed spec — skip */ }
    } else {
      out.push(...yamlPaths(text, norm(rel)));
    }
  }
  return out;
}

// Light OpenAPI YAML extractor: within the top-level `paths:` block, a less-indented
// `"/route":` line opens a path and the `get:`/`post:`/… children are its methods.
function yamlPaths(text, filePath) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let inPaths = false, pathsIndent = -1, curPath = null, curIndent = -1;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\s*#/.test(line) || line.trim() === "") continue;
    const indent = line.match(/^\s*/)[0].length;
    if (!inPaths) {
      if (/^\s*paths\s*:/.test(line)) { inPaths = true; pathsIndent = indent; }
      continue;
    }
    if (indent <= pathsIndent && line.trim() !== "") { break; } // left the paths block
    const pathM = line.match(/^\s*["']?(\/[^"':]*)["']?\s*:/);
    if (pathM && (curIndent === -1 || indent <= curIndent)) {
      curPath = pathM[1]; curIndent = indent; continue;
    }
    const methM = line.match(/^\s*(get|post|put|delete|patch|options|head|trace)\s*:/i);
    if (methM && curPath && indent > curIndent) {
      out.push({ framework: "openapi", method: methM[1].toUpperCase(), routePath: curPath, filePath, line: i + 1, signal: `${methM[1].toUpperCase()} ${curPath}` });
    }
  }
  return out;
}

// All route entry points for the target (code frameworks + OpenAPI), deduped and
// capped. Each: { framework, method, routePath, filePath, line, signal }.
export function extractRoutes(target, { scopeDir = ".", cap = 300 } = {}) {
  const resolvedTarget = resolve(target);
  const all = [...codeRoutes(resolvedTarget, scopeDir), ...openApiRoutes(resolvedTarget)];
  const seen = new Set();
  const out = [];
  for (const r of all) {
    const key = `${r.framework}:${r.method}:${r.routePath}:${r.filePath}:${r.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
    if (out.length >= cap) break;
  }
  return out;
}

// Convenience: the distinct files that declare routes (a ranking signal — these are
// attacker-reachable surface even when no generic entry-def pattern matches them).
export function routeFiles(target, opts = {}) {
  return new Set(extractRoutes(target, opts).map((r) => r.filePath));
}

// HTTP route / endpoint extraction for x-ray entry-point detection.
//
// Entry-point detection was 7 Android/payment-skewed regexes — it missed the
// routing of every mainstream web framework and ignored API specs entirely, so
// source enumeration (which feeds threat-model, taint candidate files, and
// traffic-map) started blind to most handlers on a web app. This adds two things:
//   1. FRAMEWORK_ROUTE_PATTERNS — route-registration shapes across the common
//      web frameworks, so handlers are found as entry points.
//   2. extractOpenApiOperations — parse an OpenAPI/Swagger spec into its declared
//      method+path operations, the authoritative endpoint list when one exists.
// Both are deterministic; the spec parser is dependency-free (JSON natively,
// YAML via a small structural scan).

// Route-registration patterns by framework. Each is a ripgrep regex; the caller
// runs them like the other ENTRY_POINT_PATTERNS. Kept high-signal to limit noise.
export const FRAMEWORK_ROUTE_PATTERNS = [
  {
    id: "express-route",
    // app.get('/x', …)  router.post("/y", …)  (Express / Koa / Fastify / NestJS-ish)
    query: "\\b(app|router|r|fastify|server)\\.(get|post|put|delete|patch|all|use)\\s*\\(\\s*[\"'`]",
    boundary: "Express/Koa/Fastify HTTP route"
  },
  {
    id: "nest-decorator",
    query: "@(Get|Post|Put|Delete|Patch|All|Controller)\\s*\\(",
    boundary: "NestJS controller/route decorator"
  },
  {
    id: "flask-django-route",
    // Flask @app.route / @bp.route, Django path()/re_path()/url()
    query: "@\\w+\\.route\\s*\\(|\\b(path|re_path|url)\\s*\\(\\s*[\"'r]",
    boundary: "Flask/Django URL route"
  },
  {
    id: "fastapi-route",
    query: "@(app|router|api)\\.(get|post|put|delete|patch|websocket)\\s*\\(",
    boundary: "FastAPI route"
  },
  {
    id: "spring-mapping",
    query: "@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\\s*\\(",
    boundary: "Spring MVC request mapping"
  },
  {
    id: "go-http-route",
    query: "\\b(http|mux|r|router|e)\\.(HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH)\\s*\\(",
    boundary: "Go net/http or router route"
  },
  {
    id: "rails-routes",
    // config/routes.rb: get '/x' => ..., resources :things
    query: "\\b(get|post|put|patch|delete|resources?|match)\\s+[\"':]",
    boundary: "Rails route declaration"
  },
  {
    id: "aspnet-route",
    query: "\\[(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\\s*[\\](]",
    boundary: "ASP.NET route attribute"
  }
];

// Filenames that are almost certainly an OpenAPI/Swagger spec.
export const OPENAPI_FILE_GLOBS = [
  "openapi.json", "openapi.yaml", "openapi.yml",
  "swagger.json", "swagger.yaml", "swagger.yml",
  "openapi.*.json", "openapi.*.yaml", "api-docs.json"
];

const HTTP_METHODS = new Set(["get", "post", "put", "delete", "patch", "options", "head", "trace"]);

// Parse an OpenAPI/Swagger document (JSON or YAML text) into a list of
// { method, path } operations. Best-effort: full JSON parse when possible, else a
// small YAML structural scan of the `paths:` block. Returns [] for non-specs.
export function extractOpenApiOperations(text) {
  if (typeof text !== "string" || !text.trim()) return [];

  // JSON path: authoritative when it parses.
  try {
    const doc = JSON.parse(text);
    if (doc && typeof doc === "object" && doc.paths && typeof doc.paths === "object") {
      return operationsFromPathsObject(doc.paths);
    }
    // Parsed but not a spec → nothing to extract.
    return [];
  } catch {
    // Not JSON — fall through to the YAML scan.
  }

  return operationsFromYaml(text);
}

function operationsFromPathsObject(paths) {
  const ops = [];
  for (const [path, item] of Object.entries(paths)) {
    if (!path.startsWith("/") || !item || typeof item !== "object") continue;
    for (const key of Object.keys(item)) {
      if (HTTP_METHODS.has(key.toLowerCase())) ops.push({ method: key.toUpperCase(), path });
    }
  }
  return ops;
}

// Minimal YAML scan: find the top-level `paths:` block, then path keys
// (`  /x/{id}:`) and the method keys under each (`    get:`). Indentation-based,
// tolerant of comments and blank lines; good enough to enumerate endpoints.
function operationsFromYaml(text) {
  const lines = text.split(/\r?\n/);
  const ops = [];
  let inPaths = false;
  let pathsIndent = -1;
  let currentPath = null;
  let pathIndent = -1;

  for (const raw of lines) {
    const line = raw.replace(/#.*$/, "");
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;

    if (!inPaths) {
      if (/^paths\s*:/.test(line.trim()) && indent === 0) { inPaths = true; pathsIndent = indent; }
      continue;
    }
    // A new top-level key at/under the paths indent ends the paths block.
    if (indent <= pathsIndent && !/^paths\s*:/.test(line.trim())) { inPaths = false; continue; }

    const pathMatch = line.trim().match(/^(\/\S*)\s*:/);
    if (pathMatch && (pathIndent === -1 || indent <= pathIndent || currentPath === null)) {
      currentPath = pathMatch[1];
      pathIndent = indent;
      continue;
    }
    if (currentPath) {
      const methodMatch = line.trim().match(/^([a-z]+)\s*:/);
      if (methodMatch && HTTP_METHODS.has(methodMatch[1]) && indent > pathIndent) {
        ops.push({ method: methodMatch[1].toUpperCase(), path: currentPath });
      }
    }
  }
  return ops;
}
