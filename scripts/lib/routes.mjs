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
