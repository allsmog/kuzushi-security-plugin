// Contract for framework-aware route extraction (L4) and x-ray entry-point detection.
// extractRoutes/routeFiles turn concrete route declarations — across the common web
// frameworks and OpenAPI specs — into structured entry points { framework, method,
// routePath, filePath, line }, so the readers anchor on real handlers instead of a
// hand-written regex's blind spots. FRAMEWORK_ROUTE_PATTERNS / extractOpenApiOperations
// back x-ray's own entry-point detection + spec parsing. Tests needing rg skip if absent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractRoutes, routeFiles, extractOpenApiOperations, FRAMEWORK_ROUTE_PATTERNS } from "../scripts/lib/routes.mjs";
import { ripgrepPath } from "../scripts/lib/ripgrep.mjs";
import { runXray } from "../scripts/cmd/x-ray.mjs";

const rgOk = (() => { try { return spawnSync(ripgrepPath(), ["--version"], { stdio: "ignore" }).status === 0; } catch { return false; } })();
const rgPresent = !spawnSync("rg", ["--version"]).error;

function repo(files) {
  const t = mkdtempSync(join(tmpdir(), "kz-routes-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(t, rel); mkdirSync(join(abs, ".."), { recursive: true }); writeFileSync(abs, body);
  }
  return t;
}
const has = (routes, framework, method, routePath) =>
  routes.some((r) => r.framework === framework && r.method === method && r.routePath === routePath);

test("extractRoutes: Express + FastAPI verb('/path') forms", { skip: !rgOk }, () => {
  const t = repo({
    "src/app.js": "app.get('/users', h);\nrouter.post('/users/:id/pay', pay);\napp.use('/admin', mw);\n",
    "api/main.py": "@router.get('/items')\ndef items(): ...\n@app.delete('/items/{id}')\ndef rm(): ...\n"
  });
  const routes = extractRoutes(t);
  assert.ok(has(routes, "http", "GET", "/users"), "express get");
  assert.ok(has(routes, "http", "POST", "/users/:id/pay"), "express post with params");
  assert.ok(has(routes, "http", "ANY", "/admin"), "app.use → ANY");
  assert.ok(has(routes, "http", "GET", "/items") && has(routes, "http", "DELETE", "/items/{id}"), "fastapi decorators");
});

test("extractRoutes: Flask route with methods, Django path, Spring annotations", { skip: !rgOk }, () => {
  const t = repo({
    "web/views.py": "@app.route('/login', methods=['POST'])\ndef login(): ...\n",
    "web/urls.py": "urlpatterns = [ path('profile/', view), re_path(r'^admin/$', adm) ]\n",
    "src/Ctrl.java": "@PostMapping(\"/transfer\")\npublic void transfer(){}\n@RequestMapping(value=\"/account\")\npublic void acct(){}\n"
  });
  const routes = extractRoutes(t);
  assert.ok(has(routes, "flask", "POST", "/login"), "flask route methods captured");
  assert.ok(has(routes, "django", "ANY", "profile/"), "django path");
  assert.ok(has(routes, "spring", "POST", "/transfer"), "spring @PostMapping");
  assert.ok(has(routes, "spring", "ANY", "/account"), "spring @RequestMapping → ANY");
});

test("extractRoutes: Go net/http handlers", { skip: !rgOk }, () => {
  const t = repo({ "main.go": "mux.HandleFunc(\"/healthz\", health)\nhttp.Handle(\"/metrics\", m)\n" });
  const routes = extractRoutes(t);
  assert.ok(has(routes, "go-http", "ANY", "/healthz"), "go HandleFunc");
  assert.ok(has(routes, "go-http", "ANY", "/metrics"), "go Handle");
});

test("extractRoutes: OpenAPI JSON spec paths × methods", { skip: !rgOk }, () => {
  const spec = JSON.stringify({ openapi: "3.0.0", paths: {
    "/orders": { get: {}, post: {} },
    "/orders/{id}": { delete: {} }
  } });
  const t = repo({ "openapi.json": spec });
  const routes = extractRoutes(t);
  assert.ok(has(routes, "openapi", "GET", "/orders"), "openapi GET /orders");
  assert.ok(has(routes, "openapi", "POST", "/orders"), "openapi POST /orders");
  assert.ok(has(routes, "openapi", "DELETE", "/orders/{id}"), "openapi DELETE with path param");
});

test("extractRoutes: OpenAPI YAML spec paths × methods (light parser)", { skip: !rgOk }, () => {
  const yaml = [
    "openapi: 3.0.0",
    "paths:",
    "  /widgets:",
    "    get:",
    "      summary: list",
    "    post:",
    "      summary: create",
    "  /widgets/{id}:",
    "    delete:",
    "      summary: remove"
  ].join("\n");
  const t = repo({ "swagger.yaml": yaml });
  const routes = extractRoutes(t);
  assert.ok(has(routes, "openapi", "GET", "/widgets"), "yaml GET /widgets");
  assert.ok(has(routes, "openapi", "POST", "/widgets"), "yaml POST /widgets");
  assert.ok(has(routes, "openapi", "DELETE", "/widgets/{id}"), "yaml DELETE /widgets/{id}");
});

test("routeFiles: returns the distinct files that declare routes", { skip: !rgOk }, () => {
  const t = repo({ "a.js": "app.get('/x', h);\n", "b.js": "function noRoutesHere(){}\n" });
  const files = routeFiles(t);
  assert.ok(files.has("a.js"), "route file included");
  assert.ok(!files.has("b.js"), "non-route file excluded");
});

test("extractRoutes: ignores comments / non-routes (no false positives on plain code)", { skip: !rgOk }, () => {
  const t = repo({ "calc.js": "function add(a,b){ return a+b; }\nconst x = get(5);\n" });
  const routes = extractRoutes(t);
  assert.equal(routes.length, 0, "plain helper code yields no routes");
});

test("extracts operations from a JSON OpenAPI spec", () => {
  const spec = JSON.stringify({
    openapi: "3.0.0",
    paths: {
      "/users": { get: {}, post: {} },
      "/users/{id}": { get: {}, delete: {} }
    }
  });
  const ops = extractOpenApiOperations(spec);
  assert.equal(ops.length, 4);
  assert.deepEqual(ops.find((o) => o.path === "/users/{id}" && o.method === "DELETE"), { method: "DELETE", path: "/users/{id}" });
});

test("extracts operations from a YAML OpenAPI spec", () => {
  const yaml = [
    "openapi: 3.0.0",
    "info:",
    "  title: x",
    "paths:",
    "  /login:",
    "    post:",
    "      summary: log in",
    "  /account/{id}:",
    "    get:",
    "      summary: read",
    "    put:",
    "      summary: update",
    "components:",
    "  schemas: {}"
  ].join("\n");
  const ops = extractOpenApiOperations(yaml);
  assert.deepEqual(ops.sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method)), [
    { method: "GET", path: "/account/{id}" },
    { method: "PUT", path: "/account/{id}" },
    { method: "POST", path: "/login" }
  ]);
});

test("non-spec text yields no operations", () => {
  assert.deepEqual(extractOpenApiOperations("just a readme\nwith paths: in prose"), []);
  assert.deepEqual(extractOpenApiOperations(JSON.stringify({ name: "pkg", version: "1.0.0" })), []);
  assert.deepEqual(extractOpenApiOperations(""), []);
});

test("framework route patterns cover the major web frameworks", () => {
  const ids = new Set(FRAMEWORK_ROUTE_PATTERNS.map((p) => p.id));
  for (const id of ["express-route", "flask-django-route", "fastapi-route", "spring-mapping", "go-http-route"]) {
    assert.ok(ids.has(id), `expected a pattern for ${id}`);
  }
});

test("x-ray surfaces framework handlers and OpenAPI endpoints", { skip: rgPresent ? false : "ripgrep not on PATH" }, () => {
  const t = mkdtempSync(join(tmpdir(), "kz-xray-routes-"));
  mkdirSync(join(t, "src"), { recursive: true });
  writeFileSync(join(t, "src", "server.js"),
    "const app = require('express')();\napp.get('/users/:id', (req, res) => res.json({}));\napp.post('/login', (req, res) => res.sendStatus(200));\n");
  writeFileSync(join(t, "openapi.json"), JSON.stringify({ openapi: "3.0.0", paths: { "/health": { get: {} }, "/admin/reset": { post: {} } } }));

  const res = runXray(t, {});
  const kinds = new Set(res.entryPoints.map((e) => e.kind));
  assert.ok(kinds.has("express-route"), "should detect the Express routes");
  assert.ok(kinds.has("openapi-route"), "should detect the OpenAPI endpoints");
  const texts = res.entryPoints.filter((e) => e.kind === "openapi-route").map((e) => e.text);
  assert.ok(texts.includes("POST /admin/reset"), `OpenAPI endpoints surfaced: ${texts.join(", ")}`);
});
