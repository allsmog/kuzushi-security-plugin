// Route extraction widens x-ray entry-point detection beyond the original
// Android/payment regexes to web frameworks + OpenAPI specs. These pin the spec
// parser (JSON and YAML) and an end-to-end x-ray run that should now surface both
// framework handlers and declared API endpoints.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractOpenApiOperations, FRAMEWORK_ROUTE_PATTERNS } from "../scripts/lib/routes.mjs";
import { runXray } from "../scripts/cmd/x-ray.mjs";

const rgPresent = !spawnSync("rg", ["--version"]).error;

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
