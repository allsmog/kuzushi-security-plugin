#!/usr/bin/env node
// Native tree-sitter MCP server. Uses web-tree-sitter (WASM) so the plugin
// doesn't need node-gyp / per-platform native bindings. Grammars come from the
// bundled tree-sitter-wasms package (java, kotlin, ruby, js, ts, python, c,
// cpp, rust, go, php, scala, …).
//
// SELF-GATING: this is the reference "conditional MCP" server. Claude Code can't
// conditionally *start* MCP servers, so instead this server always connects and
// keeps all tools listed (a server that exposes no tools is flagged in /mcp),
// but gates each tool *at call time* by the languages detected for the project
// (from .kuzushi context). A request for a language the repo doesn't contain
// returns a structured "skipped" result instead of parsing. The project root is
// taken from CLAUDE_PROJECT_DIR (set by Claude Code in every stdio MCP server's
// environment), falling back to process.cwd().
//
// Tools:
//   tree_sitter:languages      report detected languages + available grammars
//   tree_sitter:node_at        smallest enclosing node at a (line, column)
//   tree_sitter:query          run an S-expression query over a file
//   tree_sitter:callers        intra-file call sites for a function name
//   tree_sitter:taint_sources  candidate taint sources (evidence only)
//   tree_sitter:taint_sinks    candidate taint sinks (evidence only)

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));

if (process.argv.includes("--help")) {
  console.log("tree-sitter MCP server (self-gating). Tools: tree_sitter:languages, :node_at, :query, :callers, :taint_sources, :taint_sinks.");
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Grammar discovery + language resolution
// ---------------------------------------------------------------------------

function findGrammarDir() {
  try {
    const pkgPath = require.resolve("tree-sitter-wasms/package.json");
    return resolve(dirname(pkgPath), "out");
  } catch {
    return null;
  }
}

const GRAMMAR_DIR = findGrammarDir();

const LANGUAGE_ALIASES = {
  java: "java", kotlin: "kotlin", kt: "kotlin", ruby: "ruby", rb: "ruby",
  javascript: "javascript", js: "javascript", typescript: "typescript", ts: "typescript",
  python: "python", py: "python", c: "c", cpp: "cpp", "c++": "cpp", h: "c", hpp: "cpp",
  rust: "rust", rs: "rust", go: "go", php: "php", scala: "scala",
  bash: "bash", sh: "bash", json: "json", html: "html", css: "css"
};

const FILE_EXT_TO_LANGUAGE = [
  [".java", "java"], [".kt", "kotlin"], [".kts", "kotlin"], [".rb", "ruby"], [".erb", "ruby"],
  [".js", "javascript"], [".jsx", "javascript"], [".mjs", "javascript"], [".cjs", "javascript"],
  [".ts", "typescript"], [".tsx", "typescript"], [".py", "python"], [".rs", "rust"],
  [".go", "go"], [".php", "php"], [".scala", "scala"], [".c", "c"], [".h", "c"],
  [".cc", "cpp"], [".cpp", "cpp"], [".hpp", "cpp"]
];

// context-build's inventory.byLanguage uses display names; map them to grammars.
const CONTEXT_LANG_TO_GRAMMAR = {
  Java: "java", Kotlin: "kotlin", Ruby: "ruby", Python: "python",
  JavaScript: "javascript", TypeScript: "typescript", C: "c", "C++": "cpp",
  Rust: "rust", Go: "go", PHP: "php", Scala: "scala"
};

function languageFromFile(path) {
  if (!path) return null;
  const lower = path.toLowerCase();
  for (const [ext, lang] of FILE_EXT_TO_LANGUAGE) {
    if (lower.endsWith(ext)) return lang;
  }
  return null;
}

function resolveLanguage(input) {
  if (!input) return null;
  return LANGUAGE_ALIASES[input.toLowerCase()] ?? null;
}

// ---------------------------------------------------------------------------
// Self-gating: detected languages for the project (from .kuzushi context)
// ---------------------------------------------------------------------------

function projectRoot() {
  return process.env.CLAUDE_PROJECT_DIR || process.cwd();
}

// Returns a Set of detected grammar names, or null when we can't tell (no
// context yet, or only "Other" was detected) — null means "don't gate".
function detectedGrammars() {
  const runsDir = resolve(projectRoot(), ".kuzushi", "runs");
  if (!existsSync(runsDir)) return null;
  let latest = null;
  try {
    for (const entry of readdirSync(runsDir, { withFileTypes: true })) {
      if (!entry.isDirectory() || !entry.name.startsWith("host-context-")) continue;
      const ctx = resolve(runsDir, entry.name, "context.json");
      if (!existsSync(ctx)) continue;
      const mtime = statSync(ctx).mtime;
      if (!latest || mtime > latest.mtime) latest = { ctx, mtime };
    }
  } catch {
    return null;
  }
  if (!latest) return null;
  let byLanguage;
  try {
    byLanguage = JSON.parse(readFileSync(latest.ctx, "utf8"))?.inventory?.byLanguage ?? {};
  } catch {
    return null;
  }
  const set = new Set();
  for (const [lang, count] of Object.entries(byLanguage)) {
    if (lang === "Other" || !(Number(count) > 0)) continue;
    const grammar = CONTEXT_LANG_TO_GRAMMAR[lang];
    if (grammar) set.add(grammar);
  }
  return set.size > 0 ? set : null;
}

// If the project has a known language set and `lang` isn't in it, return a
// skip result; otherwise null (allowed). Computed per call so a context built
// after server start is picked up without a restart.
function gateLanguage(lang) {
  const detected = detectedGrammars();
  if (!detected || detected.has(lang)) return null;
  return {
    ok: false,
    skipped: `language "${lang}" not detected in this repository`,
    detectedLanguages: [...detected]
  };
}

function availableGrammars() {
  if (!GRAMMAR_DIR || !existsSync(GRAMMAR_DIR)) return [];
  try {
    return readdirSync(GRAMMAR_DIR)
      .filter((f) => f.startsWith("tree-sitter-") && f.endsWith(".wasm"))
      .map((f) => f.slice("tree-sitter-".length, -".wasm".length))
      .sort();
  } catch {
    return [];
  }
}

function languagesReport() {
  const detected = detectedGrammars();
  return {
    ok: true,
    projectRoot: projectRoot(),
    detectedLanguages: detected ? [...detected] : [],
    gating: Boolean(detected),
    availableGrammars: availableGrammars(),
    note: detected
      ? "Tools are gated to the detected languages; other languages return a 'skipped' result."
      : "No detected-language context found — tools are ungated (run kuzushi context first to enable gating)."
  };
}

// ---------------------------------------------------------------------------
// Parser / language lazy loading
// ---------------------------------------------------------------------------

let cachedParser;
const languageCache = new Map();

async function getParser() {
  if (cachedParser) return cachedParser;
  const mod = await import("web-tree-sitter");
  const Parser = mod.default ?? mod.Parser ?? mod["module.exports"];
  await Parser.init();
  cachedParser = Parser;
  return Parser;
}

async function loadLanguage(name) {
  if (!GRAMMAR_DIR) {
    throw new Error("tree-sitter-wasms not installed — run npm install in the plugin root");
  }
  const cached = languageCache.get(name);
  if (cached) return cached;
  const wasmPath = resolve(GRAMMAR_DIR, `tree-sitter-${name}.wasm`);
  if (!existsSync(wasmPath)) {
    throw new Error(`Grammar not found for language "${name}" at ${wasmPath}`);
  }
  const Parser = await getParser();
  const lang = await Parser.Language.load(wasmPath);
  languageCache.set(name, lang);
  return lang;
}

async function parseFile(filePath, languageName) {
  if (!existsSync(filePath)) throw new Error(`file not found: ${filePath}`);
  const lang = await loadLanguage(languageName);
  const Parser = await getParser();
  const parser = new Parser();
  parser.setLanguage(lang);
  const source = readFileSync(filePath, "utf8");
  return { tree: parser.parse(source), source };
}

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

function describeNode(node) {
  return {
    type: node.type,
    startLine: node.startPosition.row + 1,
    startColumn: node.startPosition.column,
    endLine: node.endPosition.row + 1,
    endColumn: node.endPosition.column
  };
}

function nodeChain(node) {
  const chain = [];
  let cursor = node;
  while (cursor) {
    chain.push(describeNode(cursor));
    cursor = cursor.parent;
  }
  return chain;
}

function truncateText(text) {
  if (text == null) return "";
  return text.length > 600 ? `${text.slice(0, 600)}…` : text;
}

// ---------------------------------------------------------------------------
// Tool implementations (each gates on detected languages first)
// ---------------------------------------------------------------------------

async function nodeAt({ file, line, column = 0, language }) {
  const absPath = resolve(file);
  const lang = language ? resolveLanguage(language) : languageFromFile(absPath);
  if (!lang) {
    throw new Error(`Unable to resolve language for ${file}; pass language="java"|"ruby"|... explicitly`);
  }
  const gate = gateLanguage(lang);
  if (gate) return { ...gate, file };

  const { tree, source } = await parseFile(absPath, lang);
  const targetLine = Math.max(0, Number(line) - 1);
  const targetColumn = Math.max(0, Number(column));
  const node = tree.rootNode.descendantForPosition({ row: targetLine, column: targetColumn });
  if (!node) {
    return { ok: false, file, line, column, language: lang, reason: "no node at position" };
  }
  const sourceLines = source.split(/\r?\n/);
  const surroundingStart = Math.max(0, node.startPosition.row - 1);
  const surroundingEnd = Math.min(sourceLines.length, node.endPosition.row + 2);
  return {
    ok: true,
    file,
    line,
    column,
    language: lang,
    node: { ...describeNode(node), text: truncateText(node.text) },
    parents: nodeChain(node.parent).slice(0, 8),
    surroundingLines: sourceLines.slice(surroundingStart, surroundingEnd)
  };
}

async function runQuery({ file, language, query: queryText, limit = 200 }) {
  const absPath = resolve(file);
  const lang = language ? resolveLanguage(language) : languageFromFile(absPath);
  if (!lang) throw new Error(`Unable to resolve language for ${file}`);
  const gate = gateLanguage(lang);
  if (gate) return { ...gate, file };

  const langObj = await loadLanguage(lang);
  const { tree } = await parseFile(absPath, lang);
  const captures = langObj.query(queryText).captures(tree.rootNode).slice(0, limit);
  return {
    ok: true,
    file,
    language: lang,
    matchCount: captures.length,
    captures: captures.map((capture) => ({
      name: capture.name,
      ...describeNode(capture.node),
      text: truncateText(capture.node.text)
    }))
  };
}

const TAINT_SOURCE_QUERIES = {
  javascript: `
    (member_expression object: (identifier) @obj (#match? @obj "^(req|request|ctx)$") property: (property_identifier) @prop (#match? @prop "^(body|query|params|cookies|headers|url|originalUrl)$")) @source
    (member_expression object: (member_expression) @nested property: (property_identifier) @prop (#match? @prop "^(body|query|params|cookies|headers)$")) @source
    (call_expression function: (member_expression object: (identifier) @obj (#eq? @obj "process") property: (property_identifier) @prop (#match? @prop "^(argv|env)$"))) @source
  `,
  typescript: `
    (member_expression object: (identifier) @obj (#match? @obj "^(req|request|ctx)$") property: (property_identifier) @prop (#match? @prop "^(body|query|params|cookies|headers|url|originalUrl)$")) @source
    (member_expression object: (member_expression) @nested property: (property_identifier) @prop (#match? @prop "^(body|query|params|cookies|headers)$")) @source
  `,
  python: `
    (attribute object: (identifier) @obj (#match? @obj "^(request|flask\\\\.request|self)$") attribute: (identifier) @attr (#match? @attr "^(args|form|json|values|cookies|headers|data|files|GET|POST)$")) @source
    (call function: (attribute object: (identifier) @obj (#eq? @obj "os") attribute: (identifier) @attr (#match? @attr "^(getenv|environ)$"))) @source
    (subscript value: (attribute object: (identifier) @obj (#eq? @obj "os") attribute: (identifier) @attr (#eq? @attr "environ"))) @source
  `,
  go: `
    (selector_expression operand: (identifier) @obj (#match? @obj "^(r|req|c)$") field: (field_identifier) @field (#match? @field "^(URL|Header|Body|Form|PostForm|Cookies)$")) @source
    (call_expression function: (selector_expression operand: (identifier) @obj (#eq? @obj "os") field: (field_identifier) @field (#eq? @field "Getenv"))) @source
  `,
  ruby: `
    (call method: (identifier) @m (#match? @m "^(params|request|ENV)$")) @source
  `,
  java: `
    (method_invocation object: (identifier) @obj (#eq? @obj "request") name: (identifier) @method (#match? @method "^(getParameter|getQueryString|getHeader|getCookies)$")) @source
  `
};

const TAINT_SINK_QUERIES = {
  javascript: `
    (call_expression function: (identifier) @fn (#match? @fn "^(eval|Function|exec|execSync|spawn|spawnSync|fetch|require)$")) @sink
    (call_expression function: (member_expression object: (identifier) @obj (#match? @obj "^(child_process|cp|vm)$") property: (property_identifier) @prop (#match? @prop "^(exec|execSync|spawn|spawnSync|runInContext|runInNewContext|runInThisContext|compileFunction)$"))) @sink
    (call_expression function: (member_expression object: (identifier) @obj (#match? @obj "^(fs|fsp|fsPromises)$") property: (property_identifier) @prop (#match? @prop "^(readFile|writeFile|appendFile|unlink|createReadStream|createWriteStream|open)$"))) @sink
    (call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @prop (#match? @prop "^(query|exec|raw|execute|run)$"))) @sink
    (assignment_expression left: (member_expression property: (property_identifier) @prop (#match? @prop "^(innerHTML|outerHTML)$"))) @sink
    (call_expression function: (member_expression object: (identifier) @obj (#match? @obj "^(res|response)$") property: (property_identifier) @prop (#match? @prop "^(send|render|redirect)$"))) @sink
  `,
  typescript: `
    (call_expression function: (identifier) @fn (#match? @fn "^(eval|Function|exec|execSync|spawn|spawnSync|fetch|require)$")) @sink
    (call_expression function: (member_expression object: (identifier) @obj (#match? @obj "^(child_process|cp|vm)$") property: (property_identifier) @prop (#match? @prop "^(exec|execSync|spawn|spawnSync|runInContext|runInNewContext)$"))) @sink
    (call_expression function: (member_expression object: (identifier) @obj (#match? @obj "^(fs|fsp|fsPromises)$") property: (property_identifier) @prop (#match? @prop "^(readFile|writeFile|appendFile|unlink|createReadStream|createWriteStream|open)$"))) @sink
    (call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @prop (#match? @prop "^(query|exec|raw|execute|run)$"))) @sink
    (assignment_expression left: (member_expression property: (property_identifier) @prop (#match? @prop "^(innerHTML|outerHTML)$"))) @sink
  `,
  python: `
    (call function: (identifier) @fn (#match? @fn "^(eval|exec|compile)$")) @sink
    (call function: (attribute object: (identifier) @obj (#eq? @obj "os") attribute: (identifier) @attr (#match? @attr "^(system|popen)$"))) @sink
    (call function: (attribute object: (identifier) @obj (#match? @obj "^(subprocess)$") attribute: (identifier) @attr (#match? @attr "^(run|call|check_call|check_output|Popen)$"))) @sink
    (call function: (attribute object: (identifier) @obj (#match? @obj "^(pickle|joblib|torch)$") attribute: (identifier) @attr (#match? @attr "^(load|loads)$"))) @sink
  `,
  go: `
    (call_expression function: (selector_expression operand: (identifier) @obj (#eq? @obj "exec") field: (field_identifier) @field (#match? @field "^(Command|CommandContext)$"))) @sink
    (call_expression function: (selector_expression operand: (identifier) @obj (#eq? @obj "os") field: (field_identifier) @field (#match? @field "^(Open|Create|Remove|ReadFile|WriteFile)$"))) @sink
  `,
  ruby: `
    (call method: (identifier) @m (#match? @m "^(eval|system|exec|\\\`|popen|send)$")) @sink
  `,
  java: `
    (method_invocation object: (identifier) @obj (#match? @obj "^(Runtime|ProcessBuilder)$") name: (identifier) @method) @sink
  `
};

async function findTaintSources({ file, language, limit = 200 }) {
  const absPath = resolve(file);
  const lang = language ? resolveLanguage(language) : languageFromFile(absPath);
  if (!lang) throw new Error(`Unable to resolve language for ${file}`);
  const gate = gateLanguage(lang);
  if (gate) return { ...gate, file };
  const queryText = TAINT_SOURCE_QUERIES[lang];
  if (!queryText) {
    return { ok: false, file, language: lang, reason: `taint-sources query not defined for language "${lang}"` };
  }
  const result = await runQuery({ file: absPath, language: lang, query: queryText, limit });
  if (!result.ok) return result;
  const sources = result.captures.filter((c) => c.name === "source");
  return { ok: true, file, language: lang, kind: "taint-source", count: sources.length, captures: sources };
}

async function findTaintSinks({ file, language, limit = 200 }) {
  const absPath = resolve(file);
  const lang = language ? resolveLanguage(language) : languageFromFile(absPath);
  if (!lang) throw new Error(`Unable to resolve language for ${file}`);
  const gate = gateLanguage(lang);
  if (gate) return { ...gate, file };
  const queryText = TAINT_SINK_QUERIES[lang];
  if (!queryText) {
    return { ok: false, file, language: lang, reason: `taint-sinks query not defined for language "${lang}"` };
  }
  const result = await runQuery({ file: absPath, language: lang, query: queryText, limit });
  if (!result.ok) return result;
  const sinks = result.captures.filter((c) => c.name === "sink");
  return { ok: true, file, language: lang, kind: "taint-sink", count: sinks.length, captures: sinks };
}

const CALLER_QUERIES = {
  javascript: `(call_expression function: (identifier) @callee) (call_expression function: (member_expression property: (property_identifier) @callee))`,
  typescript: `(call_expression function: (identifier) @callee) (call_expression function: (member_expression property: (property_identifier) @callee))`,
  python: `(call function: (identifier) @callee) (call function: (attribute attribute: (identifier) @callee))`,
  ruby: `(call method: (identifier) @callee) (method_call method: (identifier) @callee)`,
  java: `(method_invocation name: (identifier) @callee)`,
  kotlin: `(call_expression (simple_identifier) @callee)`,
  c: `(call_expression function: (identifier) @callee)`,
  cpp: `(call_expression function: (identifier) @callee) (call_expression function: (field_expression field: (field_identifier) @callee))`,
  rust: `(call_expression function: (path_expression) @callee) (call_expression function: (identifier) @callee)`,
  go: `(call_expression function: (identifier) @callee) (call_expression function: (selector_expression field: (field_identifier) @callee))`,
  php: `(function_call_expression function: (name) @callee) (member_call_expression name: (name) @callee)`
};

async function findCallers({ file, language, function: functionName, limit = 50 }) {
  if (!functionName) throw new Error("function name is required");
  const absPath = resolve(file);
  const lang = language ? resolveLanguage(language) : languageFromFile(absPath);
  if (!lang) throw new Error(`Unable to resolve language for ${file}`);
  const gate = gateLanguage(lang);
  if (gate) return { ...gate, file };
  const queryText = CALLER_QUERIES[lang];
  if (!queryText) {
    return { ok: false, file, language: lang, reason: `callers query not yet defined for language "${lang}"` };
  }
  const result = await runQuery({ file: absPath, language: lang, query: queryText, limit: limit * 3 });
  if (!result.ok) return result;
  const matches = result.captures.filter((capture) => capture.text === functionName).slice(0, limit);
  return { ok: true, file, language: lang, function: functionName, callCount: matches.length, callers: matches };
}

// ---------------------------------------------------------------------------
// MCP server wiring
// ---------------------------------------------------------------------------

function asTextResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function main() {
  const server = new McpServer(
    { name: "kuzushi-tree-sitter", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "tree_sitter_languages",
    {
      title: "tree_sitter:languages",
      description: "Report the languages detected for this repository (from kuzushi context), whether tool gating is active, and the available WASM grammars.",
      inputSchema: {}
    },
    async () => asTextResult(languagesReport())
  );

  server.registerTool(
    "tree_sitter_node_at",
    {
      title: "tree_sitter:node_at",
      description: "Return the smallest tree-sitter node enclosing a given (line, column) in a file, plus its parent chain. Gated to detected languages.",
      inputSchema: {
        file: z.string().describe("Absolute or relative path to a source file"),
        line: z.number().int().describe("1-indexed line number"),
        column: z.number().int().optional().describe("0-indexed column"),
        language: z.string().optional().describe("Override language detection (java, ruby, javascript, ...)")
      }
    },
    async (args) => asTextResult(await nodeAt(args))
  );

  server.registerTool(
    "tree_sitter_query",
    {
      title: "tree_sitter:query",
      description: "Run a tree-sitter S-expression query against a file and return all captures. Gated to detected languages.",
      inputSchema: {
        file: z.string(),
        query: z.string(),
        language: z.string().optional(),
        limit: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await runQuery(args))
  );

  server.registerTool(
    "tree_sitter_callers",
    {
      title: "tree_sitter:callers",
      description: "Find intra-file call sites for a named function or method, scoped to a single source file. Gated to detected languages.",
      inputSchema: {
        file: z.string(),
        function: z.string(),
        language: z.string().optional(),
        limit: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await findCallers(args))
  );

  server.registerTool(
    "tree_sitter_taint_sources",
    {
      title: "tree_sitter:taint_sources",
      description: "Find candidate taint sources (req.body, req.query, request.args, process.env, os.environ, etc.) in a single file. Evidence only. Gated to detected languages.",
      inputSchema: {
        file: z.string(),
        language: z.string().optional(),
        limit: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await findTaintSources(args))
  );

  server.registerTool(
    "tree_sitter_taint_sinks",
    {
      title: "tree_sitter:taint_sinks",
      description: "Find candidate taint sinks (eval, child_process.exec, vm.runInContext, pickle.load, os.system, subprocess, exec.Command, innerHTML assignments, etc.) in a single file. Evidence only. Gated to detected languages.",
      inputSchema: {
        file: z.string(),
        language: z.string().optional(),
        limit: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await findTaintSinks(args))
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error(`tree-sitter MCP server failed: ${error.stack ?? error.message}`);
  process.exit(1);
});
