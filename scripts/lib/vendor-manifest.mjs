// Vendor manifest: how each tool is obtained on the current platform/arch.
//
// method:
//   "github-gz"  — download a gzipped single binary, gunzip + chmod
//   "github-zip" — download a zip, extract, pick the binary
//   "tarball"    — download a .tar.gz, extract a tree (jdtls)
//   "npm"        — shipped as an npm dependency (no runtime download)
//   "native"     — no vendorable artifact; run a per-OS installer command
//
// Asset URLs use GitHub's …/releases/latest/download/<asset> for unversioned
// assets; versioned ones (clangd) resolve the latest tag at install time.
//
// sizeClass "heavy" (codeql ~1GB, joern ~2GB) is never auto-installed — it
// requires --include-heavy / --only (the /install path). Everything is
// language-gated by the caller via capabilities.selectCapabilities().

const PLATFORM = process.platform; // darwin | linux | win32
const ARCH = process.arch; // arm64 | x64

export function platformKey() {
  return `${PLATFORM}/${ARCH}`;
}

function rustAnalyzerAsset() {
  if (PLATFORM === "darwin") return ARCH === "arm64" ? "rust-analyzer-aarch64-apple-darwin.gz" : "rust-analyzer-x86_64-apple-darwin.gz";
  if (PLATFORM === "linux") return ARCH === "arm64" ? "rust-analyzer-aarch64-unknown-linux-gnu.gz" : "rust-analyzer-x86_64-unknown-linux-gnu.gz";
  return null;
}

function clangdAssetPrefix() {
  if (PLATFORM === "darwin") return "clangd-mac";
  if (PLATFORM === "linux" && ARCH === "x64") return "clangd-linux";
  return null; // arm64-linux / windows: no prebuilt → native installer
}

function codeqlAsset() {
  if (PLATFORM === "darwin") return "codeql-osx64.zip";
  if (PLATFORM === "linux" && ARCH === "x64") return "codeql-linux64.zip";
  if (PLATFORM === "win32") return "codeql-win64.zip";
  return null;
}

// Per-OS native installer command (string array) for tools with no vendorable
// binary, or for the degraded path (e.g. arm64-linux clangd).
function nativeInstall(tool) {
  const apt = (pkg) => ["sudo", "apt-get", "install", "-y", pkg];
  const brew = (pkg) => ["brew", "install", pkg];
  const map = {
    gopls: { any: ["go", "install", "golang.org/x/tools/gopls@latest"] },
    gtags: { darwin: brew("global"), linux: apt("global") },
    semgrep: { any: ["python3", "-m", "pip", "install", "--user", "semgrep"] },
    clangd: { darwin: brew("llvm"), linux: apt("clangd") },
    z3: { darwin: brew("z3"), linux: apt("z3") },
    crosshair: { any: ["python3", "-m", "pip", "install", "--user", "crosshair-tool"] }
  };
  const entry = map[tool];
  if (!entry) return null;
  return entry.any ?? entry[PLATFORM] ?? null;
}

// Tool descriptors. `languages` mirrors capabilities.mjs so the caller can gate
// by detected languages. `bin` is the wrapper name under bin/ (what configs call).
export const VENDOR_TOOLS = {
  "rust-analyzer": {
    kind: "lsp", method: "github-gz", sizeClass: "light", bin: "rust-analyzer",
    languages: ["Rust"], repo: "rust-lang/rust-analyzer",
    asset: rustAnalyzerAsset(), needsJava: false
  },
  clangd: {
    kind: "lsp", method: "github-zip", sizeClass: "light", bin: "clangd",
    languages: ["C", "C++"], repo: "clangd/clangd",
    assetPrefix: clangdAssetPrefix(), needsJava: false
  },
  jdtls: {
    kind: "lsp", method: "tarball", sizeClass: "light", bin: "jdtls",
    languages: ["Java"], needsJava: true,
    url: "https://download.eclipse.org/jdtls/snapshots/jdt-language-server-latest.tar.gz"
  },
  gopls: {
    kind: "lsp", method: "native", sizeClass: "light", bin: "gopls",
    languages: ["Go"], needsJava: false
  },
  codegraph: {
    kind: "mcp", method: "npm", sizeClass: "light",
    languages: ["JavaScript", "TypeScript", "Python", "Java", "Go"], needsJava: false,
    npm: "@colbymchenry/codegraph"
  },
  semgrep: {
    kind: "mcp", method: "native", sizeClass: "light",
    languages: ["Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go", "Ruby", "C", "C++", "PHP", "Scala"],
    needsJava: false
  },
  gtags: {
    kind: "mcp", method: "native", sizeClass: "light",
    languages: ["C", "C++", "Java", "JavaScript", "Python", "PHP"], needsJava: false
  },
  codeql: {
    kind: "mcp", method: "github-zip", sizeClass: "heavy", bin: "codeql",
    languages: ["Go", "Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Ruby", "C", "C++"],
    repo: "github/codeql-cli-binaries", asset: codeqlAsset(), needsJava: false
  },
  joern: {
    kind: "mcp", method: "github-zip", sizeClass: "heavy", bin: "joern",
    languages: ["C", "C++", "Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go"],
    repo: "joernio/joern", asset: "joern-cli.zip", needsJava: true
  },
  // Optional concolic backends for the kuzushi-concolic MCP server (/path-solve).
  // Small CLIs, but marked opt-in (sizeClass "heavy" is the manifest's "don't
  // auto-install" lever) — installed on demand via /install z3 | /install crosshair.
  z3: {
    kind: "mcp", method: "native", sizeClass: "heavy",
    languages: ["Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go", "Ruby", "C", "C++", "Rust", "PHP", "Scala"],
    needsJava: false
  },
  crosshair: {
    kind: "mcp", method: "native", sizeClass: "heavy",
    languages: ["Python"], needsJava: false
  }
};

// Direct download URL for a github-gz / github-zip tool (or null if no prebuilt
// for this platform → caller falls back to nativeInstall).
export function downloadUrl(tool) {
  const t = VENDOR_TOOLS[tool];
  if (!t) return null;
  if (t.method === "tarball") return t.url;
  if (t.method === "github-gz") return t.asset ? `https://github.com/${t.repo}/releases/latest/download/${t.asset}` : null;
  if (t.method === "github-zip") {
    if (tool === "clangd") return t.assetPrefix ? { repo: t.repo, assetPrefix: t.assetPrefix } : null; // versioned: resolve tag
    return t.asset ? `https://github.com/${t.repo}/releases/latest/download/${t.asset}` : null;
  }
  return null;
}

export function nativeInstallCommand(tool) {
  return nativeInstall(tool);
}
