import { execFileSync } from "node:child_process";
import { hostname, platform, release, arch } from "node:os";
import { dirname, basename, resolve, posix, isAbsolute } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PIN, SOURCE_DIGEST, DESIGN_MANIFEST_DIGEST, ORIGINAL_REVIEW_DIGEST, A1_PATHS, LIMITS, STRUCTURAL_CLEANUP_PROPOSAL, digest, portablePath, manifestDigest, validateEntries, exactNames, assertGitState, dependencyClosure, matchesGlob, captureRoot, assertRoot, readBounded, verifyEntries, inventoryTree, auditCandidate, freeBytesAt, resourcePlan } from "./safe-release-isolation.mjs";

// Read-only executable. Importing this module performs no I/O. No lifecycle or
// copy dispatch exists, including on malformed flags or missing arguments.
const fail = (code) => { throw Error("A1_" + code); };
export function parseArguments(args) {
  if (!Array.isArray(args)) fail("ARGUMENTS");
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (key === "--plan" || key === "--verify") { if (options.mode) fail("MODE"); options.mode = key.slice(2); continue; }
    if (!["--repo", "--baseline", "--original-review", "--review-inputs", "--review-sha256"].includes(key) || !args[i + 1] || args[i + 1].startsWith("--") || options[key]) fail("ARGUMENTS");
    options[key] = args[++i];
  }
  if (!options.mode || ["--repo", "--baseline", "--original-review", "--review-inputs", "--review-sha256"].some((v) => !options[v])) fail("ARGUMENTS");
  for (const key of ["--repo", "--baseline", "--original-review", "--review-inputs"]) if (!isAbsolute(options[key])) fail("ABSOLUTE_ARGUMENT");
  if (!/^[a-f0-9]{64}$/.test(options["--review-sha256"])) fail("REVIEW_DIGEST");
  return options;
}
function readPinned(file, sha256) {
  const capture = captureRoot(dirname(file)), bytes = readBounded(capture, basename(file), undefined, LIMITS.outputBytes).content;
  if (digest(bytes) !== sha256) fail("MANIFEST_DIGEST");
  return JSON.parse(bytes.toString("utf8"));
}
export function parseStatus(buffer) {
  const rows = buffer.toString("utf8").split("\0"); if (rows.pop() !== "") fail("GIT_FORMAT");
  return rows.map((row) => {
    if (!/^(?: M|\?\?) /.test(row)) fail("GIT_STATUS");
    return { status: row.slice(0, 2), path: portablePath(row.slice(3)) };
  });
}
export function collectGit(repo) {
  // Fixed read-only argv, no shell, no hooks/fsmonitor, no optional index writes.
  const env = Object.fromEntries(["PATH", "SystemRoot", "WINDIR"].filter((v) => process.env[v]).map((v) => [v, process.env[v]]));
  env.GIT_OPTIONAL_LOCKS = "0"; env.GIT_CONFIG_NOSYSTEM = "1"; env.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  const git = (...args) => execFileSync("git", ["--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", ...args], { cwd: repo, env, timeout: 5000, maxBuffer: LIMITS.outputBytes, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  const refs = git("rev-parse", "HEAD", "main", "origin/main").toString("utf8").trim().split(/\r?\n/);
  if (refs.length !== 3) fail("GIT_FORMAT");
  const split = (v) => { const list = v.toString("utf8").split("\0"); if (list.pop() !== "") fail("GIT_FORMAT"); return list; };
  return { head: refs[0], main: refs[1], originMain: refs[2], index: split(git("diff", "--cached", "--name-only", "-z")), tracked: split(git("ls-files", "-z")), status: parseStatus(git("status", "--porcelain=v1", "-z", "--untracked-files=all")) };
}

// Source-only parser. Every static edge must resolve inside the unchanged 609;
// runtime-supplied paths are listed separately and cannot authorize execution.
export function analyzeBuildClosure(manifest, contents, ts) {
  const names = manifest.buildInputs.map((v) => v.path), available = new Set(names), edges = [], external = new Set(), dynamic = [];
  const pkg = JSON.parse(contents.get("package.json")), lock = JSON.parse(contents.get("package-lock.json"));
  if (JSON.stringify(lock) !== JSON.stringify(JSON.parse(contents.get("npm-shrinkwrap.json")))) fail("LOCK_MISMATCH");
  function add(from, to, kind) {
    portablePath(to); if (!available.has(to)) fail("CLOSURE_MISSING"); edges.push({ from, to, kind });
  }
  function moduleEdge(from, specifier, kind = "import") {
    if (specifier.startsWith("node:")) return;
    if (!specifier.startsWith(".")) {
      if (specifier.startsWith("/") || specifier.includes(":") || specifier.includes("\\")) fail("CLOSURE_EXTERNAL_PATH");
      const name = specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0];
      if (!lock.packages?.["node_modules/" + name]) { const error = Error("A1_CLOSURE_UNLOCKED_DEPENDENCY"); error.cause = { from, specifier, name }; throw error; } external.add(name); return;
    }
    const target = posix.normalize(posix.join(posix.dirname(from), specifier));
    const candidates = [target, target.replace(/\.js$/, ".ts"), target.replace(/\.js$/, ".tsx"), ...[".ts", ".tsx", ".mjs", ".js", ".json", "/index.ts", "/index.tsx"].map((s) => target + s)];
    const found = [...new Set(candidates)].filter((v) => available.has(v));
    if (found.length !== 1) fail("CLOSURE_MISSING_OR_AMBIGUOUS"); add(from, found[0], kind);
  }
  for (const name of names) {
    const source = contents.get(name); if (typeof source !== "string") fail("CLOSURE_UNREAD_INPUT");
    if (/\.[cm]?[jt]sx?$/.test(name)) {
      const ast = ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true);
      if (ast.parseDiagnostics.length) fail("CLOSURE_PARSE");
      const requireScopes = new Set();
      function collectBindings(node) {
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === "require") {
          let scope = node.parent; while (scope && !ts.isBlock(scope) && !ts.isSourceFile(scope)) scope = scope.parent;
          requireScopes.add(scope);
        }
        ts.forEachChild(node, collectBindings);
      }
      collectBindings(ast);
      function visit(node) {
        if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) moduleEdge(name, node.moduleSpecifier.text);
        if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || node.expression.getText(ast) === "require")) {
          let scope = node.parent, boundRequire = false;
          if (node.expression.getText(ast) === "require") while (scope) { if (requireScopes.has(scope)) boundRequire = true; scope = scope.parent; }
          if (boundRequire) dynamic.push({ from: name, line: ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1, kind: "lexically-bound-require-runtime-contract", dependencyClosure: "HOLD_OWNER_APPLICATION_OR_COMPUTED_MODULE_ROOT" });
          else if (node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) moduleEdge(name, node.arguments[0].text, "dynamic-literal-import");
          else dynamic.push({ from: name, line: ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1, kind: "runtime-module-input" });
        }
        if (ts.isNewExpression(node) && node.expression.getText(ast) === "URL" && node.arguments?.length === 2 && ts.isStringLiteral(node.arguments[0]) && node.arguments[1].getText(ast) === "import.meta.url") {
          const spec = node.arguments[0].text;
          if (spec.startsWith(".")) {
            const target = posix.normalize(posix.join(posix.dirname(name), spec));
            if (available.has(target)) add(name, target, "relative-resource");
            else if (target.endsWith(".js") && available.has(target.replace(/\.js$/, ".ts")) && manifest.compiledCandidate?.some((v) => v.path === target.replace(/^src\//, "dist/"))) moduleEdge(name, spec, "compiled-worker-source");
            else if (target.endsWith("/")) dynamic.push({ from: name, kind: "runtime-directory" });
            else fail("CLOSURE_RESOURCE_MISSING");
          } else if (!/^[a-z]+:/.test(spec)) fail("CLOSURE_RESOURCE_MISSING");
        }
        if (ts.isNewExpression(node) && node.expression.getText(ast) === "URL" && node.arguments?.length === 2 && !ts.isStringLiteral(node.arguments[0]) && node.arguments[1].getText(ast) === "import.meta.url") dynamic.push({ from: name, line: ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1, kind: "computed-relative-resource-runtime-contract" });
        if (ts.isCallExpression(node) && /^(?:readFile|readFileSync|open|openSync|readdir|readdirSync)$/.test(node.expression.getText(ast))) dynamic.push({ from: name, line: ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1, kind: "filesystem-call-reviewed-no-runtime-execution" });
        ts.forEachChild(node, visit);
      }
      visit(ast);
    }
    if (name.endsWith(".css")) for (const match of source.matchAll(/(?:url\(\s*["']?([^\s"')]+)|@import\s+["']([^"']+))/g)) {
      const spec = match[1] || match[2]; if (/^(?:data:|#)/.test(spec)) continue;
      if (/^(?:https?:|\/\/)/.test(spec)) fail("CLOSURE_NETWORK_ASSET");
      add(name, posix.normalize(posix.join(posix.dirname(name), spec)), "css-resource");
    }
  }
  // Original release command topology is explicit, never evaluated as shell.
  const expectedScripts = {
    "prepack": "npm run build:release && npm run package:verify",
    "build:release": "node scripts/prepare-release-build.mjs && npm run standards:check && tsc -p tsconfig.release.json && tsc -p tsconfig.module-sdk.json && node scripts/copy-runtime-assets.mjs && npm run dashboard:typecheck && npm run dashboard:build",
    "standards:check": "tsx scripts/standards-catalog.ts --check && tsx scripts/check-standards-mappings.ts",
    "dashboard:typecheck": "tsc --noEmit -p apps/dashboard-ui/tsconfig.json",
    "dashboard:build": "vite build --config apps/dashboard-ui/vite.config.ts",
    "package:verify": "node scripts/verify-release-inputs.mjs", "package:smoke": "node scripts/package-smoke.mjs"
  };
  for (const [key, text] of Object.entries(expectedScripts)) if (pkg.scripts[key] !== text) fail("CLOSURE_SCRIPT_DRIFT");
  const roots = ["package.json", "package-lock.json", "npm-shrinkwrap.json", ".gitignore", ".gitattributes", "apps/dashboard-ui/index.html", "apps/dashboard-ui/vite.config.ts", "apps/dashboard-ui/tsconfig.json", "tsconfig.json", "tsconfig.release.json", "tsconfig.module-sdk.json", ...["prepare-release-build.mjs", "package-smoke.mjs", "verify-release-inputs.mjs", "copy-runtime-assets.mjs", "standards-catalog.ts", "check-standards-mappings.ts"].map((v) => "scripts/" + v)];
  for (const name of names.filter((v) => /^src\/.*\.ts$/.test(v))) add("tsconfig.json", name, "tsc-include");
  for (const name of names.filter((v) => v.startsWith("apps/dashboard-ui/src/"))) add("apps/dashboard-ui/tsconfig.json", name, "ui-include-including-tests");
  for (const name of ["tsconfig.release.json", "tsconfig.module-sdk.json", "apps/dashboard-ui/tsconfig.json", "tsconfig.json"]) {
    const config = JSON.parse(contents.get(name)); if (config.extends) add(name, posix.normalize(posix.join(posix.dirname(name), config.extends)), "tsconfig-extends");
    for (const type of config.compilerOptions?.types || []) moduleEdge(name, type === "node" || ["react", "react-dom"].includes(type) ? "@types/" + type : type, "tsconfig-type");
  }
  const html = contents.get("apps/dashboard-ui/index.html");
  for (const match of html.matchAll(/(?:src|href)=["']([^"']+)["']/g)) add("apps/dashboard-ui/index.html", posix.normalize("apps/dashboard-ui/" + match[1].replace(/^\//, "")), "html-resource");
  const standards = JSON.parse(contents.get("standards/sources.lock.json")); add("scripts/standards-catalog.ts", "standards/sources.lock.json", "standards-lock");
  for (const source of standards.sources) {
    const name = "standards/sources/" + portablePath(source.file); add("scripts/standards-catalog.ts", name, "standards-resource");
    const entry = manifest.buildInputs.find((v) => v.path === name); if (entry.bytes !== source.bytes || entry.sha256 !== source.sha256) fail("CLOSURE_STANDARDS_DIGEST");
  }
  const assets = ts.createSourceFile("assets.mjs", contents.get("scripts/copy-runtime-assets.mjs"), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const runtimeAssets = [];
  function assetVisit(n) {
    if (ts.isArrayLiteralExpression(n) && n.elements.length === 2 && n.elements.every(ts.isStringLiteral) && n.elements[0].text.startsWith("src/")) { add("scripts/copy-runtime-assets.mjs", n.elements[0].text, "runtime-copy-source"); runtimeAssets.push({ source: n.elements[0].text, destination: n.elements[1].text }); }
    ts.forEachChild(n, assetVisit);
  }
  assetVisit(assets); if (runtimeAssets.length !== 4) fail("CLOSURE_ASSET_DRIFT");
  const generatedDeclarations = [], candidateNames = new Set((manifest.compiledCandidate || []).map((v) => v.path));
  function shippedInput(from, target) {
    if (!candidateNames.has(target)) fail("CLOSURE_SHIPPED_DECLARATION_MISSING");
    let input = target;
    if (target.startsWith("dist/")) input = target.replace(/^dist\//, "src/").replace(/\.d\.ts$/, ".ts").replace(/\.js$/, ".ts");
    else if (target === "apps/dashboard-ui/dist/index.html") input = "apps/dashboard-ui/index.html";
    add(from, input, "shipped-declaration-source"); generatedDeclarations.push({ from, shipped: target, input });
  }
  for (const script of ["scripts/package-smoke.mjs", "scripts/verify-release-inputs.mjs"]) {
    const ast = ts.createSourceFile(script, contents.get(script), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    let declarations = 0;
    function requiredVisit(node) {
      if (ts.isVariableDeclaration(node) && ["required", "requiredFiles"].includes(node.name.getText(ast)) && node.initializer && ts.isArrayLiteralExpression(node.initializer)) {
        if (!node.initializer.elements.every(ts.isStringLiteral)) fail("CLOSURE_COMPUTED_SHIPPED_DECLARATION");
        for (const item of node.initializer.elements) shippedInput(script, item.text); declarations++;
      }
      ts.forEachChild(node, requiredVisit);
    }
    requiredVisit(ast); if (declarations !== 1) fail("CLOSURE_SHIPPED_DECLARATION_DRIFT");
  }
  for (const entry of manifest.compiledCandidate || []) if (entry.path.startsWith("dist/")) shippedInput("package.json", entry.path);
  for (const name of names) if (pkg.files.some((glob) => matchesGlob(name, glob)) || ["README.md", "LICENSE", "package.json"].includes(name)) roots.push(name);
  // Source coverage is finite; filesystem and dynamic imports remain explicit
  // HOLDs instead of inventing a closure proof for installed consumer execution.
  const result = dependencyClosure(names, roots, edges);
  return { ...result, plannedInputs: names.length, edges: edges.sort((a, b) => (a.from + "/" + a.to + "/" + a.kind).localeCompare(b.from + "/" + b.to + "/" + b.kind)), externalLockedPackages: [...external].sort(), runtimeAssets, generatedDeclarations, runtimeReads: dynamic, sourceOnly: true, ownerCopyAuthorized: false };
}

export async function readonlyPreflight(options, adapters = {}) {
  const baseline = readPinned(options["--baseline"], DESIGN_MANIFEST_DIGEST), original = readPinned(options["--original-review"], ORIGINAL_REVIEW_DIGEST), review = readPinned(options["--review-inputs"], options["--review-sha256"]);
  if (baseline.baseline !== PIN || original.frozenParent !== PIN || baseline.sourceFingerprint !== SOURCE_DIGEST || manifestDigest(baseline.sources) !== SOURCE_DIGEST || baseline.sources.length !== 1059 || baseline.buildInputs.length !== 609 || baseline.compiledCandidate.length !== 543 || baseline.generatedSnapshot.length !== 1277) fail("BASELINE");
  if (review.frozenParent !== PIN || review.sourceFingerprint !== SOURCE_DIGEST || review.designManifestSha256 !== DESIGN_MANIFEST_DIGEST || review.originalReviewSha256 !== ORIGINAL_REVIEW_DIGEST) fail("REVIEW_BASELINE");
  const oldNames = Object.keys(original.changedFiles); if (oldNames.length !== 14 || Object.keys(original.originalTests).length !== 235) fail("BASELINE");
  exactNames(Object.keys(review.changedFiles), [...oldNames, ...A1_PATHS]);
  validateEntries(review.changedEntries);
  exactNames(review.changedEntries.map((v) => v.path), [...oldNames, ...A1_PATHS]);
  const reviewedChanges = new Map(review.changedEntries.map((v) => [v.path, v]));
  for (const name of Object.keys(review.changedFiles)) if (reviewedChanges.get(name).sha256 !== review.changedFiles[name]) fail("REVIEW_CHANGE_DIGEST");
  for (const name of oldNames) if (review.changedFiles[name] !== original.changedFiles[name]) fail("D0_DRIFT");
  const originalSources = new Map(baseline.sources.map((v) => [v.path, v]));
  for (const [name, sha] of Object.entries({ ...original.frozenFiles, ...original.changedFiles, ...original.originalTests })) if (originalSources.get(name)?.sha256 !== sha) fail("BASELINE");
  const capture = captureRoot(options["--repo"]), initialGit = (adapters.git || collectGit)(capture.root);
  const modified = new Set(["apps/dashboard-ui/src/main.tsx", "apps/dashboard-ui/src/styles.css"]);
  const changes = [...oldNames, ...A1_PATHS].map((name) => ({ path: name, status: modified.has(name) ? " M" : "??" }));
  const gitProof = assertGitState(initialGit, changes, [...baseline.sources.map((v) => v.path), ...A1_PATHS]);
  const sourceBefore = verifyEntries(capture, baseline.sources);
  const newEntries = A1_PATHS.map((name) => { const file = readBounded(capture, name); if (file.sha256 !== review.changedFiles[name] || file.bytes !== reviewedChanges.get(name).bytes) fail("A1_REVIEW_DRIFT"); return { path: name, sha256: file.sha256, bytes: file.bytes, currentIdentity: file.identity }; });
  const generatedBefore = [...inventoryTree(capture, "dist"), ...inventoryTree(capture, "apps/dashboard-ui/dist")];
  exactNames(generatedBefore.map((v) => v.path), baseline.generatedSnapshot.map((v) => v.path));
  const expectedGenerated = new Map(baseline.generatedSnapshot.map((v) => [v.path, v]));
  for (const entry of generatedBefore) if (entry.sha256 !== expectedGenerated.get(entry.path).sha256 || entry.bytes !== expectedGenerated.get(entry.path).bytes) fail("GENERATED_DRIFT");
  const buildInputs = baseline.buildInputs;
  for (const entry of buildInputs) if (originalSources.get(entry.path)?.sha256 !== entry.sha256 || originalSources.get(entry.path)?.bytes !== entry.bytes) fail("BUILD_INPUT_DRIFT");
  const sourceIdentities = new Map(sourceBefore.map((entry) => [entry.path, entry.currentIdentity]));
  const contents = new Map(buildInputs.map((entry) => [entry.path, readBounded(capture, entry.path, sourceIdentities.get(entry.path)).content.toString("utf8")]));
  const { default: ts } = adapters.typescript ? { default: adapters.typescript } : await import(pathToFileURL(resolve(capture.root, "node_modules/typescript/lib/typescript.js")));
  const closure = analyzeBuildClosure(baseline, contents, ts);
  const candidate = baseline.compiledCandidate.map((entry) => { const file = readBounded(capture, entry.path); if (file.sha256 !== entry.sha256 || file.bytes !== entry.bytes) fail("CANDIDATE_DRIFT"); return file; });
  const candidateProof = auditCandidate(candidate, [...baseline.currentPackageFiles, "package.json"]);
  const resources = resourcePlan({ sourceBytes: validateEntries(buildInputs), dependencyBytes: LIMITS.sourceBytes, freeBytes: freeBytesAt(capture) });
  const sourceAfter = verifyEntries(capture, sourceBefore); verifyEntries(capture, newEntries); const generatedAfter = [...inventoryTree(capture, "dist"), ...inventoryTree(capture, "apps/dashboard-ui/dist")];
  exactNames(generatedAfter.map((v) => v.path), generatedBefore.map((v) => v.path)); verifyEntries(capture, generatedBefore);
  const finalGit = (adapters.git || collectGit)(capture.root); assertGitState(finalGit, changes, [...baseline.sources.map((v) => v.path), ...A1_PATHS]);
  if (JSON.stringify(initialGit) !== JSON.stringify(finalGit)) fail("GIT_CHANGED_DURING_VERIFY"); assertRoot(capture);
  return { schemaVersion: 1, status: "HOLD_WITH_BLOCKER", mode: options.mode, machine: { platform: platform(), release: release(), arch: arch(), node: process.version, abi: process.versions.modules, machineSha256: digest(hostname()) }, frozenParent: PIN, sourceFingerprint: manifestDigest(sourceAfter), reviewInputsSha256: options["--review-sha256"], counts: { originalSource: sourceAfter.length, originalTests: 235, originalD0: 14, a1: 4, generated: generatedAfter.length, plannedInputs: 609, candidate: candidate.length }, git: gitProof, closure, candidate: candidateProof, resources, cleanupPolicyProposal: STRUCTURAL_CLEANUP_PROPOSAL, unchanged: true, readonly: true, materialized: 0, install: false, npm: false, releaseBuild: false, network: false, productionExecution: false, independentSignature: false, holds: ["REAL_OWNER_COPY_NOT_IMPLEMENTED_OR_AUTHORIZED", "NATIVE_CUSTODY_AND_TOCTOU_PROOF", "REAL_TREE_GLOBAL_CLEANUP_POLICY_REQUIRES_REVIEW", "DYNAMIC_RUNTIME_AND_INSTALLED_CONSUMER_CLOSURE", "LIVE_REMOTE_NOT_QUERIED_IN_READONLY_MODE", "DEPENDENCY_HEADROOM_ESTIMATE_REQUIRES_REVIEW", "NATIVE_WINDOWS_LINK_CAPABILITIES", "LINUX", "PACKAGE_SMOKE_AND_INTERNAL_EXECUTEFRESH_CONFLICT", "D1", "D2", "D3", "D4"] };
}
export async function main(args) {
  try {
    const result = await readonlyPreflight(parseArguments(args)); const text = JSON.stringify(result) + "\n";
    if (Buffer.byteLength(text) > LIMITS.outputBytes) fail("OUTPUT_CAP"); process.stdout.write(text); return 2;
  } catch (error) {
    // Native errors may contain private paths, config or credential-bearing URLs.
    const code = /^A1_[A-Z_]+$/.test(error.message) ? error.message : "A1_NATIVE_OR_PARSE_FAILURE";
    process.stderr.write(JSON.stringify({ schemaVersion: 1, status: "FAIL", reason: code, readonly: true, materialized: 0 }) + "\n"); return 1;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main(process.argv.slice(2));
