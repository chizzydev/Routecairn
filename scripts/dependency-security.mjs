import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const severityOrder = ["info", "low", "moderate", "high", "critical"];
const [command, ...argumentsList] = process.argv.slice(2);

if (command === "audit") audit(argumentsList);
else if (command === "sbom") sbom(argumentsList);
else fail("Usage: node scripts/dependency-security.mjs <audit|sbom> [options]");

function audit(args) {
  validateOptions(args, new Set(["--level", "--output"]));
  const level = option(args, "--level") ?? process.env.ROUTECAIRN_AUDIT_LEVEL ?? "moderate";
  const output = option(args, "--output");
  if (!severityOrder.includes(level)) fail(`Unsupported audit level: ${level}`);
  const result = npm(["audit", "--json", `--audit-level=${level}`]);
  const report = parseJson(result.stdout, "npm audit");
  if (output) atomicJson(resolve(output), report);
  const counts = report?.metadata?.vulnerabilities;
  if (!counts || severityOrder.some((severity) => !Number.isInteger(counts[severity]))) fail("npm audit returned an invalid vulnerability summary.");
  const threshold = severityOrder.indexOf(level);
  const actionable = severityOrder.slice(threshold).reduce((total, severity) => total + counts[severity], 0);
  process.stdout.write(`Dependency audit: ${counts.total} total; ${actionable} at ${level} or higher.\n`);
  if (actionable > 0 || (result.status !== 0 && counts.total === 0)) process.exitCode = 1;
}

function sbom(args) {
  validateOptions(args, new Set(["--output-dir"]));
  const outputDirectory = resolve(option(args, "--output-dir") ?? ".routecairn-security");
  const packageManifest = parseJson(readFileSync(resolve("package.json"), "utf8"), "package.json");
  const version = safeSegment(packageManifest.version ?? "unknown");
  const generated = [
    generateSbom(["sbom", "--sbom-format", "cyclonedx"], resolve(outputDirectory, `routecairn-${version}-full.cdx.json`), "full", packageManifest),
    generateSbom(["sbom", "--sbom-format", "cyclonedx", "--omit=dev"], resolve(outputDirectory, `routecairn-${version}-runtime.cdx.json`), "runtime", packageManifest)
  ];
  const checksums = generated.map((item) => `${item.digest}  ${item.filename}`).join("\n") + "\n";
  atomicText(resolve(outputDirectory, "SHA256SUMS"), checksums);
  atomicJson(resolve(outputDirectory, "dependency-security-manifest.json"), {
    schemaVersion: 1,
    package: { name: packageManifest.name, version: packageManifest.version },
    generatedAt: new Date().toISOString(),
    generator: `npm/${npm(["--version"]).stdout.trim()}`,
    artifacts: generated
  });
  process.stdout.write(`Generated ${generated.length} validated CycloneDX SBOMs in ${outputDirectory}.\n`);
}

function generateSbom(npmArguments, outputPath, scope, packageManifest) {
  const result = npm(npmArguments);
  if (result.status !== 0) fail(commandFailure(result, `npm ${npmArguments.join(" ")} failed.`));
  const document = parseJson(result.stdout, `${scope} SBOM`);
  canonicalizeRootComponent(document, packageManifest);
  validateSbom(document, scope, packageManifest);
  const serialized = `${JSON.stringify(document, null, 2)}\n`;
  atomicText(outputPath, serialized);
  return {
    scope,
    filename: outputPath.split(/[\\/]/).at(-1),
    format: "CycloneDX",
    specVersion: document.specVersion,
    componentCount: document.components.length,
    digest: createHash("sha256").update(serialized).digest("hex")
  };
}

function canonicalizeRootComponent(document, packageManifest) {
  const root = document?.metadata?.component;
  const name = String(packageManifest.name ?? "");
  const version = String(packageManifest.version ?? "");
  if (!root || root.version !== version || !name || !version) return;
  let decodedPurl = "";
  try { decodedPurl = decodeURIComponent(String(root.purl ?? "")); } catch { decodedPurl = ""; }
  const packageIdentity = `${name}@${version}`;
  if (root["bom-ref"] === packageIdentity || decodedPurl === `pkg:npm/${packageIdentity}`) root.name = name;
}

function validateSbom(document, scope, packageManifest) {
  if (document?.bomFormat !== "CycloneDX" || typeof document.specVersion !== "string") fail(`${scope} SBOM is not a CycloneDX document.`);
  if (!Array.isArray(document.components) || document.components.length === 0) fail(`${scope} SBOM contains no components.`);
  const root = document.metadata?.component;
  if (typeof root?.name !== "string" || root.name.toLowerCase() !== String(packageManifest.name).toLowerCase() || root.version !== packageManifest.version) fail(`${scope} SBOM root component does not match package.json.`);
  if (typeof root["bom-ref"] !== "string") fail(`${scope} SBOM root component has no component reference.`);
  const references = new Set([root["bom-ref"]]);
  for (const component of document.components) {
    if (typeof component.name !== "string" || typeof component.version !== "string" || typeof component["bom-ref"] !== "string") fail(`${scope} SBOM contains an incomplete component.`);
    if (references.has(component["bom-ref"])) fail(`${scope} SBOM contains a duplicate component reference.`);
    if (scope === "runtime" && component.properties?.some((property) => property?.name === "cdx:npm:package:development" && property.value === "true")) fail("runtime SBOM contains a development-only component.");
    references.add(component["bom-ref"]);
  }
  if (!Array.isArray(document.dependencies) || document.dependencies.length === 0) fail(`${scope} SBOM contains no dependency graph.`);
  const graphReferences = new Set();
  for (const dependency of document.dependencies) {
    if (typeof dependency?.ref !== "string" || !references.has(dependency.ref) || !Array.isArray(dependency.dependsOn)) fail(`${scope} SBOM dependency graph contains an unknown component.`);
    if (graphReferences.has(dependency.ref)) fail(`${scope} SBOM dependency graph contains a duplicate component.`);
    if (dependency.dependsOn.some((reference) => typeof reference !== "string" || !references.has(reference))) fail(`${scope} SBOM dependency graph contains an unknown edge.`);
    graphReferences.add(dependency.ref);
  }
  if (!graphReferences.has(root["bom-ref"]) || document.components.some((component) => !graphReferences.has(component["bom-ref"]))) fail(`${scope} SBOM dependency graph is incomplete.`);
}

function npm(args) {
  const environment = { ...process.env, npm_config_fund: "false", npm_config_update_notifier: "false" };
  const configuredCli = process.env.npm_execpath;
  if (configuredCli && existsSync(configuredCli)) return spawnSync(process.execPath, [configuredCli, ...args], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, env: environment });
  const adjacentCli = resolve(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  if (existsSync(adjacentCli)) return spawnSync(process.execPath, [adjacentCli, ...args], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, env: environment });
  return spawnSync("npm", args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, env: environment });
}

function commandFailure(result, fallback) { return [result.error?.message, result.stderr?.trim(), fallback].find(Boolean); }
function validateOptions(args, allowed) { const seen = new Set(); for (let index = 0; index < args.length; index += 2) { const name = args[index]; const value = args[index + 1]; if (!allowed.has(name)) fail(`Unsupported option: ${name ?? "<empty>"}`); if (seen.has(name)) fail(`Duplicate option: ${name}`); if (!value || value.startsWith("--")) fail(`${name} requires a value.`); seen.add(name); } }
function option(args, name) { const index = args.indexOf(name); if (index < 0) return undefined; const value = args[index + 1]; if (!value || value.startsWith("--")) fail(`${name} requires a value.`); return value; }
function parseJson(value, label) { try { return JSON.parse(value); } catch { fail(`${label} returned invalid JSON${value ? "." : " or did not execute."}`); } }
function safeSegment(value) { const result = String(value).replace(/[^A-Za-z0-9._-]/g, "-"); if (!result) fail("Package version cannot be used in an artifact name."); return result; }
function atomicJson(path, value) { atomicText(path, `${JSON.stringify(value, null, 2)}\n`); }
function atomicText(path, value) { mkdirSync(dirname(path), { recursive: true }); const temporary = `${path}.${process.pid}.tmp`; try { writeFileSync(temporary, value, { encoding: "utf8", mode: 0o600 }); rmSync(path, { force: true }); renameSync(temporary, path); } finally { rmSync(temporary, { force: true }); } }
function fail(message) { process.stderr.write(`${message}\n`); process.exit(1); }
