import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = await mkdtemp(join(tmpdir(), "routecairn-package-smoke-"));
const packDirectory = join(temporaryRoot, "pack");
const consumerDirectory = join(temporaryRoot, "consumer");
const retainedDestination = optionValue("--pack-destination");
const keepTemporary = process.argv.includes("--keep-temp");

try {
  await mkdir(packDirectory, { recursive: true });
  const packed = runNpm(["pack", "--json", "--silent", "--pack-destination", packDirectory], packageRoot);
  const packResult = parsePackResult(packed.stdout);
  const tarball = resolve(packDirectory, packResult.filename);
  const names = new Set(packResult.files.map((entry) => String(entry.path).replace(/^package\//, "").replaceAll("\\", "/")));

  const required = [
  "dist/validation/ProtocolFixtureSocket.js",
    "npm-shrinkwrap.json",
    "dist/standards/catalog/official-catalog.json", "dist/standards/StandardsCoverageValidation.js", "dist/cli/commands/standards.js", "standards/NOTICE.md", "standards/sources.lock.json", "docs/STANDARDS_ACCOUNTING.md",
    "dist/core/plugins/ModuleDistribution.js", "dist/core/plugins/ModuleRegistry.js", "dist/core/plugins/ModuleSdk.d.ts", "dist/cli/commands/modules.js", "docs/MODULE_ECOSYSTEM.md", "examples/modules/security-headers/index.mjs", "examples/modules/framework-fingerprint/index.mjs", "examples/modules/graphql-response/index.mjs", "examples/module-registry.example.json", "deploy/module-registry/compose.yaml",
    "dist/cli/index.js",
    "dist/dashboard/server/DashboardServer.js",
    "dist/core/plugins/ThirdPartyModuleRunner.mjs",
    "dist/modules/protocolSecurity/NativeHttp3Worker.js",
    "dist/benchmark/IndependentBenchmark.js",
    "dist/modules/activeVulnerability/ActiveOAuthJourney.js",
    "dist/modules/activeVulnerability/ActiveFileFixtures.js",
    "docs/ACTIVE_VULNERABILITY_OPERATIONS.md",
    "docs/OAST_OPERATIONS.md",
    "docs/ATTACK_GRAPH_OPERATIONS.md",
    "docs/PROTOCOL_SEMANTICS_OPERATIONS.md",
    "dist/modules/protocolSecurity/NativeWebTransport.js",
    "dist/modules/protocolSecurity/ProtocolGraphqlMultipart.js",
    "dist/modules/protocolSecurity/ProtocolGrpcFrames.js",
    "dist/dashboard/execution/AdaptiveEvidenceSafety.js",
    "dist/modules/apiGraphql/GraphqlDocumentSafety.js",
    "dist/dashboard/execution/AdaptiveAttackStateGraph.js",
    "dist/oast/OastDns.js",
    "dist/oast/OastDnsTransport.js",
    "dist/oast/OastDeploymentVerification.js",
    "deploy/oast/compose.yaml",
    "examples/oast-deployment-verification.example.json",
    "dist/benchmark/fixtures/credibility-python.py",
    "dist/benchmark/fixtures/credibility-go.go",
    "benchmarks/routecairn-credibility-corpus-v2.json",
    "docs/INDEPENDENT_BENCHMARK.md",
    "docs/EXTERNAL_ACCEPTANCE.md",
    "dist/validation/ExternalAcceptanceReadiness.js",
    "dist/validation/OwnedAcceptanceHistory.js",
    "dist/validation/OwnedDecideExercise.js",
    "dist/validation/DecideAcceptanceAccounts.js",
    "dist/validation/OwnedSupabaseExercise.js",
    "dist/validation/SupabaseAcceptanceStore.js",
    "apps/dashboard-ui/dist/index.html",
    "examples/protocol-security.example.json",
    "examples/active-vulnerability-validation.example.json",
    "examples/external-acceptance.example.json",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "package.json"
  ];
  for (const name of required) assert(names.has(name), `Published package is missing ${name}.`);
  assert([...names].some((name) => /^apps\/dashboard-ui\/dist\/assets\/.*\.js$/.test(name)), "Published package has no dashboard JavaScript bundle.");

  const forbidden = [
    [/^src\//, "source files"],
    [/^tests?\//, "test files"],
    [/^\.github\//, "workflow files"],
    [/\.map$/, "source maps"],
    [/\.d\.ts$/, "declaration files"]
  ];
  for (const [pattern, description] of forbidden) {
    const match = [...names].find((name) => name !== "dist/core/plugins/ModuleSdk.d.ts" && pattern.test(name));
    assert(!match, `Published package contains ${description}: ${match}`);
  }

  const packagedJson = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
  assert(packResult.version === packagedJson.version, `Tarball version ${packResult.version} differs from package.json ${packagedJson.version}.`);
  assert(packResult.name === packagedJson.name, `Tarball name ${packResult.name} differs from package.json ${packagedJson.name}.`);
  assert(Number(packResult.unpackedSize) < 8 * 1024 * 1024, `Published package is unexpectedly large: ${packResult.unpackedSize} bytes unpacked.`);

  await mkdir(consumerDirectory, { recursive: true });
  await writeFile(join(consumerDirectory, "package.json"), JSON.stringify({ name: "routecairn-package-consumer", private: true, type: "module" }, null, 2));
  runNpm(["install", "--no-save", "--package-lock=false", "--no-audit", "--no-fund", tarball], consumerDirectory, {
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1"
  });

  const installedRoot = join(consumerDirectory, "node_modules", "routecairn");
  const publishedLock = JSON.parse(await readFile(join(installedRoot, "npm-shrinkwrap.json"), "utf8"));
  const reviewedLock = JSON.parse(await readFile(join(packageRoot, "package-lock.json"), "utf8"));
  assert(JSON.stringify(publishedLock) === JSON.stringify(reviewedLock), "Installed package does not contain the reviewed dependency graph.");
  const cli = runNode([join(installedRoot, "dist", "cli", "index.js"), "--help"], consumerDirectory);
  assert(/Usage:\s+routecairn/i.test(cli.stdout), "Installed CLI did not render its help output.");
  assert(cli.stdout.includes("fleet") && cli.stdout.includes("initialize-evidence-storage"), "Installed CLI lacks distributed fleet and bucket administration commands.");
  const standardsVerification = JSON.parse(runNode([join(installedRoot, "dist/cli/index.js"), "standards", "verify"], consumerDirectory).stdout);
  assert(standardsVerification.status === "VERIFIED" && standardsVerification.counts.OWASP_ASVS === 345 && standardsVerification.counts.OWASP_WSTG === 97 && standardsVerification.builtInMappings === 111, "Installed standards catalog/mappings failed verification.");
  const fleetHelp=runNode([join(installedRoot,"dist/cli/index.js"),"fleet","--help"],consumerDirectory);
  assert(fleetHelp.stdout.includes("--tls-ca") && fleetHelp.stdout.includes("--trust-proxy"), "Installed fleet CLI lacks TLS/ingress controls.");
  assert(cli.stdout.includes("external-acceptance"), "Installed CLI did not expose the external-acceptance workflow.");
  const modulesHelp = runNode([join(installedRoot, "dist", "cli", "index.js"), "modules", "--help"], consumerDirectory);
  assert(modulesHelp.stdout.includes("request-signature") && modulesHelp.stdout.includes("install"), "Installed CLI is missing module distribution commands.");
  const moduleCli = (...args) => JSON.parse(runNode([join(installedRoot, "dist/cli/index.js"), "modules", ...args], consumerDirectory).stdout);
  const privateKeyPath = join(consumerDirectory, "publisher.key"), publicKeyPath = join(consumerDirectory, "publisher.pub"), trustPath = join(consumerDirectory, "module-trust.json"), payloadPath = join(consumerDirectory, "module-payload.json"), bundlePath = join(consumerDirectory, "module-bundle.json");
  const generatedKey = moduleCli("keygen", "--private-key", privateKeyPath, "--public-key", publicKeyPath);
  const expiresAt = new Date(Date.now() + 3600_000).toISOString();
  await writeFile(trustPath, JSON.stringify({ schemaVersion: 1, publishers: [{ publisher: "package-smoke", modulePrefixes: ["reference"], publicKeyPem: await readFile(publicKeyPath, "utf8"), keyId: generatedKey.keyId, notBefore: new Date(Date.now() - 1000).toISOString(), expiresAt }], revokedKeyIds: [], revokedPackageDigests: [] }));
  const builtModule = moduleCli("build", "--directory", join(installedRoot, "examples/modules/security-headers"), "--publisher", "package-smoke", "--expires-at", expiresAt, "--output", payloadPath);
  moduleCli("sign", "--payload", payloadPath, "--private-key", privateKeyPath, "--output", bundlePath);
  assert(moduleCli("review", "--bundle", bundlePath, "--trust", trustPath).packageApproval === "REQUIRED", "Installed module review lost separate approval.");
  const installedModule = moduleCli("install", "--bundle", bundlePath, "--trust", trustPath, "--root", join(consumerDirectory, "modules"), "--digest", builtModule.packageDigest);
  assert(installedModule.approved === false && installedModule.packageDigest === builtModule.packageDigest, "Installed signed module changed digest or granted execution approval.");
  const oastHelp = runNode([join(installedRoot, "dist", "cli", "index.js"), "oast", "--help"], consumerDirectory);
  assert(oastHelp.stdout.includes("verify-deployment"), "Installed CLI did not expose public OAST deployment verification.");

  const installedAcceptance = join(consumerDirectory, "installed-package-acceptance.mjs");
  await writeFile(installedAcceptance, `
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
const packageRoot = new URL("./node_modules/routecairn/", import.meta.url);
const externalAcceptance = await import(new URL("dist/validation/ExternalAcceptance.js", packageRoot));
const externalManifest = JSON.parse(await readFile(new URL("examples/external-acceptance.example.json", packageRoot), "utf8"));
externalAcceptance.externalAcceptanceManifestSchema.parse(externalManifest);
const catalogModule = await import(new URL("dist/dashboard/contracts/AdvancedEngineSchemas.js", packageRoot));
const catalog = await catalogModule.loadAdvancedEngineCatalog("https://authorized-target.invalid");
if (!Array.isArray(catalog) || catalog.length < 14) throw new Error("Installed dashboard could not load its packaged engine templates.");
const serverModule = await import(new URL("dist/dashboard/server/DashboardServer.js", packageRoot));
let handle;
try {
  handle = await serverModule.startDashboardServer({ host: "127.0.0.1", port: 0, dataDir: fileURLToPath(new URL("./dashboard-data/", import.meta.url)) });
  const response = await fetch(handle.url, { redirect: "manual" });
  const html = await response.text();
  if (response.status !== 200) throw new Error(\`Installed dashboard returned HTTP \${response.status}.\`);
  if (!html.includes("<title>RouteCairn Dashboard</title>") || !html.includes('<div id="root"></div>')) throw new Error("Installed dashboard did not serve the packaged UI.");
  process.stdout.write("INSTALLED_PACKAGE_ACCEPTED\\n");
} finally {
  if (handle) await handle.close();
}
`);
  const installed = runNode([installedAcceptance], consumerDirectory);
  assert(installed.stdout.includes("INSTALLED_PACKAGE_ACCEPTED"), "Installed package acceptance did not complete.");

  const protocolOutput = join(consumerDirectory, "protocol-acceptance");
  const protocolAcceptance = runNode([
    join(installedRoot, "dist", "cli", "index.js"),
    "validate-protocol-fixtures",
    "--output",
    protocolOutput
  ], consumerDirectory);
  const protocolSummary = JSON.parse(protocolAcceptance.stdout);
  assert(protocolSummary?.status === "PASSED", "Installed package protocol acceptance did not pass.");
  assert(protocolSummary?.nativeHttp3 === true, "Installed package did not execute native HTTP/3 acceptance.");
  assert(protocolSummary?.externalCurlRequired === false, "Installed package protocol acceptance still depends on curl.");
  assert(Array.isArray(protocolSummary?.lanes) && protocolSummary.lanes.every((lane) => lane.status === "PASSED"), "Installed package protocol acceptance reported a failed lane.");
  assert(protocolSummary.lanes.some((lane) => lane.name === "webtransport-native" && lane.checks?.certificateVerification === true && lane.checks?.deniedStatus === 403), "Installed package did not execute verified WebTransport acceptance.");
  const protocolEvidence = JSON.parse(await readFile(join(protocolSummary.outputDirectory, "protocol-acceptance.json"), "utf8"));
  assert(protocolEvidence?.evidenceSha256 === protocolSummary.evidenceSha256, "Installed package protocol evidence digest does not match its summary.");

  if (retainedDestination) {
    const destination = resolve(packageRoot, retainedDestination);
    await mkdir(destination, { recursive: true });
    const target = join(destination, basename(tarball));
    const bytes = await readFile(tarball);
    await writeFile(target, bytes, { flag: "w" });
    process.stdout.write(`Verified and retained ${target}.\n`);
  } else {
    process.stdout.write(`Verified installable package ${packResult.filename} (${names.size} files).\n`);
  }
} finally {
  if (keepTemporary) process.stdout.write(`Package smoke workspace retained at ${temporaryRoot}.\n`);
  else await rm(temporaryRoot, { recursive: true, force: true });
}

function runNpm(args, cwd, environment = {}) {
  const npmCli = process.env.npm_execpath;
  const command = npmCli ? process.execPath : process.platform === "win32" ? "npm.cmd" : "npm";
  const commandArgs = npmCli ? [npmCli, ...args] : args;
  return run(command, commandArgs, cwd, environment);
}

function runNode(args, cwd) {
  return run(process.execPath, args, cwd, {});
}

function run(command, args, cwd, environment) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    timeout: command === process.execPath && !args.some((value) => value === "install" || value === "pack") ? 120_000 : 600_000,
    killSignal: "SIGKILL",
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...environment }
  });
  if (result.error || result.status !== 0) {
    throw new Error([`Command failed: ${command} ${args.join(" ")}`, result.stdout, result.stderr, result.error?.message].filter(Boolean).join("\n"));
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function parsePackResult(stdout) {
  const end = stdout.lastIndexOf("]");
  for (let start = stdout.indexOf("["); start >= 0 && end > start; start = stdout.indexOf("[", start + 1)) {
    try {
      const parsed = JSON.parse(stdout.slice(start, end + 1));
      if (Array.isArray(parsed) && parsed.length === 1 && parsed[0]?.filename && Array.isArray(parsed[0]?.files)) return parsed[0];
    } catch {
      // Lifecycle output may contain terminal control sequences before npm's JSON result.
    }
  }
  throw new Error(`npm pack did not return the expected JSON result: ${stdout}`);
}

function optionValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a directory.`);
  return value;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
