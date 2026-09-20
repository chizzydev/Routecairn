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
    "dist/cli/index.js",
    "dist/dashboard/server/DashboardServer.js",
    "dist/core/plugins/ThirdPartyModuleRunner.mjs",
    "apps/dashboard-ui/dist/index.html",
    "examples/protocol-security.example.json",
    "examples/active-vulnerability-validation.example.json",
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
    const match = [...names].find((name) => pattern.test(name));
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
  const cli = runNode([join(installedRoot, "dist", "cli", "index.js"), "--help"], consumerDirectory);
  assert(/Usage:\s+routecairn/i.test(cli.stdout), "Installed CLI did not render its help output.");

  const installedAcceptance = join(consumerDirectory, "installed-package-acceptance.mjs");
  await writeFile(installedAcceptance, `
import { fileURLToPath } from "node:url";
const packageRoot = new URL("./node_modules/routecairn/", import.meta.url);
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
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...environment }
  });
  if (result.error || result.status !== 0) {
    throw new Error([`Command failed: ${command} ${args.join(" ")}`, result.stdout, result.stderr, result.error?.message].filter(Boolean).join("\n"));
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function parsePackResult(stdout) {
  const start = stdout.indexOf("[");
  const end = stdout.lastIndexOf("]");
  assert(start >= 0 && end > start, `npm pack did not return JSON: ${stdout}`);
  const parsed = JSON.parse(stdout.slice(start, end + 1));
  assert(Array.isArray(parsed) && parsed.length === 1 && parsed[0]?.filename && Array.isArray(parsed[0]?.files), "npm pack returned an unexpected result.");
  return parsed[0];
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
