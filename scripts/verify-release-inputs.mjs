import { lstat, readFile, readdir } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requiredFiles = [
  "dist/cli/index.js",
  "dist/dashboard/server/DashboardServer.js",
  "dist/core/plugins/ThirdPartyModuleRunner.mjs",
  "dist/benchmark/fixtures/credibility-python.py",
  "apps/dashboard-ui/dist/index.html",
  "examples/supabase-authorization.example.json",
  "examples/authentication-lifecycle.example.json",
  "examples/authentication-lifecycle-automation.example.json",
  "examples/business-invariants.example.json",
  "examples/controlled-races.example.json",
  "examples/api-graphql.example.json",
  "examples/protocol-security.example.json",
  "examples/link-portal-security.example.json",
  "examples/operational-endpoints.example.json",
  "examples/billing-entitlement.example.json",
  "examples/assisted-review.example.json",
  "examples/pre-handover.example.json",
  "examples/bug-bounty-authorization.example.json",
  "examples/active-vulnerability-validation.example.json",
  "benchmarks/routecairn-credibility-corpus-v1.json",
  "LICENSE",
  "README.md",
  "SECURITY.md"
];

for (const relativePath of requiredFiles) {
  const path = resolve(packageRoot, relativePath);
  const stat = await lstat(path).catch(() => undefined);
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.size === 0) {
    throw new Error(`Release input is missing, empty, or unsafe: ${relativePath}`);
  }
}

const dashboardFiles = await walk(resolve(packageRoot, "apps/dashboard-ui/dist"));
if (!dashboardFiles.some((path) => extname(path) === ".js")) {
  throw new Error("The built dashboard contains no JavaScript asset.");
}

const packageJson = JSON.parse(await readFile(resolve(packageRoot, "package.json"), "utf8"));
if (!Array.isArray(packageJson.files) || packageJson.files.length === 0) {
  throw new Error("package.json must use an explicit release allowlist.");
}

process.stdout.write(`Verified ${requiredFiles.length} required release inputs and ${dashboardFiles.length} dashboard files.\n`);

async function walk(root) {
  const files = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = resolve(root, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Release assets must not contain symbolic links: ${path}`);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}
