import { lstat, readFile, readdir } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requiredFiles = [
  "dist/validation/ProtocolFixtureSocket.js",
  "npm-shrinkwrap.json",
  "dist/standards/catalog/official-catalog.json", "dist/standards/OfficialCatalogIdentity.js", "dist/standards/StandardsCoverageValidation.js", "dist/cli/commands/standards.js", "standards/sources.lock.json", "standards/NOTICE.md", "docs/STANDARDS_ACCOUNTING.md",
  "dist/controlPlane/FleetServer.js", "dist/controlPlane/DashboardSingleton.js", "dist/controlPlane/InitializeEvidenceStorage.js", "dist/cli/commands/fleet.js", "docs/HORIZONTAL_SCALE_OPERATIONS.md", "deploy/control-plane/Minio.Dockerfile", "deploy/control-plane/Caddyfile.distributed", "deploy/helm/routecairn/templates/dashboard.yaml", "deploy/helm/routecairn/templates/dashboard-storage.yaml",
  "dist/core/plugins/ModuleDistribution.js", "dist/core/plugins/ModuleRegistry.js", "dist/core/plugins/ModuleSdk.d.ts", "dist/cli/commands/modules.js", "docs/MODULE_ECOSYSTEM.md", "examples/modules/security-headers/index.mjs", "examples/modules/framework-fingerprint/index.mjs", "examples/modules/graphql-response/index.mjs", "examples/module-registry.example.json", "deploy/module-registry/compose.yaml",
  "dist/cli/index.js",
  "dist/dashboard/server/DashboardServer.js",
  "dist/core/plugins/ThirdPartyModuleRunner.mjs",
  "dist/standards/StandardsCoverage.js",
  "dist/standards/StandardsCoverageWriter.js",
  "dist/benchmark/fixtures/credibility-python.py",
  "dist/benchmark/fixtures/credibility-go.go",
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
  "examples/active-vulnerability-oast.example.json",
  "examples/oast-service.self-hosted.example.json",
  "examples/oast-service.hosted.example.json",
  "examples/third-party-module.example.json",
  "examples/third-party-module-broker-binding.example.json",
  "deploy/oast/Dockerfile",
  "deploy/control-plane/Dockerfile",
  "deploy/control-plane/compose.distributed.yaml",
  "deploy/control-plane/otel-collector.yaml",
  "deploy/helm/routecairn/Chart.yaml",
  "deploy/helm/routecairn/values.yaml",
  "deploy/helm/routecairn/templates/deployment.yaml",
  "deploy/helm/routecairn/templates/worker-pools.yaml",
  "examples/external-acceptance.example.json",
  "benchmarks/routecairn-credibility-corpus-v1.json",
  "benchmarks/routecairn-credibility-corpus-v2.json",
  "docs/INDEPENDENT_BENCHMARK.md",
  "docs/EXTERNAL_ACCEPTANCE.md",
  "dist/validation/ExternalAcceptanceReadiness.js",
  "dist/validation/OwnedAcceptanceHistory.js",
  "dist/validation/OwnedDecideExercise.js",
  "dist/validation/DecideAcceptanceAccounts.js",
  "dist/validation/OwnedSupabaseExercise.js",
  "dist/validation/SupabaseAcceptanceStore.js",
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
