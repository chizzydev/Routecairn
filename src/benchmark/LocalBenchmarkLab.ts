import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { performance } from "node:perf_hooks";
import { runScanCommand } from "../cli/commands/scan.js";
import { defaultConfig, exampleScope } from "../config/defaults.js";
import { scopeSchema } from "../config/ConfigSchema.js";
import { authProfileSchema } from "../core/auth/AuthProfile.js";
import { RouteCairnEngine } from "../core/engine/RouteCairnEngine.js";
import { createDefaultPluginRegistry } from "../core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../core/planning/ScanPlanner.js";
import type { ModuleId, ModuleSettings } from "../core/planning/ScanPlan.js";
import type { RouteCairnReport } from "../reports/ReportTypes.js";
import { evaluateBenchmark, type BenchmarkResult, type BenchmarkRunInput } from "./BenchmarkEvaluator.js";
import { writeBenchmarkArtifacts } from "./BenchmarkArtifacts.js";
import type { BenchmarkManifest } from "./BenchmarkSchemas.js";
import { benchmarkAuthProfiles, comprehensiveBenchmarkInputs, startComprehensiveBenchmarkTarget } from "./ComprehensiveBenchmarkFixture.js";

export interface LocalBenchmarkOptions { output?: string; repetitions?: number; baseline?: BenchmarkResult; release?: string; build?: string }

/** Runs only against a process-owned loopback target with paired vulnerable and secure controls. */
export async function runLocalBenchmark(options: LocalBenchmarkOptions = {}) {
  const repetitions = options.repetitions ?? 3;
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 20) throw new Error("BENCHMARK_REPETITIONS_INVALID");
  const parent = resolve(options.output ?? tmpdir()); await mkdir(parent, { recursive: true });
  const directory = await mkdtemp(join(parent, "routecairn-benchmark-"));
  const target = await startComprehensiveBenchmarkTarget();
  const previousMutationDirectory = process.env.ROUTECAIRN_MUTATION_DIR;
  const previousSupabaseAnon = process.env.ROUTECAIRN_BENCHMARK_SUPABASE_ANON;
  try {
    const origin = target.origin;
    const scopeValue = scopeSchema.parse({ ...exampleScope, program: "RouteCairn comprehensive intentionally vulnerable benchmark fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"], rateLimitPerSecond: 50, concurrency: 5, respectRobotsTxt: false });
    const scope = await writeJson(directory, "scope.json", scopeValue);
    const profiles = benchmarkAuthProfiles(origin);
    const auth = await writeJson(directory, "auth.json", profiles.primary);
    const authA = await writeJson(directory, "auth-a.json", profiles.accountA);
    const authB = await writeJson(directory, "auth-b.json", profiles.accountB);
    const apiGraphql = await writeJson(directory, "api-graphql.json", localScannerManifest(origin));
    const activeVulnerability = await writeJson(directory, "active-vulnerability.json", localActiveManifest(origin));
    const comprehensive = comprehensiveBenchmarkInputs(origin);
    const protocolSecurity = await writeJson(directory, "protocol-security.json", comprehensive.protocol);
    const supabaseAuthorization = await writeJson(directory, "supabase-authorization.json", comprehensive.supabase);
    const authenticationLifecycle = await writeJson(directory, "authentication-lifecycle.json", comprehensive.lifecycle);
    const linkPortalSecurity = await writeJson(directory, "link-portal-security.json", comprehensive.links);
    const billingEntitlement = await writeJson(directory, "billing-entitlement.json", comprehensive.billing);
    const controlledRaces = await writeJson(directory, "controlled-races.json", comprehensive.races);
    process.env.ROUTECAIRN_BENCHMARK_SUPABASE_ANON = unsignedJwt("anon");
    const runs: BenchmarkRunInput[] = [];
    for (let index = 0; index < repetitions; index += 1) {
      target.reset(); process.env.ROUTECAIRN_MUTATION_DIR = join(directory, "mutation-journals", `run-${index + 1}`);
      const beforeRequests = target.requestCount(); const started = performance.now(); const cpuBefore = process.cpuUsage(); let peakRssBytes = process.memoryUsage().rss;
      const sampler = setInterval(() => { peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss); }, 10); sampler.unref();
      try {
        const runDirectory = join(directory, "scans", `run-${index + 1}`);
        const core = await runScanCommand(`${origin}/`, { scope, authA, authB, apiGraphql, activeVulnerability, profile: "quick", output: join(runDirectory, "core"), maxRequests: "60", cleanupReservedRequests: "0" });
        const extended = await runScanCommand(`${origin}/`, { scope, auth, authA, authB, protocolSecurity, supabaseAuthorization, authenticationLifecycle, linkPortalSecurity, billingEntitlement, controlledRaces, profile: "quick", output: join(runDirectory, "extended"), maxRequests: "180", cleanupReservedRequests: "30" });
        const browser = await runBrowserBenchmark(origin, scopeValue, profiles.browser, join(runDirectory, "browser"));
        const reports = await Promise.all([core.reportPath, extended.reportPath, browser.reportPath].map(async (path) => JSON.parse(await readFile(path, "utf8")) as RouteCairnReport));
        const report = mergeReports(reports);
        await mkdir(runDirectory, { recursive: true }); await writeFile(join(runDirectory, "report.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
        const transmitted = report.requestAudit.reduce((sum, entry) => sum + (entry.transmittedRequests ?? (entry.outcome === "sent" ? 1 : 0)), 0); const cpu = process.cpuUsage(cpuBefore);
        runs.push({ report, telemetry: { runtimeMs: performance.now() - started, peakRssBytes, requestCount: target.requestCount() - beforeRequests, transmittedRequestCount: transmitted, cpuUserMicros: cpu.user, cpuSystemMicros: cpu.system } });
      } finally { clearInterval(sampler); }
    }
    const manifest = localTruthManifest();
    await writeJson(directory, "benchmark-manifest.json", manifest);
    const result = evaluateBenchmark(manifest, runs, { ...(options.baseline ? { baseline: options.baseline } : {}), ...(options.release ? { release: options.release } : {}), ...(options.build ? { build: options.build } : {}) });
    const artifacts = await writeBenchmarkArtifacts(directory, result);
    return { directory, fixtureOnly: true, externalTargetsTested: false, targetKind: "INTENTIONALLY_VULNERABLE_LOOPBACK", result, artifacts };
  } finally {
    if (previousMutationDirectory === undefined) delete process.env.ROUTECAIRN_MUTATION_DIR; else process.env.ROUTECAIRN_MUTATION_DIR = previousMutationDirectory;
    if (previousSupabaseAnon === undefined) delete process.env.ROUTECAIRN_BENCHMARK_SUPABASE_ANON; else process.env.ROUTECAIRN_BENCHMARK_SUPABASE_ANON = previousSupabaseAnon;
    await target.close();
  }
}

export function localTruthManifest(): BenchmarkManifest {
  const selector = (caseId: string, workflowId = "api-graphql-authorization") => [{ workflowId, caseId }];
  const pair = (prefix: string, workflowId: string, category: string, label: string, tags: string[]) => ([
    { id: `${prefix}-vulnerable`, label: `Detect ${label}`, expected: "FINDING" as const, selectors: selector(`${prefix}-vulnerable`, workflowId), category, tags: [...tags, "positive"], required: true },
    { id: `${prefix}-secure`, label: `Accept secure ${label} control`, expected: "NO_FINDING" as const, selectors: selector(`${prefix}-secure`, workflowId), category, tags: [...tags, "negative-control"], required: true }
  ]);
  return {
    schemaVersion: 1, id: "routecairn-comprehensive-detection-lab", label: "RouteCairn comprehensive detection benchmark",
    description: "Balanced vulnerable and secure controls spanning REST, protocol, authentication, Supabase, browser, signed-link, billing, race, and cleanup behavior on a generated loopback-only target.",
    cases: [
      { id: "object-vulnerable", label: "Detect cross-tenant object authorization bypass", expected: "FINDING", selectors: selector("object-vulnerable"), category: "OBJECT_AUTHORIZATION", tags: ["rest", "positive"], required: true },
      { id: "object-secure", label: "Accept correctly denied cross-tenant object access", expected: "NO_FINDING", selectors: selector("object-secure"), category: "OBJECT_AUTHORIZATION", tags: ["rest", "negative-control"], required: true },
      { id: "admin-vulnerable", label: "Detect privileged function authorization bypass", expected: "FINDING", selectors: selector("admin-vulnerable"), category: "FUNCTION_AUTHORIZATION", tags: ["rest", "positive"], required: true },
      { id: "admin-secure", label: "Accept correctly denied privileged function access", expected: "NO_FINDING", selectors: selector("admin-secure"), category: "FUNCTION_AUTHORIZATION", tags: ["rest", "negative-control"], required: true },
      { id: "sql-vulnerable", label: "Detect database error differential", expected: "FINDING", selectors: selector("sql-vulnerable", "active-vulnerability-validation"), category: "SQL_INJECTION", tags: ["active", "positive"], required: true },
      { id: "sql-secure", label: "Accept neutralized SQL canary", expected: "NO_FINDING", selectors: selector("sql-secure", "active-vulnerability-validation"), category: "SQL_INJECTION", tags: ["active", "negative-control"], required: true },
      { id: "redirect-vulnerable", label: "Detect an untrusted external redirect", expected: "FINDING", selectors: selector("redirect-vulnerable", "active-vulnerability-validation"), category: "OPEN_REDIRECT", tags: ["active", "positive"], required: true },
      { id: "redirect-secure", label: "Accept a same-origin redirect boundary", expected: "NO_FINDING", selectors: selector("redirect-secure", "active-vulnerability-validation"), category: "OPEN_REDIRECT", tags: ["active", "negative-control"], required: true },
      ...pair("protocol-sse", "protocol-security", "PROTOCOL_SSE", "SSE authorization bypass", ["protocol", "sse"]),
      ...pair("protocol-graphql", "protocol-security", "PROTOCOL_GRAPHQL_MUTATION", "GraphQL mutation authorization bypass", ["protocol", "graphql", "cleanup"]),
      ...pair("protocol-multipart", "protocol-security", "PROTOCOL_MULTIPART", "multipart authorization bypass", ["protocol", "multipart"]),
      ...pair("supabase-table", "supabase-authorization", "SUPABASE_TABLE_RLS", "Supabase table RLS bypass", ["supabase", "rls"]),
      ...pair("supabase-storage", "supabase-authorization", "SUPABASE_STORAGE", "Supabase storage isolation bypass", ["supabase", "storage"]),
      ...pair("supabase-rpc", "supabase-authorization", "SUPABASE_RPC", "Supabase RPC authorization bypass", ["supabase", "rpc"]),
      ...pair("auth-enumeration", "authentication-lifecycle", "AUTHENTICATION_LIFECYCLE", "login enumeration differential", ["authentication", "lifecycle", "cleanup"]),
      ...pair("signed-expiry", "link-portal-export-security", "SIGNED_LINK", "expired signed-link acceptance", ["signed-link"]),
      ...pair("billing-premium", "billing-entitlement-security", "BILLING_AUTHORIZATION", "cross-account premium access", ["billing", "entitlement"]),
      ...pair("race", "controlled-race", "RACE_CONDITION", "one-time token race", ["race", "cleanup"]),
      { id: "browser-secret-exposure", label: "Detect a server credential in a browser-delivered bundle", expected: "FINDING", selectors: [{ findingType: "Server Credential Exposure" }], category: "BROWSER", tags: ["browser", "secret-boundary", "positive"], required: true },
      { id: "browser-authenticated-bootstrap", label: "Accept a successful authenticated browser bootstrap", expected: "NO_FINDING", selectors: selector("authenticated-browser-bootstrap", "browser-crawler"), category: "BROWSER", tags: ["browser", "authentication", "negative-control"], required: true }
    ],
    thresholds: { minRecall: 1, maxFalsePositiveRate: 0, maxInconclusiveRate: 0, minCoverageCompleteness: 1, minRepetitions: 3, minCasesPerCategory: 2, requireBalancedCategories: true, minCleanupObservationsPerRun: 6, maxCleanupFailures: 0, maxP95RuntimeMs: 180_000, maxPeakRssBytes: 2_000_000_000, maxRequestsPerAssessedCase: 12 },
    regression: { maxRecallDrop: 0, maxFalsePositiveRateIncrease: 0, maxInconclusiveRateIncrease: 0, maxCoverageDrop: 0, maxRuntimeIncreaseRatio: 1, maxMemoryIncreaseRatio: 0.75, maxRequestIncreaseRatio: 0.15, failOnCaseRegression: true }, metadata: { fixture: true, mutationFree: false, disposableStateChanges: true, externalTargetsTested: false }
  };
}

function localActiveManifest(origin: string) {
  const proof = { allowedRedirectOrigins: [], secureStatuses: [], vulnerableStatuses: [] };
  const queryCase = (id: string, vulnerabilityClass: "SQL_INJECTION" | "OPEN_REDIRECT", path: string, name: string, originalValue: string) => ({ id, label: id, vulnerabilityClass, actorId: "anonymous", environment: "LOCAL_FIXTURE", request: { url: `${origin}${path}`, method: "GET", headers: {}, injection: { location: "QUERY", name, originalValue }, operatorConfirmedNonMutating: false }, proof });
  return {
    schemaVersion: 1,
    maxRequests: 12,
    maxResponseBytes: 65_536,
    maxCases: 4,
    actors: [{ id: "anonymous", safeAlias: "Anonymous", authSlot: "anonymous", relationship: "PUBLIC" }],
    discovery: { enabled: false, classes: [], maxCandidates: 0, queryParametersOnly: true, includeAuthenticated: false },
    cases: [
      queryCase("sql-vulnerable", "SQL_INJECTION", "/search/vulnerable?q=fixture", "q", "fixture"),
      queryCase("sql-secure", "SQL_INJECTION", "/search/secure?q=fixture", "q", "fixture"),
      queryCase("redirect-vulnerable", "OPEN_REDIRECT", "/redirect/vulnerable?next=%2Fhome", "next", "/home"),
      queryCase("redirect-secure", "OPEN_REDIRECT", "/redirect/secure?next=%2Fhome", "next", "/home")
    ]
  };
}

function localScannerManifest(origin: string) {
  const actors = [{ id: "foreign", safeAlias: "foreign-tenant-member", authSlot: "account_b", relationship: "CROSS_TENANT_MEMBER", principalId: "account-b", tenantId: "tenant-b", role: "member" }];
  const routes = [
    { id: "object-vulnerable-route", safeAlias: "object-vulnerable", protocol: "REST", kind: "OBJECT", objectType: "record", url: `${origin}/object/vulnerable`, pathTemplate: "/object/{id}", documentedMethods: ["GET"] },
    { id: "object-secure-route", safeAlias: "object-secure", protocol: "REST", kind: "OBJECT", objectType: "record", url: `${origin}/object/secure`, pathTemplate: "/object/{id}", documentedMethods: ["GET"] },
    { id: "admin-vulnerable-route", safeAlias: "admin-vulnerable", protocol: "REST", kind: "FUNCTION", functionName: "admin.read.vulnerable", url: `${origin}/admin/vulnerable`, documentedMethods: ["GET"] },
    { id: "admin-secure-route", safeAlias: "admin-secure", protocol: "REST", kind: "FUNCTION", functionName: "admin.read.secure", url: `${origin}/admin/secure`, documentedMethods: ["GET"] }
  ];
  const check = (id: string, routeId: string, kind: "OBJECT_AUTHORIZATION" | "FUNCTION_AUTHORIZATION") => ({ id, matrixId: `${id}-matrix`, label: id, kind, routeId, actorId: "foreign", requireVerifiedIdentity: false, request: { method: "GET" }, response: { expectedDecision: "DENY" } });
  return { schemaVersion: 1, maxRequests: 8, actors, routes, checks: [check("object-vulnerable", "object-vulnerable-route", "OBJECT_AUTHORIZATION"), check("object-secure", "object-secure-route", "OBJECT_AUTHORIZATION"), check("admin-vulnerable", "admin-vulnerable-route", "FUNCTION_AUTHORIZATION"), check("admin-secure", "admin-secure-route", "FUNCTION_AUTHORIZATION")] };
}
async function runBrowserBenchmark(origin: string, scope: ReturnType<typeof scopeSchema.parse>, rawProfile: unknown, outputDir: string) {
  const authProfile = authProfileSchema.parse(rawProfile);
  const includeModules: ModuleId[] = ["baseline", "browser-crawler", "js-intelligence", "secret-boundary"];
  const moduleSettings: Partial<Record<ModuleId, ModuleSettings>> = { "browser-crawler": { browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: [origin], browserCaptureScreenshot: false, browserMaxPages: 3 } };
  const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "full", scope, config: defaultConfig, authProfile, overrides: { includeModules, moduleSettings, maxRequests: 60 } });
  return new RouteCairnEngine().scan({ target: `${origin}/`, scope, config: defaultConfig, plan, outputDir, authProfile });
}

function mergeReports(reports: readonly RouteCairnReport[]): RouteCairnReport {
  const [first] = reports; if (!first) throw new Error("BENCHMARK_REPORTS_REQUIRED");
  const merged = { ...first, findings: reports.flatMap((report) => report.findings), discoveredUrls: reports.flatMap((report) => report.discoveredUrls), requestAudit: reports.flatMap((report) => report.requestAudit) } as Record<string, unknown>;
  const moduleKeys = ["protocolSecurity", "supabaseAuthorization", "authenticationLifecycle", "linkPortalSecurity", "billingEntitlement", "controlledRace", "browserCrawl", "secretBoundary"];
  for (const key of moduleKeys) { const source = reports.find((report) => (report as unknown as Record<string, unknown>)[key] !== undefined); if (source) merged[key] = (source as unknown as Record<string, unknown>)[key]; }
  return merged as unknown as RouteCairnReport;
}

function unsignedJwt(role: string): string { return `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(JSON.stringify({ role })).toString("base64url")}.`; }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); return path; }
