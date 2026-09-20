import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { performance } from "node:perf_hooks";
import { runScanCommand } from "../cli/commands/scan.js";
import { exampleScope } from "../config/defaults.js";
import type { RouteCairnReport } from "../reports/ReportTypes.js";
import { evaluateBenchmark, type BenchmarkResult, type BenchmarkRunInput } from "./BenchmarkEvaluator.js";
import { writeBenchmarkArtifacts } from "./BenchmarkArtifacts.js";
import type { BenchmarkManifest } from "./BenchmarkSchemas.js";

export interface LocalBenchmarkOptions { output?: string; repetitions?: number; baseline?: BenchmarkResult; release?: string; build?: string }

/** Runs only against a process-owned loopback target with fixed read-only cases. */
export async function runLocalBenchmark(options: LocalBenchmarkOptions = {}) {
  const repetitions = options.repetitions ?? 3;
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 20) throw new Error("BENCHMARK_REPETITIONS_INVALID");
  const parent = resolve(options.output ?? tmpdir()); await mkdir(parent, { recursive: true });
  const directory = await mkdtemp(join(parent, "routecairn-benchmark-"));
  let requests = 0;
  const server = createServer(async (request, response) => {
    requests += 1;
    if (request.url === "/") return json(response, 200, { service: "benchmark-fixture" });
    if (request.url === "/object/vulnerable") return json(response, 200, { id: "tenant-a-object", tenantId: "tenant-a" });
    if (request.url === "/object/secure") return void response.writeHead(403).end();
    if (request.url === "/admin/vulnerable") return json(response, 200, { privileged: true });
    if (request.url === "/admin/secure") return void response.writeHead(403).end();
    if (request.url?.startsWith("/search/vulnerable?")) return request.url.includes("%27") || request.url.includes("'") ? json(response, 500, { error: "SQL syntax error near query" }) : json(response, 200, { matches: [] });
    if (request.url?.startsWith("/search/secure?")) return json(response, 200, { matches: [] });
    if (request.url?.startsWith("/redirect/vulnerable?")) { const next = new URL(request.url, "http://fixture.invalid").searchParams.get("next") ?? "/home"; response.writeHead(302, { location: next }).end(); return; }
    if (request.url?.startsWith("/redirect/secure?")) { response.writeHead(302, { location: "/home" }).end(); return; }
    if (request.url === "/me") return json(response, 200, identity(request));
    return void response.writeHead(404).end();
  });
  await new Promise<void>((resolveListen, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolveListen); });
  try {
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const scope = await writeJson(directory, "scope.json", { ...exampleScope, program: "RouteCairn intentionally vulnerable benchmark fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 50, concurrency: 4, respectRobotsTxt: false });
    const authA = await writeJson(directory, "auth-a.json", { label: "benchmark-account-a", safeAlias: "benchmark-a", principalId: "account-a", tenantId: "tenant-a", headers: { Authorization: "Bearer benchmark-a" } });
    const authB = await writeJson(directory, "auth-b.json", { label: "benchmark-account-b", safeAlias: "benchmark-b", principalId: "account-b", tenantId: "tenant-b", headers: { Authorization: "Bearer benchmark-b" } });
    const apiGraphql = await writeJson(directory, "api-graphql.json", localScannerManifest(origin));
    const activeVulnerability = await writeJson(directory, "active-vulnerability.json", localActiveManifest(origin));
    const runs: BenchmarkRunInput[] = [];
    for (let index = 0; index < repetitions; index += 1) {
      const beforeRequests = requests; const started = performance.now(); let peakRssBytes = process.memoryUsage().rss;
      const sampler = setInterval(() => { peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss); }, 10); sampler.unref();
      try {
        const scan = await runScanCommand(`${origin}/`, { scope, authA, authB, apiGraphql, activeVulnerability, profile: "quick", output: join(directory, "scans", `run-${index + 1}`), maxRequests: "50", cleanupReservedRequests: "0" });
        const report = JSON.parse(await readFile(scan.reportPath, "utf8")) as RouteCairnReport;
        const transmitted = report.requestAudit.reduce((sum, entry) => sum + (entry.transmittedRequests ?? (entry.outcome === "sent" ? 1 : 0)), 0);
        runs.push({ report, telemetry: { runtimeMs: performance.now() - started, peakRssBytes, requestCount: requests - beforeRequests, transmittedRequestCount: transmitted } });
      } finally { clearInterval(sampler); }
    }
    const manifest = localTruthManifest();
    await writeJson(directory, "benchmark-manifest.json", manifest);
    const result = evaluateBenchmark(manifest, runs, { ...(options.baseline ? { baseline: options.baseline } : {}), ...(options.release ? { release: options.release } : {}), ...(options.build ? { build: options.build } : {}) });
    const artifacts = await writeBenchmarkArtifacts(directory, result);
    return { directory, fixtureOnly: true, externalTargetsTested: false, targetKind: "INTENTIONALLY_VULNERABLE_LOOPBACK", result, artifacts };
  } finally { await new Promise<void>((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose())); }
}

export function localTruthManifest(): BenchmarkManifest {
  const selector = (caseId: string, workflowId = "api-graphql-authorization") => [{ workflowId, caseId }];
  return {
    schemaVersion: 1, id: "routecairn-read-only-detection-lab", label: "RouteCairn read-only detection benchmark",
    description: "Balanced vulnerable and secure controls executed against a generated loopback-only target.",
    cases: [
      { id: "object-vulnerable", label: "Detect cross-tenant object authorization bypass", expected: "FINDING", selectors: selector("object-vulnerable"), category: "OBJECT_AUTHORIZATION", tags: ["rest", "positive"], required: true },
      { id: "object-secure", label: "Accept correctly denied cross-tenant object access", expected: "NO_FINDING", selectors: selector("object-secure"), category: "OBJECT_AUTHORIZATION", tags: ["rest", "negative-control"], required: true },
      { id: "admin-vulnerable", label: "Detect privileged function authorization bypass", expected: "FINDING", selectors: selector("admin-vulnerable"), category: "FUNCTION_AUTHORIZATION", tags: ["rest", "positive"], required: true },
      { id: "admin-secure", label: "Accept correctly denied privileged function access", expected: "NO_FINDING", selectors: selector("admin-secure"), category: "FUNCTION_AUTHORIZATION", tags: ["rest", "negative-control"], required: true },
      { id: "sql-vulnerable", label: "Detect database error differential", expected: "FINDING", selectors: selector("sql-vulnerable", "active-vulnerability-validation"), category: "SQL_INJECTION", tags: ["active", "positive"], required: true },
      { id: "sql-secure", label: "Accept neutralized SQL canary", expected: "NO_FINDING", selectors: selector("sql-secure", "active-vulnerability-validation"), category: "SQL_INJECTION", tags: ["active", "negative-control"], required: true },
      { id: "redirect-vulnerable", label: "Detect an untrusted external redirect", expected: "FINDING", selectors: selector("redirect-vulnerable", "active-vulnerability-validation"), category: "OPEN_REDIRECT", tags: ["active", "positive"], required: true },
      { id: "redirect-secure", label: "Accept a same-origin redirect boundary", expected: "NO_FINDING", selectors: selector("redirect-secure", "active-vulnerability-validation"), category: "OPEN_REDIRECT", tags: ["active", "negative-control"], required: true }
    ],
    thresholds: { minRecall: 1, maxFalsePositiveRate: 0, maxInconclusiveRate: 0, minCoverageCompleteness: 1, maxP95RuntimeMs: 60_000, maxPeakRssBytes: 2_000_000_000, maxRequestsPerAssessedCase: 10 },
    regression: { maxRecallDrop: 0, maxFalsePositiveRateIncrease: 0, maxInconclusiveRateIncrease: 0, maxCoverageDrop: 0, maxRuntimeIncreaseRatio: 0.5, maxMemoryIncreaseRatio: 0.5, maxRequestIncreaseRatio: 0.25, failOnCaseRegression: true }, metadata: { fixture: true, mutationFree: true }
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
function identity(request: IncomingMessage) { const value = request.headers.authorization === "Bearer benchmark-a" ? "a" : "b"; return { id: `account-${value}`, tenantId: `tenant-${value}` }; }
function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); return path; }
