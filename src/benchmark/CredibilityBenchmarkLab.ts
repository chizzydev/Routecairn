import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { runScanCommand } from "../cli/commands/scan.js";
import { exampleScope } from "../config/defaults.js";
import { scopeSchema } from "../config/ConfigSchema.js";
import type { RouteCairnReport } from "../reports/ReportTypes.js";
import { evaluateBenchmark, type BenchmarkResult, type BenchmarkRunInput } from "./BenchmarkEvaluator.js";
import { writeBenchmarkArtifacts } from "./BenchmarkArtifacts.js";
import type { BenchmarkManifest, BenchmarkTruthCase } from "./BenchmarkSchemas.js";
import { benchmarkAuthProfiles } from "./ComprehensiveBenchmarkFixture.js";

type Control = "vulnerable" | "secure" | "near-miss";
interface Target { id: string; language: string; framework: string; origin: string; reset(): Promise<void>; close(): Promise<void> }
export interface CredibilityBenchmarkOptions { output?: string; repetitions?: number; baseline?: BenchmarkResult; release?: string; build?: string; pythonCommand?: string; goCommand?: string }

const variantsPerCategory = 12;
export const credibilityCategories = ["object", "function", "sql", "sql-boolean", "sql-union", "redirect", "authentication", "second-order", "nosql", "crlf", "template", "traversal"] as const;
export const credibilityTargetMatrix = [
  { id: "node-http", language: "TypeScript", framework: "node:http" },
  { id: "python-http", language: "Python", framework: "http.server" },
  { id: "python-wsgi", language: "Python", framework: "wsgiref" },
  { id: "go-http", language: "Go", framework: "net/http" }
] as const;
const targetsRequired = credibilityTargetMatrix.length;

/** Runs 576 HTTP cases across four process-owned implementations in three languages. */
export async function runCredibilityBenchmark(options: CredibilityBenchmarkOptions = {}) {
  const repetitions = options.repetitions ?? 3; if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 10) throw new Error("BENCHMARK_REPETITIONS_INVALID");
  const parent = resolve(options.output ?? tmpdir()); await mkdir(parent, { recursive: true }); const directory = await mkdtemp(join(parent, "routecairn-credibility-"));
  const targets = await startTargets(options.pythonCommand, options.goCommand, directory); const previousMutationDirectory = process.env.ROUTECAIRN_MUTATION_DIR;
  try {
    if (targets.length !== targetsRequired) throw new Error("BENCHMARK_CREDIBILITY_TARGET_MATRIX_INCOMPLETE");
    const runs: BenchmarkRunInput[] = [];
    for (let repetition = 0; repetition < repetitions; repetition += 1) {
      const started = performance.now(); const cpuBefore = process.cpuUsage(); let peakRssBytes = process.memoryUsage().rss; let requestCount = 0;
      const sampler = setInterval(() => { peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss); }, 10); sampler.unref(); const reports: RouteCairnReport[] = [];
      try {
        for (const target of targets) {
          await target.reset(); const targetDirectory = join(directory, "scans", `run-${repetition + 1}`, target.id); process.env.ROUTECAIRN_MUTATION_DIR = join(directory, "mutation-journals", `run-${repetition + 1}`, target.id);
          const scopeValue = scopeSchema.parse({ ...exampleScope, program: `RouteCairn credibility corpus ${target.id}`, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"], rateLimitPerSecond: 50, concurrency: 5, respectRobotsTxt: false });
          const scope = await writeJson(targetDirectory, "scope.json", scopeValue); const auth = await writeJson(targetDirectory, "auth.json", benchmarkAuthProfiles(target.origin).primary);
          const apiGraphql = await writeJson(targetDirectory, "api-graphql.json", apiInput(target)); const authenticationLifecycle = await writeJson(targetDirectory, "authentication-lifecycle.json", lifecycleInput(target));
          const active = activeInput(target);
          for (let offset = 0; offset < active.cases.length; offset += 100) {
            const activeVulnerability = await writeJson(targetDirectory, `active-vulnerability-${offset}.json`, { ...active, cases: active.cases.slice(offset, offset + 100), maxCases: Math.min(100, active.cases.length - offset) });
            const scan = await runScanCommand(`${target.origin}/healthz`, { scope, auth, ...(offset === 0 ? { apiGraphql, authenticationLifecycle } : {}), activeVulnerability, profile: "quick", includeModules: offset === 0 ? ["api-graphql-authorization", "active-vulnerability-validation", "authentication-lifecycle"] : ["active-vulnerability-validation"], replaceProfileModules: true, output: join(targetDirectory, `scan-${offset}`), maxRequests: "900", cleanupReservedRequests: offset === 0 ? "60" : "0" });
            const report = JSON.parse(await readFile(scan.reportPath, "utf8")) as RouteCairnReport; requestCount += report.requestAudit.reduce((sum, item) => sum + (item.transmittedRequests ?? (item.outcome === "sent" ? 1 : 0)), 0); reports.push(report);
          }
        }
        const report = mergeReports(reports); const runDirectory = join(directory, "scans", `run-${repetition + 1}`); await writeFile(join(runDirectory, "report.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
        const cpu = process.cpuUsage(cpuBefore); runs.push({ report, telemetry: { runtimeMs: performance.now() - started, peakRssBytes, requestCount, transmittedRequestCount: requestCount, cpuUserMicros: cpu.user, cpuSystemMicros: cpu.system } });
      } finally { clearInterval(sampler); }
    }
    const manifest = credibilityTruthManifest(targets); await writeJson(directory, "benchmark-manifest.json", manifest);
    const result = evaluateBenchmark(manifest, runs, { ...(options.baseline ? { baseline: options.baseline } : {}), ...(options.release ? { release: options.release } : {}), ...(options.build ? { build: options.build } : {}) });
    const artifacts = await writeBenchmarkArtifacts(directory, result); return { directory, fixtureOnly: true, externalTargetsTested: false, targetKind: "MULTI_LANGUAGE_INTENTIONALLY_VULNERABLE_LOOPBACK", result, artifacts };
  } finally {
    if (previousMutationDirectory === undefined) delete process.env.ROUTECAIRN_MUTATION_DIR; else process.env.ROUTECAIRN_MUTATION_DIR = previousMutationDirectory;
    await Promise.allSettled(targets.map((target) => target.close()));
  }
}

export function credibilityTruthManifest(targets: readonly Pick<Target, "id" | "language" | "framework">[]): BenchmarkManifest {
  const cases: BenchmarkTruthCase[] = [];
  for (const target of targets) for (const category of credibilityCategories) for (let index = 0; index < variantsPerCategory; index += 1) {
    const control = controlFor(index); const id = caseId(target.id, category, control, index); const positive = control === "vulnerable"; const workflowId = ["object", "function"].includes(category) ? "api-graphql-authorization" : !["authentication", "second-order"].includes(category) ? "active-vulnerability-validation" : "authentication-lifecycle";
    const categoryName = ({ object: "OBJECT_AUTHORIZATION", function: "FUNCTION_AUTHORIZATION", sql: "SQL_INJECTION", redirect: "OPEN_REDIRECT", authentication: "AUTHENTICATION_LIFECYCLE", "second-order": "SECOND_ORDER_STATE", "sql-boolean": "SQL_BOOLEAN_INJECTION", "sql-union": "SQL_UNION_INJECTION", nosql: "NOSQL_INJECTION", crlf: "CRLF_INJECTION", template: "TEMPLATE_INJECTION", traversal: "PATH_TRAVERSAL" } as const)[category];
    cases.push({ id, label: `${target.framework} ${category} ${control} mutant ${index}`, expected: positive ? "FINDING" : "NO_FINDING", selectors: [{ workflowId, caseId: id }], category: categoryName, tags: [target.language, target.framework, category, positive ? "positive" : control === "near-miss" ? "negative-control-near-miss" : "negative-control", "mutant"], language: target.language, framework: target.framework, weaknessId: weakness(category), control: positive ? "VULNERABLE" : control === "near-miss" ? "NEAR_MISS" : "SECURE", complexity: category === "authentication" ? "MULTI_STEP" : category === "second-order" ? "SECOND_ORDER" : "SINGLE_STEP", mutation: { lineage: `${target.id}/${category}/${positive ? "vulnerable" : "secure"}`, operator: mutationOperator(category, index), generation: index + 1 }, required: true });
  }
  return { schemaVersion: 1, id: "routecairn-public-credibility-corpus", label: "RouteCairn multi-language detection credibility corpus", description: "Versioned public corpus with executable positive, secure, near-miss, multi-step, second-order, and deterministic mutant cases across separate Node, Python HTTP/WSGI and Go implementations. These remain self-maintained behavior fixtures, not external acceptance evidence.", cases,
    thresholds: { minRecall: 1, maxFalsePositiveRate: 0, maxInconclusiveRate: 0, minCoverageCompleteness: 1, minRepetitions: 3, minCasesPerCategory: targets.length * variantsPerCategory, requireBalancedCategories: true, minCleanupObservationsPerRun: targets.length * variantsPerCategory * 2, maxCleanupFailures: 0, maxP95RuntimeMs: 900_000, maxPeakRssBytes: 2_500_000_000, maxRequestsPerAssessedCase: 8, minCorpusCases: cases.length, minPositiveCases: cases.length / 2, minNegativeCases: cases.length / 2, minLanguages: 3, minFrameworks: 4, minNearMissControls: cases.length / 4, minMultiStepCases: targets.length * variantsPerCategory, minSecondOrderCases: targets.length * variantsPerCategory, minMutantCases: cases.length, minYoudenIndex: 1, minCategories: 12, minStabilityRate: 1, minCategoryRecall: 1, maxCategoryFalsePositiveRate: 0, maxCategoryInconclusiveRate: 0 },
    regression: { maxRecallDrop: 0, maxFalsePositiveRateIncrease: 0, maxInconclusiveRateIncrease: 0, maxCoverageDrop: 0, maxYoudenIndexDrop: 0, maxRuntimeIncreaseRatio: 1, maxMemoryIncreaseRatio: 0.75, maxRequestIncreaseRatio: 0.2, failOnCaseRegression: true },
    corpus: { version: "2.0.0", publisher: "RouteCairn public benchmark laboratory", publishedAt: "2026-09-29T00:00:00.000Z", license: "MIT", independence: "SELF_MAINTAINED", blinded: false }, metadata: { fixture: true, deterministicMutants: true, externalTargetsTested: false, caseCount: cases.length } };
}

function apiInput(target: Target) {
  const routes: unknown[] = []; const checks: unknown[] = [];
  for (const category of ["object", "function"] as const) for (let index = 0; index < variantsPerCategory; index += 1) {
    const control = controlFor(index); const id = caseId(target.id, category, control, index); const routeId = `${id}-route`; const near = control === "near-miss";
    routes.push({ id: routeId, safeAlias: id, protocol: "REST", kind: category === "object" ? "OBJECT" : "FUNCTION", ...(category === "object" ? { objectType: "record", pathTemplate: `/object/{control}/{variant}` } : { functionName: `admin.read.${index}` }), url: `${target.origin}/${category === "function" ? "admin" : category}/${control}/v${String(index).padStart(2, "0")}`, documentedMethods: ["GET"] });
    checks.push({ id, matrixId: `${id}-matrix`, label: id, kind: category === "object" ? "OBJECT_AUTHORIZATION" : "FUNCTION_AUTHORIZATION", routeId, actorId: "foreign", requireVerifiedIdentity: false, request: { method: "GET" }, response: near ? { expectedDecision: "OBSERVE", fieldRules: [{ path: category === "object" ? "id" : "privileged", classification: category === "object" ? "OBJECT_IDENTITY" : "INTERNAL", expectation: "MUST_BE_ABSENT" }] } : { expectedDecision: "DENY" } });
  }
  return { schemaVersion: 1, maxRequests: 100, actors: [{ id: "foreign", safeAlias: "cross-tenant-member", authSlot: "primary", relationship: "CROSS_TENANT_MEMBER" }], routes, checks };
}

function activeInput(target: Target) {
  const cases: unknown[] = [];
  const families = ["sql", "sql-boolean", "sql-union", "redirect", "nosql", "crlf", "template", "traversal"] as const;
  const classes = { sql: "SQL_INJECTION", "sql-boolean": "SQL_INJECTION", "sql-union": "SQL_INJECTION", redirect: "OPEN_REDIRECT", nosql: "NOSQL_INJECTION", crlf: "CRLF_INJECTION", template: "TEMPLATE_INJECTION", traversal: "PATH_TRAVERSAL" };
  const techniques = { sql: "ERROR", "sql-boolean": "BOOLEAN", "sql-union": "UNION", redirect: "OAUTH_MIX_UP", nosql: "OPERATOR", crlf: "CRLF", template: "SECOND_ORDER", traversal: "PARSER_CANARY" };
  for (const category of families) for (let index = 0; index < variantsPerCategory; index += 1) {
    const control = controlFor(index); const id = caseId(target.id, category, control, index); const original = category === "redirect" ? "/home" : category === "traversal" ? "fixture.txt" : "fixture";
    const name = category === "redirect" ? "next" : "q"; const family = category === "sql" ? "search" : category;
    cases.push({ id, label: id, vulnerabilityClass: classes[category], actorId: "anonymous", environment: "LOCAL_FIXTURE", request: { url: `${target.origin}/${family}/${control}/v${String(index).padStart(2, "0")}?${name}=${encodeURIComponent(original)}`, method: "GET", headers: {}, injection: { location: "QUERY", name, originalValue: original }, operatorConfirmedNonMutating: false },
      proof: { allowedRedirectOrigins: [], secureStatuses: category === "template" || category === "traversal" ? [422] : [], vulnerableStatuses: [], ...(category === "nosql" ? { marker: "CORPUS_PRIVATE_DOCUMENT" } : category === "traversal" ? { marker: "CORPUS_PRIVATE_FILE" } : {}) },
      strategy: { techniques: [techniques[category]], encodings: ["PLAIN"], maxStrategies: 1, approvedRisks: ["PASSIVE_DIFFERENTIAL", ...(category === "template" ? ["STATEFUL_CANARY"] : [])] } });
  }
  return { schemaVersion: 1, maxRequests: 500, maxResponseBytes: 65_536, maxCases: Math.min(100, cases.length), actors: [{ id: "anonymous", safeAlias: "Anonymous", authSlot: "anonymous", relationship: "PUBLIC" }], discovery: { enabled: false, classes: [], maxCandidates: 0, queryParametersOnly: true, includeAuthenticated: false }, cases };
}

function lifecycleInput(target: Target) {
  const authorization = { mode: "CONTROLLED_LIFECYCLE", environment: "LOCAL", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "benchmark-operator", changeTicket: "CREDIBILITY-CORPUS", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), disposableAccounts: true };
  const actor = { id: "member", safeAlias: "benchmark-member", authSlot: "primary", relationship: "SELF", declaredState: "ACTIVE" }; const cases: unknown[] = [];
  for (let index = 0; index < variantsPerCategory; index += 1) {
    const control = controlFor(index); const variant = `v${String(index).padStart(2, "0")}`; const authId = caseId(target.id, "authentication", control, index); const knownStatus = control === "near-miss" ? 404 : 401;
    cases.push({ id: authId, label: authId, category: "LOGIN_ENUMERATION_RESISTANCE", actors: [actor], authorization, cleanupRequired: true, steps: [{ id: "known", phase: "ACTION", actorId: "member", request: { method: "POST", url: `${target.origin}/auth/${control}/${variant}/login`, stateChanging: true, bodyFormat: "FORM", fields: { username: "{{SECRET:known_username}}", password: "{{SECRET:password}}" } }, assertions: [{ kind: "STATUS_IN", values: [knownStatus] }] }, { id: "unknown", phase: "VERIFY", actorId: "member", request: { method: "POST", url: `${target.origin}/auth/${control}/${variant}/login`, stateChanging: true, bodyFormat: "FORM", fields: { username: "{{SECRET:unknown_username}}", password: "{{SECRET:password}}" } }, assertions: [{ kind: "RESPONSE_SIMILAR", stepId: "known", compareStatus: true, compareShape: true, compareBodyDigest: false, maxLengthDelta: 8 }] }, { id: "cleanup", phase: "CLEANUP", actorId: "member", request: { method: "POST", url: `${target.origin}/auth/${control}/${variant}/cleanup`, stateChanging: true }, assertions: [{ kind: "STATUS_IN", values: [204] }] }] });
    const secondId = caseId(target.id, "second-order", control, index);
    cases.push({ id: secondId, label: secondId, category: "EMAIL_VERIFICATION_BYPASS", actors: [actor], authorization, cleanupRequired: true, steps: [{ id: "stage", phase: "ACTION", actorId: "member", request: { method: "POST", url: `${target.origin}/second-order/${control}/${variant}/stage`, stateChanging: true, bodyFormat: "FORM", fields: { payload: "corpus-marker" } }, assertions: [{ kind: "STATUS_IN", values: [202] }] }, { id: "render", phase: "VERIFY", actorId: "member", request: { method: "GET", url: `${target.origin}/second-order/${control}/${variant}/render`, stateChanging: false }, assertions: [{ kind: "JSON_EQUALS", path: "safe", expected: true }] }, { id: "cleanup", phase: "CLEANUP", actorId: "member", request: { method: "DELETE", url: `${target.origin}/second-order/${control}/${variant}/cleanup`, stateChanging: true }, assertions: [{ kind: "STATUS_IN", values: [204] }] }] });
  }
  return { schemaVersion: 1, maxCases: cases.length, maxStepsPerCase: 4, maxRequests: 160, maxResponseBytes: 65_536, cases };
}

function mergeReports(reports: readonly RouteCairnReport[]): RouteCairnReport {
  const first = reports[0]; if (!first) throw new Error("BENCHMARK_REPORTS_REQUIRED"); const merged = { ...first, findings: reports.flatMap((item) => item.findings), discoveredUrls: reports.flatMap((item) => item.discoveredUrls), requestAudit: reports.flatMap((item) => item.requestAudit) } as unknown as Record<string, unknown>;
  mergeReportSection(merged, reports, "apiGraphql", ["checks", "schemaComparisons", "inventory"]); mergeReportSection(merged, reports, "activeVulnerability", ["cases", "coverage"]); mergeReportSection(merged, reports, "authenticationLifecycle", ["observations"]); return merged as unknown as RouteCairnReport;
}
function mergeReportSection(target: Record<string, unknown>, reports: readonly RouteCairnReport[], key: string, arrays: readonly string[]): void { const sections = reports.map((item) => (item as unknown as Record<string, unknown>)[key]).filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object")); if (!sections.length) return; const section = { ...sections[0] }; for (const name of arrays) section[name] = sections.flatMap((item) => Array.isArray(item[name]) ? item[name] as unknown[] : []); target[key] = section; }

async function startTargets(pythonCommand = process.env.ROUTECAIRN_PYTHON ?? "python", goCommand = process.env.ROUTECAIRN_GO ?? "go", directory: string): Promise<Target[]> {
  const targets: Target[] = [];
  try {
    targets.push(await startNodeTarget());
    targets.push(await startPythonTarget(pythonCommand));
    targets.push(await startPythonTarget(pythonCommand, true));
    const script = fileURLToPath(new URL("./fixtures/credibility-go.go", import.meta.url));
    const executable = join(directory, process.platform === "win32" ? "credibility-go.exe" : "credibility-go");
    await new Promise<void>((done, reject) => { const build = spawn(goCommand, ["build", "-o", executable, script], { stdio: "ignore", windowsHide: true, env: { ...process.env, GOTOOLCHAIN: "local" } }); const timer = setTimeout(() => { build.kill(); reject(new Error("BENCHMARK_GO_BUILD_TIMEOUT")); }, 120_000); build.once("error", (error) => { clearTimeout(timer); reject(error); }); build.once("exit", (code) => { clearTimeout(timer); code === 0 ? done() : reject(new Error("BENCHMARK_GO_BUILD_FAILED")); }); });
    const child = spawn(executable, [], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    try { const port = await readPythonPort(child); targets.push({ ...credibilityTargetMatrix[3], origin: `http://127.0.0.1:${port}`, reset: async () => { /* case cleanup is authoritative */ }, close: async () => closeChild(child) }); } catch (error) { await closeChild(child); throw error; }
    return targets;
  } catch (error) { await Promise.allSettled(targets.map((target) => target.close())); throw error; }
}

async function startNodeTarget(): Promise<Target> {
  const state = new Map<string, string>(); const server = createServer((request, response) => { void handleNode(request, response, state).catch(() => json(response, 400, { error: "invalid_request" })); }); await new Promise<void>((resolvePromise, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolvePromise(); }); });
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; return { id: "node-http", language: "TypeScript", framework: "node:http", origin, reset: async () => { state.clear(); }, close: async () => { state.clear(); server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done())); } };
}

async function handleNode(request: IncomingMessage, response: ServerResponse, state: Map<string, string>): Promise<void> {
  const url = new URL(request.url ?? "/", "http://127.0.0.1"); if (url.pathname === "/healthz") return json(response, 200, { status: "ready" }); const parts = url.pathname.split("/").filter(Boolean); if (parts.length < 3) return json(response, 404, { error: "not_found" });
  const [family, control, variant, operation] = parts as [string, Control, string, string | undefined]; const vulnerable = control === "vulnerable"; const near = control === "near-miss"; const variantIndex = Number(variant.replace(/^v/, "")) || 0;
  if (family === "object") return vulnerable ? json(response, 200, variantIndex % 2 ? { id: "tenant-a-object", tenantId: "tenant-a", record: { dialect: variantIndex } } : { id: "tenant-a-object", tenantId: "tenant-a", variant }) : near ? json(response, 200, variantIndex % 2 ? { kind: "public-help", record: { id: "documentation-example" } } : { kind: "public-help", variant }) : json(response, deniedStatus(variantIndex), { error: variantIndex % 2 ? "resource_hidden" : "forbidden" });
  if (family === "admin") return vulnerable ? json(response, 200, variantIndex % 2 ? { privileged: true, result: { dialect: variantIndex } } : { privileged: true, variant }) : near ? json(response, 200, variantIndex % 2 ? { kind: "public-capability-description", capability: { privileged: false } } : { kind: "public-capability-description", variant }) : json(response, deniedStatus(variantIndex), { error: variantIndex % 2 ? "capability_hidden" : "forbidden" });
  if (family === "search") { const injected = /['"]|%2[27]/i.test(url.search); return vulnerable && injected ? json(response, [400, 422, 500][variantIndex % 3]!, { error: sqlDialect(variantIndex) }) : json(response, 200, { matches: [], variant }); }
  if (["sql-boolean", "sql-union", "nosql", "crlf", "template", "traversal"].includes(family)) {
    const q = url.searchParams.get("q") ?? "fixture";
    if (family === "sql-boolean") return json(response, 200, { matches: vulnerable && q.includes("1'='2") ? [] : ["fixture"] });
    if (family === "sql-union") { const marker = /UNION SELECT '([^']+)'/i.exec(q)?.[1]; return json(response, 200, { matches: vulnerable && marker ? [marker] : [] }); }
    if (family === "nosql") { let operator = false; try { operator = typeof JSON.parse(q).$ne === "string"; } catch { /* scalar query */ } return json(response, 200, { matches: vulnerable && operator ? ["CORPUS_PRIVATE_DOCUMENT"] : [] }); }
    if (family === "crlf") { const header = /\r\nX-RouteCairn-Proof: ([A-Za-z0-9_]+)/.exec(q)?.[1]; if (vulnerable && header) response.setHeader("x-routecairn-proof", header); return json(response, 200, { accepted: true }); }
    if (family === "template") { if (!vulnerable && q.includes("{{")) return json(response, 422, { error: "literal_only", ...(near ? { example: q } : {}) }); return json(response, 200, { rendered: vulnerable ? q.replace("{{7*7}}", "49") : q }); }
    if (family === "traversal") { if (!vulnerable && q.includes("../")) return json(response, 422, { error: "path_rejected", ...(near ? { example: "../documentation.txt" } : {}) }); return json(response, 200, { content: vulnerable && q.includes("../") ? "CORPUS_PRIVATE_FILE" : "public file" }); }
  }
  if (family === "redirect") { response.writeHead([301, 302, 307, 308][variantIndex % 4]!, { location: vulnerable ? url.searchParams.get("next") ?? "/home" : near ? `https://routecairn.invalid.example/safe/${variantIndex}` : `/home?variant=${variantIndex}`, "content-length": "0" }).end(); return; }
  if (family === "auth" && operation === "login" && request.method === "POST") { const fields = new URLSearchParams(await requestBody(request)); const known = fields.get("username") === "known@benchmark.test"; if (vulnerable && !known) return json(response, 404, { error: "account_not_found", recovery: true }); return json(response, near ? 404 : 401, { error: "invalid_credentials" }); }
  if (family === "auth" && operation === "cleanup" && request.method === "POST") { response.writeHead(204).end(); return; }
  if (family === "second-order" && operation) { const key = `${control}:${variant}`; if (operation === "stage" && request.method === "POST") { state.set(key, new URLSearchParams(await requestBody(request)).get("payload") ?? ""); return json(response, 202, { accepted: true }); } if (operation === "render" && request.method === "GET") { const unsafe = vulnerable && Boolean(state.get(key)); return json(response, 200, { safe: !unsafe, rendered: unsafe ? "stored-value" : "encoded-value" }); } if (operation === "cleanup" && request.method === "DELETE") { state.delete(key); response.writeHead(204).end(); return; } }
  json(response, 404, { error: "not_found" });
}

async function startPythonTarget(command: string, wsgi = false): Promise<Target> {
  const script = fileURLToPath(new URL("./fixtures/credibility-python.py", import.meta.url)); const child = spawn(command, [script, ...(wsgi ? ["--wsgi"] : [])], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }); let port: number; try { port = await readPythonPort(child); } catch (error) { await closeChild(child); throw error; } const origin = `http://127.0.0.1:${port}`;
  return { id: wsgi ? "python-wsgi" : "python-http", language: "Python", framework: wsgi ? "wsgiref" : "http.server", origin, reset: async () => { /* every case cleanup is authoritative */ }, close: async () => closeChild(child) };
}
type FixtureChild = ChildProcessByStdio<null, Readable, Readable>;
async function readPythonPort(child: FixtureChild): Promise<number> { return new Promise((resolvePromise, reject) => { let stdout = ""; let stderr = ""; const timer = setTimeout(() => { cleanup(); child.kill(); reject(new Error("BENCHMARK_PYTHON_START_TIMEOUT")); }, 10_000); const cleanup = () => { clearTimeout(timer); child.stdout.off("data", onData); child.stderr.off("data", onError); child.off("error", fail); child.off("exit", exited); }; const fail = (error: Error) => { cleanup(); reject(error); }; const exited = () => fail(new Error(`BENCHMARK_PYTHON_EXITED:${stderr.slice(0, 240)}`)); const onError = (data: Buffer) => { stderr += data.toString("utf8"); }; const onData = (data: Buffer) => { stdout += data.toString("utf8"); const newline = stdout.indexOf("\n"); if (newline < 0) return; try { const value = JSON.parse(stdout.slice(0, newline)) as { port?: unknown }; if (!Number.isInteger(value.port) || Number(value.port) < 1) throw new Error(); cleanup(); resolvePromise(Number(value.port)); } catch { fail(new Error("BENCHMARK_PYTHON_PORT_INVALID")); } }; child.stdout.on("data", onData); child.stderr.on("data", onError); child.once("error", fail); child.once("exit", exited); }); }
async function closeChild(child: FixtureChild): Promise<void> { if (child.exitCode !== null) return; child.kill(); await Promise.race([once(child, "exit"), new Promise((resolvePromise) => setTimeout(resolvePromise, 2000))]); if (child.exitCode === null) child.kill("SIGKILL"); }

function controlFor(index: number): Control { return index < 6 ? "vulnerable" : index < 9 ? "secure" : "near-miss"; }
function caseId(target: string, category: string, control: Control, index: number): string { const targets: Record<string, string> = { "node-http": "nh", "python-http": "ph", "python-wsgi": "pw", "go-http": "gh" }; const categories: Record<string, string> = { object: "obj", function: "fn", sql: "sql", redirect: "red", authentication: "auth", "second-order": "so" }; const controls: Record<Control, string> = { vulnerable: "v", secure: "s", "near-miss": "n" }; return `${targets[target] ?? target.slice(0, 8)}-${categories[category] ?? category.slice(0, 8)}-${controls[control]}-${String(index).padStart(2, "0")}`; }
function weakness(category: string): string { return ({ object: "CWE-639", function: "CWE-862", sql: "CWE-89", redirect: "CWE-601", authentication: "CWE-204", "second-order": "CWE-116", "sql-boolean": "CWE-89", "sql-union": "CWE-89", nosql: "CWE-943", crlf: "CWE-113", template: "CWE-1336", traversal: "CWE-22" } as Record<string, string>)[category]!; }
function mutationOperator(category: string, index: number): string { const operators: Record<string, string[]> = { object: ["denial-status", "response-shape", "nested-public-lookalike"], function: ["denial-status", "capability-shape", "nested-boolean-lookalike"], sql: ["database-error-dialect", "error-status", "literal-canary-neutralization"], redirect: ["redirect-status", "origin-lookalike", "relative-location"], authentication: ["account-error-status", "response-shape", "equal-error-control"], "second-order": ["stored-value-encoding", "state-key-layout", "cleanup-path"] }; const values = operators[category] ?? ["route-layout"]; return values[index % values.length]!; }
function deniedStatus(index: number): number { return [401, 403, 404][index % 3]!; }
function sqlDialect(index: number): string { return ["SQL syntax error near corpus canary", "PostgreSQL error: unterminated quoted string", "MySQL warning: invalid query", "ORA-00933 corpus fixture", "SQLSTATE[42000] corpus fixture"][index % 5]!; }
async function requestBody(request: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)); return Buffer.concat(chunks).toString("utf8"); }
function json(response: ServerResponse, status: number, value: unknown): void { const payload = JSON.stringify(value); response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "content-length": Buffer.byteLength(payload) }).end(payload); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { await mkdir(directory, { recursive: true }); const path = join(directory, name); await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); return path; }
