import { afterEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { ApiGraphqlReviewReport } from "../../src/reports/ApiGraphqlReport.js";

let server: Server | undefined; const directories: string[] = [];
afterEach(async () => { if (server) await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve())); server = undefined; await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("API and GraphQL authorization integration", () => {
  it("executes route, authorization, method, GraphQL, schema, exposure, tenant, and version checks through the CLI", async () => {
    const receivedBodies: string[] = [];
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/openapi.json") return json(response, 200, { openapi: "3.1.0", paths: { "/api/v1/accounts/{id}": { get: {}, head: {}, options: {} } } });
      if (request.url === "/api/v1/accounts/object-1") {
        if (request.method === "HEAD" || request.method === "OPTIONS") return void response.writeHead(403).end();
        return json(response, 200, { id: "object-1", tenantId: "org-alpha-private-4471", email: "owner@example.test" });
      }
      if (request.url === "/api/v2/accounts/object-1") return json(response, 200, { id: "object-1", tenantId: "org-alpha-private-4471", email: "owner@example.test", internalDebug: true });
      if (request.url === "/api/admin/summary") return json(response, 200, { total: 1 });
      if (request.url === "/graphql" && request.method === "POST") {
        const raw = await body(request); receivedBodies.push(raw); const parsed = JSON.parse(raw) as unknown;
        if (Array.isArray(parsed)) return json(response, 200, [{ data: { viewer: { id: "account-a" } } }, { errors: [{ message: "batch disabled" }] }]);
        const query = String((parsed as Record<string, unknown>).query ?? "");
        if (query.includes("__schema")) return json(response, 200, { errors: [{ message: "introspection disabled" }] });
        if (query.includes("first:") && query.includes("second:")) return json(response, 200, { data: { first: { id: "account-a" }, second: { id: "account-a" } } });
        return json(response, 200, { data: { viewer: { id: "account-b", tenantId: "org-alpha-private-4471", email: "foreign@example.test", recoveryCodes: ["raw-code-must-not-persist"] } } });
      }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-api-graphql-")); directories.push(directory);
    const scope = await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"], rateLimitPerSecond: 50, concurrency: 4 });
    const authA = await writeJson(directory, "auth-a.json", { label: "account-a", safeAlias: "account-a", principalId: "account-a", tenantId: "org-alpha-private-4471", headers: { Authorization: "Bearer api-secret-a" }, lifecycleSecrets: { object_id: "object-1" } });
    const authB = await writeJson(directory, "auth-b.json", { label: "account-b", safeAlias: "account-b", principalId: "account-b", tenantId: "org-beta-private-9928", headers: { Authorization: "Bearer api-secret-b" }, lifecycleSecrets: { object_id: "object-1" } });
    const manifest = await writeJson(directory, "api-graphql.json", manifestFor(origin));
    const result = await runScanCommand(`${origin}/`, { scope, authA, authB, apiGraphql: manifest, output: join(directory, "reports") });
    const text = await readFile(result.reportPath, "utf8"); const markdown = await readFile(result.markdownReportPath, "utf8"); const html = await readFile(result.htmlReportPath, "utf8"); const report = JSON.parse(text) as { apiGraphql: ApiGraphqlReviewReport; findings: Array<{ type: string }> };
    expect(report.apiGraphql).toMatchObject({ enabled: true, plannedChecks: 9, executedChecks: 9, passedChecks: 2, failedChecks: 7, blockedChecks: 0, inventory: expect.any(Array), requestsTransmitted: 13, requestBudget: 30, objectAuthorizationChecks: 1, functionAuthorizationChecks: 1, fieldAuthorizationChecks: 1, tenantIsolationChecks: 1, methodConfusionChecks: 1, introspectionChecks: 1, aliasLimitChecks: 1, batchLimitChecks: 1, versionBoundaryChecks: 1 });
    expect(report.apiGraphql.inventory).toHaveLength(5); expect(report.apiGraphql.authorizationMatrices).toHaveLength(4); expect(report.apiGraphql.schemaComparisons).toEqual(expect.arrayContaining([expect.objectContaining({ routeId: "object-v1", outcome: "PASS" }), expect.objectContaining({ routeId: "object-v2", outcome: "FAIL" })]));
    expect(report.apiGraphql.checks.find((value) => value.checkId === "field-check")).toMatchObject({ outcome: "FAIL", reasonCode: "RESPONSE_FIELD_EXPOSURE" });
    expect(report.apiGraphql.checks.find((value) => value.checkId === "tenant-check")).toMatchObject({ outcome: "FAIL", reasonCode: "TENANT_ISOLATION_MISMATCH", tenantBoundaryConfirmed: false });
    expect(report.apiGraphql.checks.find((value) => value.checkId === "introspection-check")).toMatchObject({ outcome: "PASS", introspectionClassification: "RESTRICTED" });
    expect(report.apiGraphql.checks.find((value) => value.checkId === "batch-check")).toMatchObject({ outcome: "FAIL", reasonCode: "GRAPHQL_LIMIT_NOT_ENFORCED" });
    expect(report.apiGraphql.checks.find((value) => value.checkId === "version-check")?.requests[1]).toMatchObject({ documentedFieldsPresent: 3, documentedFieldsMissing: 0, undocumentedFieldsObserved: 1 });
    expect(report.findings.map((value) => value.type)).toEqual(expect.arrayContaining(["API Authorization Issue", "API Method Confusion", "GraphQL Authorization Issue", "GraphQL Limit Issue", "API Version Boundary Issue", "API Schema Drift"]));
    expect(markdown).toContain("## API and GraphQL Authorization"); expect(html).toContain("apiGraphql"); expect(receivedBodies.length).toBe(5);
    for (const secret of ["api-secret-a", "api-secret-b", "raw-code-must-not-persist", "owner@example.test", "foreign@example.test", "org-alpha-private-4471", "org-beta-private-9928"]) for (const output of [text, markdown, html]) expectSecretAbsent(output, secret);
  }, 30_000);
});

function manifestFor(origin: string): unknown {
  const actors = [{ id: "anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" }, { id: "owner", safeAlias: "owner", authSlot: "account_a", relationship: "OWNER", principalId: "account-a", tenantId: "org-alpha-private-4471" }, { id: "foreign", safeAlias: "foreign", authSlot: "account_b", relationship: "CROSS_TENANT_MEMBER", principalId: "account-b", tenantId: "org-beta-private-9928" }];
  const routes = [{ id: "schema", safeAlias: "schema", protocol: "REST", kind: "SCHEMA", url: `${origin}/openapi.json`, documentedMethods: ["GET"], inventoryActorId: "anonymous" }, { id: "object-v1", safeAlias: "object-v1", protocol: "REST", kind: "OBJECT", objectType: "account", version: "v1", url: `${origin}/api/v1/accounts/object-1`, pathTemplate: "/api/v1/accounts/{id}", documentedMethods: ["GET", "HEAD", "OPTIONS"], documentedResponseFields: ["id", "tenantId", "email"], schemaSourceId: "schema", schemaPath: "/api/v1/accounts/{id}" }, { id: "object-v2", safeAlias: "object-v2", protocol: "REST", kind: "OBJECT", objectType: "account", version: "v2", url: `${origin}/api/v2/accounts/object-1`, pathTemplate: "/api/v2/accounts/{id}", documentedMethods: ["GET"], documentedResponseFields: ["id", "tenantId", "email"], schemaSourceId: "schema", schemaPath: "/api/v2/accounts/{id}" }, { id: "admin", safeAlias: "admin", protocol: "REST", kind: "FUNCTION", functionName: "admin.summary", url: `${origin}/api/admin/summary`, documentedMethods: ["GET"] }, { id: "graphql", safeAlias: "graphql", protocol: "GRAPHQL", kind: "FUNCTION", functionName: "graphql.query", url: `${origin}/graphql`, documentedMethods: ["POST"] }];
  const response = (expectedDecision: "ALLOW" | "DENY") => ({ expectedDecision });
  const graphql = (operationName: string, document: string) => ({ method: "POST", graphql: { operationName, document, variables: {} } });
  const checks = [
    { id: "object-check", matrixId: "object-access", label: "foreign object denied", kind: "OBJECT_AUTHORIZATION", routeId: "object-v1", actorId: "foreign", requireVerifiedIdentity: false, request: { method: "GET" }, response: response("DENY") },
    { id: "function-check", matrixId: "admin-function-access", label: "member admin denied", kind: "FUNCTION_AUTHORIZATION", routeId: "admin", actorId: "foreign", requireVerifiedIdentity: false, request: { method: "GET" }, response: response("DENY") },
    { id: "method-check", label: "method policy", kind: "METHOD_CONFUSION", routeId: "object-v1", actorId: "foreign", requireVerifiedIdentity: false, canonicalMethod: "GET", alternateMethods: ["HEAD", "OPTIONS"], expectation: "MUST_MATCH_CANONICAL", request: {} },
    { id: "field-check", matrixId: "graphql-field-access", label: "GraphQL secret field denied", kind: "FIELD_AUTHORIZATION", routeId: "graphql", actorId: "foreign", requireVerifiedIdentity: false, request: graphql("ViewerFields", "query ViewerFields { viewer { id email recoveryCodes } }"), response: { expectedDecision: "ALLOW", fieldRules: [{ path: "data.viewer.recoveryCodes", classification: "SECRET", expectation: "MUST_BE_ABSENT" }] } },
    { id: "tenant-check", matrixId: "graphql-tenant-access", label: "GraphQL tenant isolated", kind: "TENANT_ISOLATION", routeId: "graphql", actorId: "foreign", requireVerifiedIdentity: false, request: graphql("ViewerTenant", "query ViewerTenant { viewer { id tenantId } }"), response: { expectedDecision: "ALLOW", tenant: { path: "data.viewer.tenantId", expectedValue: "org-beta-private-9928", forbiddenValues: ["org-alpha-private-4471"] } } },
    { id: "introspection-check", label: "introspection restricted", kind: "GRAPHQL_INTROSPECTION", routeId: "graphql", actorId: "anonymous", requireVerifiedIdentity: false, expectedClassification: "RESTRICTED" },
    { id: "alias-check", label: "aliases bounded", kind: "GRAPHQL_ALIAS_LIMIT", routeId: "graphql", actorId: "owner", requireVerifiedIdentity: false, operationCount: 2, documents: [{ operationName: "Aliases", document: "query Aliases { first: viewer { id } second: viewer { id } }", variables: {} }], expectation: "MUST_ALLOW" },
    { id: "batch-check", label: "batch rejected", kind: "GRAPHQL_BATCH_LIMIT", routeId: "graphql", actorId: "owner", requireVerifiedIdentity: false, operationCount: 2, documents: [{ operationName: "A", document: "query A { viewer { id } }", variables: {} }, { operationName: "B", document: "query B { viewer { id } }", variables: {} }], expectation: "MUST_REJECT" },
    { id: "version-check", label: "version field boundary", kind: "VERSION_BOUNDARY", baselineRouteId: "object-v1", candidateRouteId: "object-v2", actorId: "owner", requireVerifiedIdentity: false, request: { method: "GET" }, expectation: "CANDIDATE_MUST_NOT_EXPOSE_MORE_FIELDS" }
  ];
  return { schemaVersion: 1, maxRequests: 30, maxGraphqlAliases: 3, maxGraphqlBatchOperations: 3, actors, routes, checks };
}

function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); }
async function body(request: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks).toString("utf8"); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, JSON.stringify(value)); return path; }
function expectSecretAbsent(output: string, secret: string): void { const index = output.indexOf(secret); expect(index < 0, index < 0 ? undefined : `Found ${secret} near: ${output.slice(Math.max(0, index - 100), index + secret.length + 100)}`).toBe(true); }
