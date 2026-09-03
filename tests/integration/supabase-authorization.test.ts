import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";

let server: Server | undefined;
const temporaryDirectories: string[] = [];
const anonEnv = "ROUTECAIRN_SUPABASE_TEST_ANON";
const serviceEnv = "ROUTECAIRN_SUPABASE_TEST_SERVICE";

afterEach(async () => {
  delete process.env[anonEnv];
  delete process.env[serviceEnv];
  if (server) await new Promise<void>((resolve, reject) => server?.close((error) => error ? reject(error) : resolve()));
  server = undefined;
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("Supabase authorization integration", () => {
  it("verifies actor, RLS, sensitive-column, storage, signed URL, RPC, relationship, and service-role boundaries without leaking credentials", async () => {
    const seen: Array<{ url: string; apikey?: string; authorization?: string; cookie?: string }> = [];
    let disposableRole = "user";
    server = createServer(async (request, response) => {
      const url = request.url ?? "";
      if (url === "/") { response.writeHead(200, { "content-type": "text/html" }).end("ok"); return; }
      seen.push({ url, ...(request.headers.apikey ? { apikey: String(request.headers.apikey) } : {}), ...(request.headers.authorization ? { authorization: String(request.headers.authorization) } : {}), ...(request.headers.cookie ? { cookie: String(request.headers.cookie) } : {}) });
      const cookie = String(request.headers.cookie ?? "");
      const authorization = String(request.headers.authorization ?? "");
      const isA = cookie.includes("account-a");
      const isB = cookie.includes("account-b");
      const isService = authorization.includes("service-secret-value");
      response.setHeader("content-type", "application/json");
      if (url.includes("disposable-mut") && request.method === "PATCH") {
        const body = JSON.parse(await requestBody(request)) as { role?: string };
        if (body.role) disposableRole = body.role;
        response.writeHead(200).end(JSON.stringify({ id: "disposable-mut", role: disposableRole }));
        return;
      }
      if (url.includes("disposable-mut")) { response.writeHead(200).end(JSON.stringify({ id: "disposable-mut", role: disposableRole })); return; }
      if (url.startsWith("/rest/v1/documents")) {
        if (isA || isB || isService) response.writeHead(200).end(JSON.stringify([{ id: "doc-private-a", owner_id: "account-a", tenant_id: "tenant-a" }]));
        else response.writeHead(200).end("[]");
        return;
      }
      if (url.startsWith("/rest/v1/profiles")) { response.writeHead(200).end(JSON.stringify([{ id: "public-profile", secret_token: "must-never-reach-report" }])); return; }
      if (url.startsWith("/rest/v1/accounts")) { response.writeHead(200).end(JSON.stringify([{ id: "doc-private-a", owner: { id: "account-a", private_email: "hidden@example.test" } }])); return; }
      if (url.startsWith("/storage/v1/object/private-files")) { response.writeHead(200).end(JSON.stringify({ id: "doc-private-a", bucket: "private-files" })); return; }
      if (url === "/storage/v1/object/sign/private-files/doc-private-a") { response.writeHead(200).end(JSON.stringify({ signedURL: `http://127.0.0.1:${(server?.address() as AddressInfo).port}/signed/private-files/doc-private-a?token=signed-secret` })); return; }
      if (url.startsWith("/rpc/admin_export")) { response.writeHead(403).end('{"message":"denied"}'); return; }
      response.writeHead(404).end('{}');
    });
    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const target = `http://127.0.0.1:${port}/`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-supabase-"));
    temporaryDirectories.push(directory);
    process.env[anonEnv] = jwt("anon");
    process.env[serviceEnv] = "service-secret-value";
    const result = await runScanCommand(target, {
      scope: await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "DELETE"], rateLimitPerSecond: 50, concurrency: 2 }),
      output: join(directory, "reports"),
      authA: await writeJson(directory, "a.json", auth("account-a")),
      authB: await writeJson(directory, "b.json", auth("account-b")),
      supabaseAuthorization: await writeJson(directory, "supabase.json", manifest(target)),
      mutationContracts: await writeJson(directory, "mutations.json", [mutationContract(target, process.env[anonEnv]!)])
    });
    const jsonText = await readFile(result.reportPath, "utf8");
    const markdownText = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      scanPlan: { modules: Array<{ id: string }>; supabaseAuthorization: { cases: Array<{ url: string; identityAssertions: Array<{ expectedValue: string }> }> } };
      supabaseAuthorization: import("../../src/reports/SupabaseAuthorizationReport.js").SupabaseAuthorizationReport;
      findings: Array<{ type: string; sourceModule: string }>;
      requestAudit: Array<{ requestHeaders: Record<string, string>; requestedUrl: string }>;
    };

    expect(report.scanPlan.modules.map((item) => item.id)).toEqual(["supabase-authorization"]);
    expect(report.supabaseAuthorization.plannedCases).toBe(10);
    expect(report.supabaseAuthorization.anonKeyClassification).toBe("ANON_JWT");
    expect(report.supabaseAuthorization.serviceRoleBoundaryVerified).toBe(true);
    expect(report.supabaseAuthorization.coverage).toMatchObject({ tableRead: true, tableUpdate: true, crossUser: true, crossTenant: true, sensitiveColumns: true, storage: true, signedUrls: true, rpc: true, relationships: true, accountPair: true, serviceRole: true });
    expect(report.supabaseAuthorization.resourceCoverage.find((item) => item.resource === "public.documents")?.actors).toEqual(expect.arrayContaining(["ANONYMOUS", "ACCOUNT_A", "ACCOUNT_B", "SERVICE_ROLE"]));
    expect(report.supabaseAuthorization.observations.find((item) => item.caseId === "cross-user-b")?.findingCategory).toBe("CROSS_USER_ACCESS");
    expect(report.supabaseAuthorization.observations.find((item) => item.caseId === "cross-tenant-b")?.findingCategory).toBe("CROSS_TENANT_ACCESS");
    expect(report.supabaseAuthorization.observations.find((item) => item.caseId === "sensitive-anon")?.findingCategory).toBe("SENSITIVE_COLUMN_EXPOSURE");
    expect(report.supabaseAuthorization.observations.find((item) => item.caseId === "storage-cross-tenant")?.findingCategory).toBe("CROSS_TENANT_ACCESS");
    expect(report.supabaseAuthorization.observations.find((item) => item.caseId === "signed-url-anon")?.findingCategory).toBe("SIGNED_URL_BOUNDARY_BYPASS");
    expect(report.supabaseAuthorization.observations.find((item) => item.caseId === "rpc-anon")?.matchedExpectation).toBe(true);
    expect(report.supabaseAuthorization.observations.find((item) => item.caseId === "update-cross-user")?.observedDecision).toBe("MUTATION_PROVEN");
    expect(disposableRole).toBe("user");
    expect(report.findings.some((item) => item.type === "Supabase Authorization Issue" && item.sourceModule === "supabase-authorization")).toBe(true);
    expect(seen.some((item) => item.apikey === process.env[anonEnv])).toBe(true);
    expect(seen.some((item) => item.authorization === "Bearer service-secret-value")).toBe(true);
    for (const serialized of [jsonText, markdownText]) {
      expect(serialized).not.toContain(process.env[anonEnv]!);
      expect(serialized).not.toContain("service-secret-value");
      expect(serialized).not.toContain("must-never-reach-report");
      expect(serialized).not.toContain("doc-private-a");
      expect(serialized).not.toContain("signed-secret");
    }
    expect(report.requestAudit.every((entry) => Object.values(entry.requestHeaders).every((value) => value === "<redacted>" || !value.includes("secret")))).toBe(true);
    expect(JSON.stringify(report.scanPlan.supabaseAuthorization.cases)).toContain("%3Credacted%3E");
    expect(report.scanPlan.supabaseAuthorization.cases[0]?.identityAssertions[0]?.expectedValue).toBe("<redacted>");
  });
});

function manifest(target: string) {
  const url = (path: string) => new URL(path, target).toString();
  const read = (id: string, actor: string, expectedDecision: string, boundary: string) => ({ id, surface: "TABLE", resource: "public.documents", operation: "SELECT", actor, expectedDecision, boundary, method: "GET", url: url("/rest/v1/documents?id=eq.doc-private-a"), responseShape: "LIST", identityAssertions: [{ path: "id", equals: "doc-private-a" }], requireVerifiedIdentity: false });
  return {
    schemaVersion: 1, projectUrl: target, anonKeyEnv: anonEnv, serviceRoleKeyEnv: serviceEnv,
    cases: [
      read("anon-deny", "ANONYMOUS", "DENY", "NONE"),
      read("owner-a", "ACCOUNT_A", "ALLOW", "NONE"),
      read("cross-user-b", "ACCOUNT_B", "DENY", "CROSS_USER"),
      { ...read("cross-tenant-b", "ACCOUNT_B", "DENY", "CROSS_TENANT"), surface: "RELATIONSHIP", resource: "documents_owner", url: url("/rest/v1/accounts?select=id,owner(id,private_email)&id=eq.doc-private-a") },
      read("service-allow", "SERVICE_ROLE", "ALLOW", "SERVICE_ROLE"),
      { id: "sensitive-anon", surface: "TABLE", resource: "public.profiles", operation: "SELECT", actor: "ANONYMOUS", expectedDecision: "OBSERVE_ONLY", method: "GET", url: url("/rest/v1/profiles?id=eq.public-profile"), identityAssertions: [{ path: "id", equals: "public-profile" }], forbiddenColumns: ["secret_token"], requireVerifiedIdentity: false },
      { id: "storage-cross-tenant", surface: "STORAGE", resource: "private-files", operation: "SELECT", actor: "ACCOUNT_B", expectedDecision: "DENY", boundary: "CROSS_TENANT", method: "GET", url: url("/storage/v1/object/private-files/doc-private-a"), responseShape: "SINGLE", identityAssertions: [{ path: "id", equals: "doc-private-a" }], requireVerifiedIdentity: false },
      { id: "signed-url-anon", surface: "STORAGE", resource: "private-files", operation: "SIGNED_URL", actor: "ANONYMOUS", expectedDecision: "DENY", method: "GET", url: url("/storage/v1/object/sign/private-files/doc-private-a"), responseShape: "SINGLE", requireVerifiedIdentity: false, signedUrl: { responseField: "signedURL", allowedOrigins: [new URL(target).origin], expectedPathContains: "/signed/private-files/doc-private-a", followOnce: false } },
      { id: "rpc-anon", surface: "RPC", resource: "public.admin_export", operation: "INVOKE", actor: "ANONYMOUS", expectedDecision: "DENY", method: "GET", url: url("/rpc/admin_export"), requireVerifiedIdentity: false },
      { id: "update-cross-user", surface: "TABLE", resource: "public.documents", operation: "UPDATE", actor: "ACCOUNT_B", expectedDecision: "DENY", boundary: "CROSS_USER", method: "PATCH", url: url("/rest/v1/documents?id=eq.disposable-mut"), responseShape: "VOID", requireVerifiedIdentity: false, mutationContractCaseId: "supabase-update-cross-user" }
    ],
    maxCases: 20,
    catalog: { exposedSchemas: ["public"], expectedExposedSchemas: ["public"], tables: [{ schema: "public", name: "documents", exposed: true, rlsEnabled: true, rlsForced: true, ownerColumn: "owner_id", tenantColumn: "tenant_id" }], functions: [{ schema: "public", name: "admin_export", exposed: true, securityDefiner: true, executableBy: ["authenticated"], searchPath: ["pg_catalog"], usesDynamicSql: false }], storageBuckets: [{ name: "private-files", public: false, ownershipEnforced: true }], relationships: [{ name: "documents_owner", from: "public.documents", to: "public.documents", exposed: true }] }
  };
}

function auth(label: string) { return { label, safeAlias: label, headers: { Cookie: `session=${label}` }, identityVerification: { mode: "disabled" } }; }
function jwt(role: string): string { return `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(JSON.stringify({ role })).toString("base64url")}.signature`; }
function mutationContract(target: string, anonKey: string) {
  const endpoint = new URL("/rest/v1/documents?id=eq.disposable-mut", target).toString();
  const headers = { "content-type": "application/json", Cookie: "session=account-b", apikey: anonKey };
  return {
    schemaVersion: 1, caseId: "supabase-update-cross-user", targetOrigin: new URL(target).origin, mode: "CONTROLLED_MUTATION", environment: "TEST", productionAcknowledged: false,
    authorization: { authorizedBy: "routecairn-test", changeTicket: "TEST-1", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" },
    target: { disposable: true, type: "document", alias: "disposable-document", identityFingerprint: createHash("sha256").update(JSON.stringify("disposable-mut")).digest("hex"), identityAssertion: { path: "id", operator: "EQUALS", expectedValue: "disposable-mut" } },
    attack: { request: { url: endpoint, method: "PATCH", headers, body: '{"role":"admin"}' }, allowedFields: ["role"], allowedValues: { role: ["admin"] }, semanticEffect: "UPDATE_EXISTING" },
    precondition: { request: { url: endpoint, method: "GET", headers }, assertions: [{ path: "id", operator: "EQUALS", expectedValue: "disposable-mut" }, { path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 },
    impact: { request: { url: endpoint, method: "GET", headers }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }], attempts: 1, delayMs: 0 },
    rollback: { request: { url: endpoint, method: "PATCH", headers, body: '{"role":"user"}' }, verification: { request: { url: endpoint, method: "GET", headers }, matchPreStateHash: true, attempts: 1, delayMs: 0 } }
  };
}
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8"); return path; }
function listen(targetServer: Server): Promise<void> { return new Promise((resolve) => targetServer.listen(0, "127.0.0.1", resolve)); }
function requestBody(request: import("node:http").IncomingMessage): Promise<string> { return new Promise((resolve, reject) => { const chunks: Buffer[] = []; request.on("data", (chunk: Buffer) => chunks.push(chunk)); request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8"))); request.on("error", reject); }); }
