import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";

let server: Server | undefined;
const tempDirs: string[] = [];

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => (error ? reject(error) : resolve()));
    });
    server = undefined;
  }
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("bulk authorization testing integration", () => {
  it("executes only fixed non-mutating bulk cases, flags prohibited supplied objects, and redacts evidence", async () => {
    const seen: string[] = [];
    const bodies: string[] = [];
    let publicHadAuth = false;
    server = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk: Buffer) => {
        body += chunk.toString("utf8");
      });
      request.on("end", () => {
        const cookie = String(request.headers.cookie ?? "");
        const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "viewer" : "public";
        if (actor === "public") publicHadAuth = Boolean(request.headers.cookie || request.headers.authorization || request.headers["x-csrf-token"] || request.headers["x-tenant-id"]);
        seen.push(`${actor}:${request.method}:${request.url}`);
        if (body) bodies.push(body);

        if (request.url === "/") return json(response, { ok: true });
        if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
        if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
        if (request.url === "/api/bulk/secure") return json(response, { preview: true, items: [projectA()], rejected: [{ id: "project-b-002" }] });
        if (request.url === "/api/bulk/vulnerable") return json(response, { preview: true, items: [projectA(), projectB(), { id: "unknown-999", privateName: "unknown secret" }], rejected: [] });
        if (request.url === "/api/bulk/unsafe") return json(response, { preview: true, jobId: "job-secret-123", items: [projectB()] }, 202);
        if (request.url === "/api/bulk/public?ids=project-public-003") return json(response, { preview: true, items: [projectPublic()] });
        response.writeHead(404).end();
      });
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-bulk-auth-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      bulkAuthorization: await writeJson(tempDir, "bulk.json", bulkInput(target))
    });

    const jsonText = await readFile(result.reportPath, "utf8");
    const markdownText = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      scanPlan: { modules: Array<{ id: string }>; bulkAuthorizationTesting?: { requestMatrix: Array<{ bodyHash?: string; body?: string; url: string }> } };
      identityVerification?: { accountA?: { verified: boolean }; accountB?: { verified: boolean } };
      bulkAuthorization?: {
        plannedRequests: number;
        executedRequests: number;
        confirmedIssues: number;
        observations: Array<{ caseId: string; actorId: string; observedDecision: string; findingCategory?: string; safetyContractSatisfied: boolean; matchedSuppliedObjects: number; unknownReturnedItemCount: number; bodyHash?: string; notes: string[] }>;
      };
      findings: Array<{ type: string; sourceModule: string; evidence: { curlCommand: string; source: string } }>;
      requestAudit: Array<{ requestedUrl: string; outcome: string; requestHeaders: Record<string, string>; requestBodyHash?: string }>;
    };

    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(["bulk-authorization-testing"]);
    expect(report.identityVerification?.accountA?.verified).toBe(true);
    expect(report.identityVerification?.accountB?.verified).toBe(true);
    expect(report.bulkAuthorization?.plannedRequests).toBe(4);
    expect(report.bulkAuthorization?.executedRequests).toBe(4);
    expect(publicHadAuth).toBe(false);
    expect(seen).toEqual(expect.arrayContaining([
      "public:GET:/",
      "owner:GET:/identity-a",
      "viewer:GET:/identity-b",
      "owner:POST:/api/bulk/secure",
      "viewer:POST:/api/bulk/vulnerable",
      "viewer:POST:/api/bulk/unsafe",
      "public:GET:/api/bulk/public?ids=project-public-003"
    ]));
    expect(seen.filter((entry) => entry.includes(":/api/bulk/"))).toEqual([
      "owner:POST:/api/bulk/secure",
      "viewer:POST:/api/bulk/vulnerable",
      "viewer:POST:/api/bulk/unsafe",
      "public:GET:/api/bulk/public?ids=project-public-003"
    ]);
    expect(seen.some((entry) => entry.includes("job-secret"))).toBe(false);
    expect(seen.some((entry) => entry.includes("page="))).toBe(false);
    expect(bodies).toHaveLength(3);
    expect(bodies.every((body) => body.includes('"dryRun":true'))).toBe(true);

    const secure = report.bulkAuthorization?.observations.find((observation) => observation.caseId === "secure-preview");
    const vulnerable = report.bulkAuthorization?.observations.find((observation) => observation.caseId === "vulnerable-preview");
    const unsafe = report.bulkAuthorization?.observations.find((observation) => observation.caseId === "unsafe-preview");
    const publicCase = report.bulkAuthorization?.observations.find((observation) => observation.caseId === "public-summary");
    expect(secure?.observedDecision).toBe("BULK_POLICY_SATISFIED");
    expect(vulnerable?.observedDecision).toBe("CROSS_TENANT_BULK_ACCESS");
    expect(vulnerable?.findingCategory).toBe("CROSS_TENANT_BULK_AUTHORIZATION_BYPASS");
    expect(vulnerable?.matchedSuppliedObjects).toBe(2);
    expect(vulnerable?.unknownReturnedItemCount).toBe(1);
    expect(unsafe?.observedDecision).toBe("ASYNCHRONOUS_OPERATION_DETECTED");
    expect(unsafe?.findingCategory).toBeUndefined();
    expect(publicCase?.observedDecision).toBe("BULK_POLICY_SATISFIED");
    expect(report.bulkAuthorization?.confirmedIssues).toBe(1);
    expect(report.findings.filter((finding) => finding.type === "Bulk Authorization Issue")).toHaveLength(1);
    expect(report.findings[0]?.sourceModule).toBe("bulk-authorization-testing");
    expect(report.findings[0]?.evidence.curlCommand).toContain("<redacted>");
    expect(report.requestAudit.some((entry) => entry.requestBodyHash)).toBe(true);

    for (const serialized of [jsonText, markdownText]) {
      expect(serialized).not.toContain("project-a-001");
      expect(serialized).not.toContain("project-b-002");
      expect(serialized).not.toContain("unknown-999");
      expect(serialized).not.toContain("bulk secret marker");
      expect(serialized).not.toContain("unknown secret");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
      expect(serialized).not.toContain('"objectIds":["project-a-001"');
    }
    expect(JSON.stringify(report.scanPlan.bulkAuthorizationTesting)).toContain("<object:");
    expect(JSON.stringify(report.scanPlan.bulkAuthorizationTesting)).not.toContain("project-a-001");
    expect(report.scanPlan.bulkAuthorizationTesting?.requestMatrix.every((testCase) => testCase.body === undefined || testCase.body.includes("<object:"))).toBe(true);
    expect(report.requestAudit.every((entry) => Object.values(entry.requestHeaders).every((value) => value !== "session=account-a" && value !== "session=account-b"))).toBe(true);
  });

  it("blocks verified metadata mismatches before the bulk request", async () => {
    const seen: string[] = [];
    server = createServer((request, response) => {
      seen.push(`${request.method}:${request.url}`);
      if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
      if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
      if (request.url === "/") return json(response, { ok: true });
      return json(response, { preview: true, items: [projectB()] });
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-bulk-auth-mismatch-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const input = bulkInput(target);
    input.definitions[0].cases[1].expectedTenantId = "tenant-a";
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      bulkAuthorization: await writeJson(tempDir, "bulk.json", input)
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { bulkAuthorization?: { observations: Array<{ caseId: string; observedDecision: string; notes: string[] }> } };
    const blocked = report.bulkAuthorization?.observations.find((observation) => observation.caseId === "vulnerable-preview");
    expect(blocked?.observedDecision).toBe("IDENTITY_REQUIREMENT_UNSATISFIED");
    expect(blocked?.notes.join(" ")).toContain("verified tenant metadata did not match");
    expect(seen).not.toContain("POST:/api/bulk/vulnerable");
  });

  it("does not promote declared-only protected object metadata to a confirmed finding", async () => {
    server = createServer((request, response) => {
      if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
      if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
      if (request.url === "/api/bulk/vulnerable") return json(response, { preview: true, items: [projectA(), projectB()] });
      return json(response, { ok: true });
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-bulk-auth-declared-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const input = bulkInput(target, false);
    input.definitions[0].cases = [input.definitions[0].cases[1]];
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      bulkAuthorization: await writeJson(tempDir, "bulk.json", input)
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { bulkAuthorization?: { confirmedIssues: number; observations: Array<{ observedDecision: string; findingCategory?: string }> }; findings: Array<{ type: string }> };
    expect(report.bulkAuthorization?.confirmedIssues).toBe(0);
    expect(report.bulkAuthorization?.observations[0]?.observedDecision).toBe("OBJECT_VERIFICATION_UNAVAILABLE");
    expect(report.bulkAuthorization?.observations[0]?.findingCategory).toBeUndefined();
    expect(report.findings.some((finding) => finding.type === "Bulk Authorization Issue")).toBe(false);
  });

  it("compares exact single-object denial baselines with secure and vulnerable bulk behaviour", async () => {
    const seen: string[] = [];
    server = createServer((request, response) => {
      seen.push(`${request.method}:${request.url}`);
      if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
      if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
      if (request.url === "/api/projects/project-b-002") {
        response.writeHead(403, { "content-type": "application/json" });
        response.end('{"error":"denied"}');
        return;
      }
      if (request.url === "/api/bulk/secure") return json(response, { preview: true, items: [projectA()], rejected: [{ id: "project-b-002" }] });
      if (request.url === "/api/bulk/vulnerable") return json(response, { preview: true, items: [projectA(), projectB()] });
      return json(response, { ok: true });
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-bulk-auth-baseline-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const input = baselineComparisonInput(target);
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      bulkAuthorization: await writeJson(tempDir, "bulk.json", input)
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      bulkAuthorization?: { observations: Array<{ caseId: string; findingCategory?: string; singleObjectComparison: string; objects: Array<{ objectIdHash: string; baselineDecision?: string; included: boolean }> }> };
      findings: Array<{ type: string; evidence: { source: string } }>;
    };
    const secure = report.bulkAuthorization?.observations.find((observation) => observation.caseId === "secure-with-baseline");
    const vulnerable = report.bulkAuthorization?.observations.find((observation) => observation.caseId === "vulnerable-with-baseline");
    expect(secure?.singleObjectComparison).toBe("COMPATIBLE_DENIAL");
    expect(secure?.findingCategory).toBeUndefined();
    expect(vulnerable?.singleObjectComparison).toBe("COMPATIBLE_DENIAL");
    expect(vulnerable?.findingCategory).toBe("BULK_SINGLE_OBJECT_AUTHORIZATION_INCONSISTENCY");
    expect(vulnerable?.objects.some((object) => object.baselineDecision === "DENIED_CONFIRMED" && object.included)).toBe(true);
    expect(report.findings.filter((finding) => finding.type === "Bulk Authorization Issue")).toHaveLength(1);
    expect(report.findings[0]?.evidence.source).toContain("exact supplied object");
    expect(seen.filter((entry) => entry.includes("/api/projects/project-b-002"))).toHaveLength(1);
    expect(seen.some((entry) => entry.includes("page=") || entry.includes("job"))).toBe(false);
  });

  it("prevents confirmed findings when configured POST postconditions detect state change", async () => {
    const seen: string[] = [];
    let state = "draft";
    server = createServer((request, response) => {
      seen.push(`${request.method}:${request.url}`);
      if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
      if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
      if (request.url === "/api/projects/project-b-002") return json(response, { id: "project-b-002", state });
      if (request.url === "/api/bulk/vulnerable") {
        state = "published";
        return json(response, { preview: true, items: [projectB()] });
      }
      return json(response, { ok: true });
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-bulk-auth-postcondition-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const input = postconditionInput(target);
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      bulkAuthorization: await writeJson(tempDir, "bulk.json", input)
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { bulkAuthorization?: { confirmedIssues: number; observations: Array<{ observedDecision: string; postconditionStatus: string; safetyContractSatisfied: boolean; findingCategory?: string; notes: string[] }> }; findings: Array<{ type: string }> };
    const observation = report.bulkAuthorization?.observations[0];
    expect(observation?.observedDecision).toBe("NON_MUTATING_CONTRACT_VIOLATED");
    expect(observation?.postconditionStatus).toBe("STATE_CHANGED");
    expect(observation?.safetyContractSatisfied).toBe(false);
    expect(observation?.findingCategory).toBeUndefined();
    expect(report.bulkAuthorization?.confirmedIssues).toBe(0);
    expect(report.findings.some((finding) => finding.type === "Bulk Authorization Issue")).toBe(false);
    expect(seen.filter((entry) => entry === "GET:/api/projects/project-b-002")).toHaveLength(2);
    expect(seen.some((entry) => entry.includes("rollback") || entry.includes("restore") || entry.includes("jobs"))).toBe(false);
  });
});

function bulkInput(target: string, trustedObjects = true) {
  return {
    schemaVersion: 1,
    maxDefinitions: 1,
    maxCasesPerDefinition: 4,
    maxObjectsPerCase: 3,
    maxRequests: 4,
    maxRetainedObservations: 8,
    definitions: [
      {
        id: "bulk-projects",
        label: "Bulk project preview",
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", safeAlias: "Owner", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active" },
          { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", safeAlias: "Viewer", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active" },
          { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
        ],
        cases: [
          bulkPostCase(target, "secure-preview", "owner", "/api/bulk/secure", trustedObjects),
          bulkPostCase(target, "vulnerable-preview", "viewer", "/api/bulk/vulnerable", trustedObjects),
          bulkPostCase(target, "unsafe-preview", "viewer", "/api/bulk/unsafe", trustedObjects),
          {
            id: "public-summary",
            actorId: "public",
            caseType: "PUBLIC_MIXED_VISIBILITY",
            requestStyle: "GET_COMMA_QUERY",
            method: "GET",
            url: new URL("/api/bulk/public?ids={{OBJECT_ID_LIST_COMMA}}", target).toString(),
            headers: { Accept: "application/json" },
            objects: [{ id: "public-object", objectId: "project-public-003", objectType: "project", expectedDecision: "ALLOW", tenantId: "tenant-a" }],
            expectedBatchPolicy: "MUST_ALLOW_ENTIRE_BATCH",
            requireVerifiedIdentity: false,
            safetyContract: { operationType: "SELECTION_SUMMARY", operatorConfirmedNonMutating: true, environment: "LOCAL_FIXTURE", requiredResponseMarkerPath: "preview", requiredResponseMarkerValue: true },
            responseContract: { type: "SUMMARY_ONLY", resultArrayPath: "items", resultObjectIdPath: "id" }
          }
        ]
      }
    ]
  };
}

function bulkPostCase(target: string, id: string, actorId: string, path: string, trustedObjects: boolean) {
  const verificationSource = trustedObjects ? "REUSE_VERIFIED_OBJECT_RESULT" : "DECLARED_ONLY";
  return {
    id,
    actorId,
    caseType: "MIXED_TENANT",
    requestStyle: "JSON_POST",
    method: "POST",
    url: new URL(path, target).toString(),
    headers: { Accept: "application/json" },
    bodyTemplate: { dryRun: true, operation: "preview", objectIds: "{{OBJECT_IDS_ARRAY}}" },
    objects: [
      { id: "owned", objectId: "project-a-001", objectType: "project", expectedDecision: "ALLOW", ownerActorId: "owner", tenantId: "tenant-a", verificationSource },
      { id: "foreign", objectId: "project-b-002", objectType: "project", expectedDecision: "FILTER_OUT", ownerActorId: "viewer", tenantId: "tenant-b", verificationSource }
    ],
    expectedBatchPolicy: "MUST_FILTER_UNAUTHORIZED_OBJECTS",
    requireVerifiedIdentity: true,
    expectedTenantId: actorId === "owner" ? "tenant-a" : "tenant-b",
    expectedRole: "member",
    expectedAccountState: "active",
    safetyContract: {
      operationType: "DRY_RUN",
      operatorConfirmedNonMutating: true,
      environment: "LOCAL_FIXTURE",
      requiredRequestMarkerPath: "dryRun",
      requiredRequestMarkerValue: true,
      requiredResponseMarkerPath: "preview",
      requiredResponseMarkerValue: true,
      disallowedResponsePaths: ["jobId", "taskId", "location"],
      disallowedStatusCodes: [201, 202]
    },
    responseContract: { type: "PREVIEW_OBJECT_LIST", resultArrayPath: "items", resultObjectIdPath: "id", rejectedArrayPath: "rejected", rejectedObjectIdPath: "id", metadataPaths: ["privateName"] }
  };
}

function baselineComparisonInput(target: string) {
  const input = bulkInput(target, true);
  input.definitions[0].cases = [
    bulkPostCase(target, "secure-with-baseline", "viewer", "/api/bulk/secure", true),
    { ...bulkPostCase(target, "vulnerable-with-baseline", "viewer", "/api/bulk/vulnerable", true), caseType: "REFERENCE_COMPARISON" }
  ];
  for (const testCase of input.definitions[0].cases) {
    testCase.objects[1].verificationSource = "SAFE_DETAIL_BASELINE";
    testCase.objects[1].baseline = {
      id: `${testCase.id}-foreign-baseline`,
      source: "SAFE_GET",
      actorId: "viewer",
      method: "GET",
      url: `${target}api/projects/{{OBJECT_ID}}`,
      headers: { Accept: "application/json" },
      expectedDecision: "MUST_DENY",
      requireVerifiedIdentity: true,
      objectIdentityField: "id",
      expectedTenantId: "tenant-b",
      expectedRole: "member"
    };
  }
  return input;
}

function postconditionInput(target: string) {
  const input = bulkInput(target, true);
  input.definitions[0].cases = [{ ...bulkPostCase(target, "postcondition-state-change", "viewer", "/api/bulk/vulnerable", true), caseType: "REFERENCE_COMPARISON" }];
  input.definitions[0].cases[0].postSafetyMode = "POSTCONDITION_VERIFIED_DRY_RUN";
  input.definitions[0].cases[0].postconditionChecks = [
    {
      id: "foreign-object-state",
      actorId: "viewer",
      objectId: "project-b-002",
      method: "GET",
      url: `${target}api/projects/{{OBJECT_ID}}`,
      headers: { Accept: "application/json" },
      objectIdentityField: "id",
      objectStateField: "state",
      fields: [{ path: "state", expectedValue: "draft" }],
      requireVerifiedIdentity: true,
      expectedTenantId: "tenant-b",
      expectedRole: "member"
    }
  ];
  return input;
}

function projectA() {
  return { id: "project-a-001", tenant: "tenant-a", privateName: "bulk secret marker" };
}

function projectB() {
  return { id: "project-b-002", tenant: "tenant-b", privateName: "bulk secret marker" };
}

function projectPublic() {
  return { id: "project-public-003", tenant: "tenant-a" };
}

function authProfile(label: string, principalId: string, tenantId: string, endpoint: string) {
  return {
    label,
    safeAlias: label,
    principalId,
    tenantId,
    role: "member",
    accountState: "active",
    headers: { Cookie: `session=${label}` },
    identityVerification: {
      mode: "required",
      endpoint,
      method: "GET",
      principalIdField: "id",
      tenantIdField: "tenant",
      roleField: "role",
      accountStateField: "state"
    }
  };
}

function json(response: Parameters<NonNullable<Parameters<typeof createServer>[0]>>[1], value: unknown, statusCode = 200): void {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

async function writeScope(tempDir: string): Promise<string> {
  return writeJson(tempDir, "scope.json", {
    ...exampleScope,
    allowedDomains: ["127.0.0.1"],
    allowedMethods: ["GET", "POST"],
    disallowedPaths: [],
    rateLimitPerSecond: 50,
    concurrency: 2,
    userAgent: "RouteCairn/Test"
  });
}

async function writeJson(tempDir: string, name: string, value: unknown): Promise<string> {
  const path = join(tempDir, name);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return path;
}

function listen(targetServer: Server): Promise<void> {
  return new Promise((resolve) => {
    targetServer.listen(0, "127.0.0.1", resolve);
  });
}
