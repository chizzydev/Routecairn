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

describe("collection authorization testing integration", () => {
  it("detects an explicitly supplied foreign object in a vulnerable collection without pagination, ID harvesting, or auth leakage", async () => {
    const seen: string[] = [];
    let publicHadAuth = false;
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" }).end("ok");
        return;
      }
      const cookie = String(request.headers.cookie ?? "");
      const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "viewer" : "public";
      if (actor === "public") publicHadAuth = Boolean(request.headers.cookie || request.headers.authorization || request.headers["x-csrf-token"] || request.headers["x-tenant-id"]);
      seen.push(`${actor}:${request.method}:${request.url}`);

      if (request.url === "/identity-a") return json(response, { id: "principal-a", tenant: "tenant-a", role: "member", state: "active" });
      if (request.url === "/identity-b") return json(response, { id: "principal-b", tenant: "tenant-b", role: "member", state: "active" });
      if (request.url === "/api/projects?status=active") {
        const items = actor === "owner" ? [projectA(), projectPublic(), extraProject()] : actor === "viewer" ? [projectPublic()] : [projectPublic()];
        return json(response, { items, count: items.length, summary: { privateProjects: 0 } });
      }
      if (request.url === "/api/projects-vulnerable?status=active") {
        const items = actor === "public" ? [projectA(), projectPublic()] : [projectA(), projectPublic(), extraProject()];
        return json(response, { items, count: items.length, summary: { privateProjects: actor === "public" ? 1 : 2 }, next: "/api/projects-vulnerable?page=2" });
      }
      if (request.url === "/api/projects-complete-but-truncated?status=active") {
        return json(response, { items: [projectPublic()], total: 2, hasMore: true, next: "/api/projects-complete-but-truncated?page=2" });
      }
      if (request.url === "/api/projects-numeric?status=active") {
        return json(response, { items: [{ id: 1, tenant: "tenant-a", owner: "owner", state: "active", type: "project" }] });
      }
      if (request.url === "/api/search?q=safe-term") {
        return json(response, { items: actor === "viewer" ? [projectA()] : [projectPublic()] });
      }
      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-collection-auth-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "/identity-a")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "/identity-b")),
      collectionAuthorization: await writeJson(tempDir, "collections.json", collectionInput(target))
    });

    const jsonText = await readFile(result.reportPath, "utf8");
    const markdownText = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      scanPlan: { modules: Array<{ id: string }>; collectionAuthorizationTesting?: { requestMatrix: Array<{ objectId?: string; url: string }> } };
      identityVerification?: { accountA?: { verified: boolean }; accountB?: { verified: boolean } };
      collectionAuthorization?: {
        plannedRequests: number;
        executedRequests: number;
        confirmedIssues: number;
        observations: Array<{ collectionId: string; caseId: string; actorId: string; observedDecision: string; findingCategory?: string; observedMembership: string; objectMetadataConfirmed?: boolean; countObserved?: number; countObservedHash?: string; notes: string[] }>;
      };
      findings: Array<{ type: string; sourceModule: string; evidence: { source: string; curlCommand: string } }>;
      requestAudit: Array<{ requestedUrl: string; requestHeaders: Record<string, string> }>;
    };

    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(["collection-authorization-testing"]);
    expect(report.identityVerification?.accountA?.verified).toBe(true);
    expect(report.identityVerification?.accountB?.verified).toBe(true);
    expect(report.collectionAuthorization?.plannedRequests).toBe(8);
    expect(report.collectionAuthorization?.executedRequests).toBe(8);
    expect(publicHadAuth).toBe(false);
    expect(seen.every((entry) => entry.includes(":GET:"))).toBe(true);
    expect(seen.some((entry) => entry.includes("page=2"))).toBe(false);
    expect(seen.some((entry) => entry.includes("extra-999"))).toBe(false);

    const vulnerable = report.collectionAuthorization?.observations.find((observation) => observation.caseId === "viewer-vuln-foreign");
    const publicExposure = report.collectionAuthorization?.observations.find((observation) => observation.caseId === "public-private-vuln");
    const secure = report.collectionAuthorization?.observations.find((observation) => observation.caseId === "viewer-secure-foreign");
    const search = report.collectionAuthorization?.observations.find((observation) => observation.caseId === "viewer-search-foreign");
    const volatileCount = report.collectionAuthorization?.observations.find((observation) => observation.caseId === "owner-volatile-count");
    const truncated = report.collectionAuthorization?.observations.find((observation) => observation.caseId === "complete-but-truncated-absence");
    const numericId = report.collectionAuthorization?.observations.find((observation) => observation.caseId === "numeric-id-not-string-id");
    expect(secure?.observedMembership).toBe("NOT_FOUND");
    expect(vulnerable?.observedMembership).toBe("FOUND_ONCE");
    expect(vulnerable?.objectMetadataConfirmed).toBe(true);
    expect(vulnerable?.findingCategory).toBe("CROSS_TENANT_COLLECTION_EXPOSURE");
    expect(publicExposure?.findingCategory).toBe("PRIVATE_OBJECT_PUBLIC_LISTING_EXPOSURE");
    expect(search?.findingCategory).toBe("SEARCH_RESULT_AUTHORIZATION_EXPOSURE");
    expect(volatileCount?.countObserved).toBeUndefined();
    expect(volatileCount?.countObservedHash).toBeTruthy();
    expect(volatileCount?.findingCategory).toBeUndefined();
    expect(truncated?.observedDecision).toBe("COLLECTION_RESPONSE_INCOMPLETE");
    expect(truncated?.notes.join(" ")).toContain("Partial collection signal observed");
    expect(numericId?.observedMembership).toBe("NOT_FOUND");
    expect(numericId?.findingCategory).toBeUndefined();
    expect(report.collectionAuthorization?.confirmedIssues).toBe(3);
    expect(report.findings.filter((finding) => finding.type === "Collection Authorization Issue")).toHaveLength(3);
    expect(report.findings[0]?.evidence.curlCommand).toContain("<redacted>");

    for (const serialized of [jsonText, markdownText]) {
      expect(serialized).not.toContain("doc-a-001");
      expect(serialized).not.toContain("extra-999");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
      expect(serialized).not.toContain("collection secret marker");
    }
    expect(JSON.stringify(report.scanPlan.collectionAuthorizationTesting)).toContain("<object:");
    expect(report.requestAudit.every((entry) => Object.values(entry.requestHeaders).every((value) => value !== "session=account-a" && value !== "session=account-b"))).toBe(true);
  });
});

function collectionInput(target: string) {
  return {
    schemaVersion: 1,
    maxCollections: 5,
    maxCasesPerCollection: 6,
    maxKnownObjects: 3,
    maxRequests: 10,
    maxRetainedObservations: 10,
    maxPreviewLength: 80,
    collections: [
      collection(target, "secure", "/api/projects?status=active", [
        { id: "owner-secure-own", actorId: "owner", knownObjectId: "doc-a", expectedMembership: "MUST_CONTAIN", requireVerifiedIdentity: true },
        { id: "viewer-secure-foreign", actorId: "viewer", knownObjectId: "doc-a", expectedMembership: "MUST_NOT_CONTAIN", expectedActorRelationship: "CROSS_TENANT_MEMBER", requireVerifiedIdentity: true }
      ]),
      collection(target, "vulnerable", "/api/projects-vulnerable?status=active", [
        { id: "viewer-vuln-foreign", actorId: "viewer", knownObjectId: "doc-a", expectedMembership: "MUST_NOT_CONTAIN", expectedActorRelationship: "CROSS_TENANT_MEMBER", requireVerifiedIdentity: true },
        { id: "public-private-vuln", actorId: "public", knownObjectId: "doc-a", expectedMembership: "MUST_NOT_CONTAIN", requireVerifiedIdentity: false },
        { id: "owner-volatile-count", actorId: "owner", knownObjectId: "doc-a", expectedMembership: "OBSERVE_ONLY", requireVerifiedIdentity: true, countExpectation: { path: "count", expectation: "MUST_EQUAL", expectedCount: 1, securitySensitive: true, volatile: true } }
      ]),
      { ...collection(target, "search", "/api/search?q=safe-term", [{ id: "viewer-search-foreign", actorId: "viewer", knownObjectId: "doc-a", expectedMembership: "MUST_NOT_CONTAIN", expectedActorRelationship: "CROSS_TENANT_MEMBER", requireVerifiedIdentity: true }]), category: "SEARCH", completeness: "SEARCH_RESULT_SET" },
      { ...collection(target, "truncated", "/api/projects-complete-but-truncated?status=active", [{ id: "complete-but-truncated-absence", actorId: "viewer", knownObjectId: "doc-a", expectedMembership: "MUST_NOT_CONTAIN", requireVerifiedIdentity: true }]), completeness: "COMPLETE_COLLECTION" },
      {
        ...collection(target, "numeric", "/api/projects-numeric?status=active", [{ id: "numeric-id-not-string-id", actorId: "owner", knownObjectId: "numeric-string", expectedMembership: "MUST_NOT_CONTAIN", requireVerifiedIdentity: true }]),
        knownObjects: [{ id: "numeric-string", objectId: "1", objectType: "project", ownerActorId: "owner", tenantId: "tenant-a", state: "active", expectedPublic: false, confirmedSafeToTest: true }]
      }
    ]
  };
}

function collection(target: string, id: string, path: string, cases: unknown[]) {
  return {
    id,
    label: `${id} projects`,
    category: "LIST",
    method: "GET",
    url: new URL(path, target).toString(),
    headers: { Accept: "application/json" },
    expectedContentType: "application/json",
    completeness: "FIXED_RESULT_WINDOW",
    resultArrayPath: "items",
    objectIdPath: "id",
    objectTenantPath: "tenant",
    objectOwnerPath: "owner",
    objectStatePath: "state",
    objectTypePath: "type",
    maxInspectedEntries: 10,
    maxResponseBytes: 65536,
    maxJsonDepth: 8,
    actors: [
      { id: "owner", relationship: "OWNER", authProfile: "account_a", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active" },
      { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active" },
      { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
    ],
    knownObjects: [
      { id: "doc-a", objectId: "doc-a-001", objectType: "project", ownerActorId: "owner", tenantId: "tenant-a", state: "active", expectedPublic: false, confirmedSafeToTest: true },
      { id: "doc-public", objectId: "doc-public-001", objectType: "project", tenantId: "tenant-a", state: "active", expectedPublic: true, confirmedSafeToTest: true }
    ],
    cases
  };
}

function projectA() {
  return { id: "doc-a-001", tenant: "tenant-a", owner: "owner", state: "active", type: "project", secret: "collection secret marker" };
}

function projectPublic() {
  return { id: "doc-public-001", tenant: "tenant-a", owner: "owner", state: "active", type: "project" };
}

function extraProject() {
  return { id: "extra-999", tenant: "tenant-z", owner: "someone", state: "active", type: "project" };
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

function json(response: Parameters<NonNullable<Parameters<typeof createServer>[0]>>[1], value: unknown): void {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

async function writeScope(tempDir: string): Promise<string> {
  return writeJson(tempDir, "scope.json", {
    ...exampleScope,
    allowedDomains: ["127.0.0.1"],
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
