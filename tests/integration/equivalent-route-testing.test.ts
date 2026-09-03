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

describe("equivalent route testing integration", () => {
  it("detects a supplied legacy route that exceeds canonical authorization while preserving public isolation and redaction", async () => {
    const seen: string[] = [];
    let publicHadAuth = false;
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("ok");
        return;
      }
      const cookie = String(request.headers.cookie ?? "");
      const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "viewer" : "public";
      if (actor === "public") publicHadAuth = Boolean(request.headers.cookie || request.headers.authorization || request.headers["x-csrf-token"] || request.headers["x-tenant-id"]);
      seen.push(`${actor}:${request.method}:${request.url}`);
      const objectId = request.url?.split("/").pop() ?? "";
      const body = JSON.stringify({ id: objectId, state: "published", secret: "never serialize equivalent route secret" });
      if (request.url?.startsWith("/api/documents/") && actor !== "owner") {
        response.writeHead(actor === "public" ? 401 : 403, { "content-type": "application/json" });
        response.end('{"error":"denied"}');
        return;
      }
      if (request.url?.startsWith("/legacy/documents/") && actor !== "owner") {
        response.writeHead(actor === "public" ? 401 : 403, { "content-type": "application/json" });
        response.end('{"error":"denied"}');
        return;
      }
      if (request.url?.startsWith("/legacy-open/documents/")) {
        response.writeHead(actor === "public" ? 401 : 200, { "content-type": "application/json" });
        response.end(actor === "public" ? '{"error":"login required"}' : body);
        return;
      }
      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-equivalent-route-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-one", "member", "active")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-one", "viewer", "active")),
      equivalentRoutes: await writeJson(tempDir, "equivalent-routes.json", equivalentRoutesInput(target, false))
    });

    const jsonText = await readFile(result.reportPath, "utf8");
    const markdownText = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      scanPlan: { modules: Array<{ id: string }>; equivalentRouteTesting?: { requestMatrix: Array<{ objectId: string; url: string }> } };
      equivalentRouteTesting?: {
        plannedRequests: number;
        executedRequests: number;
        confirmedIssues: number;
        observations: Array<{ actorId: string; routeId: string; routeLabel: string; observedDecision: string; findingCategory?: string; objectIdentityConfirmed: boolean; comparisonRouteId?: string }>;
      };
      findings: Array<{ type: string; sourceModule: string; evidence: { source: string; curlCommand: string } }>;
      requestAudit: Array<{ requestedUrl: string; requestHeaders: Record<string, string> }>;
    };

    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(["equivalent-route-testing"]);
    expect(report.equivalentRouteTesting?.plannedRequests).toBe(9);
    expect(report.equivalentRouteTesting?.executedRequests).toBe(9);
    expect(publicHadAuth).toBe(false);
    expect(seen.every((entry) => entry.includes(":GET:"))).toBe(true);
    expect(new Set(seen.map((entry) => entry.split(":GET:")[1]))).toEqual(new Set(["/api/documents/doc-a-001", "/legacy/documents/doc-a-001", "/legacy-open/documents/doc-a-001"]));

    const vulnerable = report.equivalentRouteTesting?.observations.find((observation) => observation.actorId === "viewer" && observation.routeId === "legacy-vuln");
    const secure = report.equivalentRouteTesting?.observations.find((observation) => observation.actorId === "viewer" && observation.routeId === "legacy-secure");
    expect(secure?.observedDecision).toBe("ACCESS_DENIED_CONFIRMED");
    expect(vulnerable?.observedDecision).toBe("ACCESS_ALLOWED_CONFIRMED");
    expect(vulnerable?.objectIdentityConfirmed).toBe(true);
    expect(vulnerable?.comparisonRouteId).toBe("canonical");
    expect(vulnerable?.findingCategory).toBe("LEGACY_ROUTE_AUTHORIZATION_BYPASS");
    expect(report.equivalentRouteTesting?.confirmedIssues).toBe(1);
    expect(report.findings.filter((finding) => finding.type === "Equivalent Route Authorization Issue")).toHaveLength(1);
    expect(report.findings[0]?.evidence.curlCommand).toBeUndefined();
    expect(report.findings[0]?.evidence.source).toMatch(/^assisted-workflow:equivalent-route-testing:/);

    for (const serialized of [jsonText, markdownText]) {
      expect(serialized).not.toContain("doc-a-001");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
      expect(serialized).not.toContain("never serialize equivalent route secret");
    }
    expect(JSON.stringify(report.scanPlan.equivalentRouteTesting)).toContain("<object:");
    expect(report.requestAudit.every((entry) => Object.values(entry.requestHeaders).every((value) => value !== "session=account-a" && value !== "session=account-b"))).toBe(true);
  });

  it("does not create a security finding for 403 versus 404 when neither route returns the protected object", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200).end("ok");
        return;
      }
      response.writeHead(request.url?.startsWith("/legacy-open/") ? 404 : 403, { "content-type": "application/json" });
      response.end('{"error":"denied"}');
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-equivalent-route-denials-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-one", "member", "active")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-one", "viewer", "active")),
      equivalentRoutes: await writeJson(tempDir, "equivalent-routes.json", equivalentRoutesInput(target, false))
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { equivalentRouteTesting?: { confirmedIssues: number }; findings: Array<{ type: string }> };
    expect(report.equivalentRouteTesting?.confirmedIssues).toBe(0);
    expect(report.findings.some((finding) => finding.type === "Equivalent Route Authorization Issue")).toBe(false);
  });

  it("blocks verified-identity-required authenticated route cells before equivalent-route requests when verification is missing", async () => {
    const seen: string[] = [];
    server = createServer((request, response) => {
      seen.push(request.url ?? "");
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"id":"doc-a-001","state":"published"}');
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-equivalent-route-gate-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const input = equivalentRoutesInput(target, true);
    input.routeSets[0].actors = input.routeSets[0].actors.filter((actor) => actor.relationship !== "PUBLIC");
    for (const route of input.routeSets[0].routes) delete route.expectations.public;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-one", "member", "active")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-one", "viewer", "active")),
      equivalentRoutes: await writeJson(tempDir, "equivalent-routes.json", input)
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { equivalentRouteTesting?: { executedRequests: number; observations: Array<{ observedDecision: string }> } };
    expect(report.equivalentRouteTesting?.executedRequests).toBe(0);
    expect(report.equivalentRouteTesting?.observations.every((observation) => observation.observedDecision === "IDENTITY_REQUIREMENT_UNSATISFIED")).toBe(true);
    expect(seen).toEqual(["/"]);
  });
});

function equivalentRoutesInput(target: string, requireVerifiedIdentity: boolean) {
  return {
    schemaVersion: 1,
    maxRouteSets: 1,
    maxRoutesPerSet: 4,
    maxActorsPerSet: 3,
    maxCells: 20,
    maxResponseBytes: 65536,
    maxPreviewLength: 80,
    routeSets: [
      {
        id: "document-equivalent-routes",
        name: "Document equivalent routes",
        objectType: "document",
        objectId: "doc-a-001",
        canonicalRouteId: "canonical",
        equivalencePolicy: "SAME_OWNER_BOUNDARY",
        objectIdentityField: "id",
        objectStateField: "state",
        expectedObjectState: "published",
        requireVerifiedIdentity,
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", principalId: "principal-a", tenantId: "tenant-one", role: "member", accountState: "active" },
          { id: "viewer", relationship: "NON_OWNER", authProfile: "account_b", principalId: "principal-b", tenantId: "tenant-one", role: "viewer", accountState: "active" },
          { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
        ],
        routes: [
          route("canonical", "Canonical API", "CANONICAL", new URL("/api/documents/{{OBJECT_ID}}", target).toString(), { owner: "MUST_ALLOW", viewer: "MUST_DENY", public: "MUST_REQUIRE_AUTHENTICATION" }),
          route("legacy-secure", "Secure legacy API", "LEGACY", new URL("/legacy/documents/{{OBJECT_ID}}", target).toString(), { owner: "MUST_ALLOW", viewer: "MUST_DENY", public: "MUST_REQUIRE_AUTHENTICATION" }, "canonical"),
          route("legacy-vuln", "Vulnerable legacy API", "LEGACY", new URL("/legacy-open/documents/{{OBJECT_ID}}", target).toString(), { owner: "MUST_ALLOW", viewer: "MUST_DENY", public: "MUST_REQUIRE_AUTHENTICATION" }, "canonical")
        ]
      }
    ]
  };
}

function route(id: string, label: string, category: string, url: string, expectations: Record<string, string>, referenceRouteId?: string) {
  return {
    id,
    label,
    category,
    isCanonical: id === "canonical",
    template: { id: `${id}-get`, method: "GET", url, headers: { Accept: "application/json" } },
    expectedContentType: "application/json",
    representationType: "json",
    ...(referenceRouteId ? { referenceRouteId } : {}),
    expectations
  };
}

function authProfile(label: string, principalId: string, tenantId: string, role: string, accountState: string) {
  return {
    label,
    safeAlias: label,
    principalId,
    tenantId,
    role,
    accountState,
    headers: { Cookie: `session=${label}` }
  };
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
