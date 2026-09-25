import { createServer, type ServerResponse } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { dashboardScanCreateSchema } from "../../src/dashboard/contracts/DashboardSchemas.js";
import { resolveDashboardScanPlan } from "../../src/dashboard/execution/ScanExecutionShared.js";

const servers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe("dashboard autonomous authorization inventory", () => {
  it("acquires account inventories and binds the frozen object, collection, and file plans", async () => {
    const server = createServer((request, response) => {
      const actor = request.headers.authorization === "Bearer a" ? "a" : request.headers.authorization === "Bearer b" ? "b" : undefined;
      if (request.url === "/api/documents" && actor) return json(response, { items: [{ id: `document-${actor}`, ownerId: `principal-${actor}`, tenantId: `tenant-${actor}`, downloadUrl: `${origin(server)}/files/document-${actor}.pdf` }] });
      response.statusCode = actor ? 404 : 401;
      response.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const target = origin(server);
    const request = dashboardScanCreateSchema.parse({
      target,
      profile: "quick",
      inventoryImport: {
        acquisition: { maxFetches: 8, authorizationDiscovery: { enabled: true, maxPages: 1, maxRoutes: 2, maxObjectsPerActor: 2 } },
        sources: [{ id: "api", kind: "OPENAPI", document: { openapi: "3.1.0", servers: [{ url: target }], security: [{ bearer: [] }], paths: {
          "/api/documents": { get: { responses: { "200": {} } } },
          "/api/documents/{id}": { get: { parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": {} } } }
        } } }]
      },
      studio: {
        version: 1,
        scanName: "Autonomous inventory",
        authorization: { category: "OWNED", confirmed: true },
        scope: { program: "fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 10, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" },
        authentication: { mode: "public" }, evidenceLevel: "minimal", outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: []
      }
    });
    const authProfileSet = {
      accountA: profile("a"),
      accountB: profile("b")
    };
    const resolved = await resolveDashboardScanPlan(request, { authProfileSet, safeSummary: {} });

    expect(resolved.plan.modules.map((module) => module.id)).toEqual(expect.arrayContaining(["object-pair-testing", "collection-authorization-testing", "file-authorization-testing"]));
    expect(resolved.plan.objectPairTesting?.requestMatrix).toHaveLength(4);
    expect(resolved.plan.collectionAuthorizationTesting?.requestMatrix).toHaveLength(4);
    expect(resolved.plan.fileAuthorizationTesting?.requestMatrix).toHaveLength(4);
  });
});

function profile(actor: "a" | "b") {
  return {
    label: `Account ${actor.toUpperCase()}`,
    principalId: `principal-${actor}`,
    tenantId: `tenant-${actor}`,
    headers: { Authorization: `Bearer ${actor}` },
    cookies: [],
    identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] },
    lifecycleSecrets: {}, notes: []
  };
}

function json(response: ServerResponse, value: unknown): void {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

function origin(server: ReturnType<typeof createServer>): string {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Server is not listening.");
  return `http://127.0.0.1:${address.port}`;
}
