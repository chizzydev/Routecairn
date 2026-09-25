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
  if (server) await new Promise<void>((resolve, reject) => server?.close((error) => error ? reject(error) : resolve()));
  server = undefined;
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("safe inventory import integration", () => {
  it("turns imported evidence into bounded executable reads while withholding writes", async () => {
    const seen: string[] = [];
    server = createServer((request, response) => {
      seen.push(`${request.method} ${request.url}`);
      if (request.url === "/") return json(response, { ok: true });
      if (request.url === "/read") return json(response, { id: "read-1" });
      if (request.url === "/items") { response.writeHead(200, { "content-type": "application/json", Link: "</items?page=2>; rel=next" }); return response.end(JSON.stringify({ items: [] })); }
      if (request.url === "/items?page=2") return json(response, { items: [] });
      if (request.url === "/files/report.pdf") { response.writeHead(request.headers.range ? 206 : 200, { "content-type": "application/pdf", "content-range": "bytes 0-3/4", "content-length": "4" }); return response.end("%PDF"); }
      response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const target = `http://127.0.0.1:${port}/`;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-inventory-"));
    tempDirs.push(tempDir);
    const scope = await writeJson(tempDir, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], rateLimitPerSecond: 50, concurrency: 2 });
    const inventory = await writeJson(tempDir, "inventory.json", {
      schemaVersion: 1,
      sources: [
        { id: "openapi", kind: "OPENAPI", document: { openapi: "3.1.0", servers: [{ url: target }], paths: { "/read": { get: { security: [], responses: { "200": { content: { "application/json": { schema: { type: "object", properties: { id: { type: "string" } } } } } } } } }, "/write": { post: { security: [], responses: { "201": {} } } } } } },
        { id: "har", kind: "HAR", document: { log: { entries: [
          { request: { method: "GET", url: `${target}items`, headers: [] }, response: { status: 200, headers: [{ name: "Link", value: "</items?page=2>; rel=next" }], content: { mimeType: "application/json", text: "{\"items\":[]}" } } },
          { request: { method: "GET", url: `${target}files/report.pdf`, headers: [] }, response: { status: 200, headers: [], content: { mimeType: "application/pdf" } } }
        ] } } }
      ]
    });
    const result = await runScanCommand(target, { scope, inventoryImport: inventory, output: join(tempDir, "reports"), maxRequests: "30" });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { apiGraphql?: { requestsTransmitted: number }; collectionAuthorization?: { executedRequests: number }; fileAuthorization?: { executedRequests: number }; scanPlan: { modules: Array<{ id: string }> } };
    expect(report.scanPlan.modules.map((item) => item.id)).toEqual(expect.arrayContaining(["api-graphql-authorization", "collection-authorization-testing", "file-authorization-testing"]));
    expect(report.apiGraphql?.requestsTransmitted).toBeGreaterThan(0);
    expect(report.collectionAuthorization?.executedRequests).toBe(2);
    expect(report.fileAuthorization?.executedRequests).toBe(1);
    expect(seen).toContain("GET /items?page=2");
    expect(seen.some((entry) => entry.includes("/write"))).toBe(false);
    expect(seen.every((entry) => !entry.startsWith("POST "))).toBe(true);
  });

  it("acquires authenticated inventories and executes the compiled cross-account contracts", async () => {
    server = createServer((request, response) => {
      const account = request.headers.authorization === "Bearer account-a" ? "a" : request.headers.authorization === "Bearer account-b" ? "b" : undefined;
      if (request.url === "/") return json(response, { ok: true });
      if (request.url === "/whoami" && account) return json(response, { principalId: `principal-${account}`, tenantId: `tenant-${account}` });
      if (request.url === "/api/projects" && account) return json(response, { data: [{ id: `${account}-project`, ownerId: `principal-${account}`, tenantId: `tenant-${account}`, fileUrl: `${origin()}/files/${account}-evidence.pdf` }] });
      const project = request.url?.match(/^\/api\/projects\/([ab])-project$/)?.[1];
      if (project) return project === account ? json(response, { id: `${project}-project`, ownerId: `principal-${project}`, tenantId: `tenant-${project}` }) : denied(response);
      const file = request.url?.match(/^\/files\/([ab])-evidence\.pdf$/)?.[1];
      if (file) {
        if (file !== account) return denied(response);
        response.writeHead(request.headers.range ? 206 : 200, { "content-type": "application/pdf", "content-range": "bytes 0-3/4", "content-length": "4" });
        return response.end("%PDF");
      }
      return denied(response, account ? 404 : 401);
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const target = `${origin()}/`;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-autonomous-inventory-"));
    tempDirs.push(tempDir);
    const scope = await writeJson(tempDir, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], rateLimitPerSecond: 50, concurrency: 2 });
    const authA = await writeJson(tempDir, "auth-a.json", authProfile("a", target));
    const authB = await writeJson(tempDir, "auth-b.json", authProfile("b", target));
    const inventory = await writeJson(tempDir, "inventory.json", {
      schemaVersion: 1,
      acquisition: { maxFetches: 10, rateLimitPerSecond: 5, authorizationDiscovery: { enabled: true, maxRoutes: 3, maxPages: 2, maxObjectsPerActor: 4 } },
      sources: [{ id: "api", kind: "OPENAPI", document: { openapi: "3.1.0", servers: [{ url: target }], security: [{ bearerAuth: [] }], paths: {
        "/api/projects": { get: { responses: { "200": {} } } },
        "/api/projects/{projectId}": { get: { parameters: [{ name: "projectId", in: "path", required: true, schema: { type: "string" } }], responses: { "200": {} } } }
      } } }]
    });

    const result = await runScanCommand(target, { scope, authA, authB, inventoryImport: inventory, output: join(tempDir, "reports"), maxRequests: "60" });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      scanPlan: { modules: Array<{ id: string }> };
      objectPairTesting?: { plannedRequests: number; executedRequests: number };
      collectionAuthorization?: { executedRequests: number };
      fileAuthorization?: { executedRequests: number };
    };
    expect(report.scanPlan.modules.map((item) => item.id)).toEqual(expect.arrayContaining(["object-pair-testing", "collection-authorization-testing", "file-authorization-testing"]));
    expect(report.objectPairTesting).toMatchObject({ plannedRequests: 4, executedRequests: 4 });
    expect(report.collectionAuthorization?.executedRequests).toBe(4);
    expect(report.fileAuthorization?.executedRequests).toBe(4);
  });
});

function json(response: Parameters<NonNullable<Parameters<typeof createServer>[0]>>[1], value: unknown): void {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

async function writeJson(tempDir: string, name: string, value: unknown): Promise<string> {
  const path = join(tempDir, name);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return path;
}

function origin(): string {
  const address = server?.address() as AddressInfo | null;
  if (!address) throw new Error("Server is not listening.");
  return `http://127.0.0.1:${address.port}`;
}

function denied(response: Parameters<NonNullable<Parameters<typeof createServer>[0]>>[1], status = 403): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: "denied" }));
}

function authProfile(account: "a" | "b", target: string): unknown {
  return {
    label: `Account ${account.toUpperCase()}`,
    safeAlias: `Account ${account.toUpperCase()}`,
    principalId: `principal-${account}`,
    tenantId: `tenant-${account}`,
    headers: { Authorization: `Bearer account-${account}` },
    cookies: [],
    identityVerification: { mode: "required", endpoint: `${target}whoami`, method: "GET", principalIdField: "principalId", tenantIdField: "tenantId", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] },
    lifecycleSecrets: {},
    notes: []
  };
}
