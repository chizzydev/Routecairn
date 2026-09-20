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
