import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { ProtocolSecurityReport } from "../../src/modules/protocolSecurity/ProtocolSecurityTypes.js";

let server: Server | undefined; const directories: string[] = [];
afterEach(async () => { if (server) await new Promise<void>((resolve) => server!.close(() => resolve())); server = undefined; await Promise.all(directories.splice(0).map((value) => rm(value, { recursive: true, force: true }))); });

describe("protocol security integration", () => {
  it("executes bounded SSE plus an authorized GraphQL mutation and verified cleanup without payload persistence", async () => {
    let mutated = false; let cleanupCount = 0; let binaryUploadObserved = false;
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/events") { response.writeHead(200, { "content-type": "text/event-stream" }); response.end("event: ready\ndata: {\"scope\":\"member-private-value\"}\n\n"); return; }
      if (request.url === "/graphql" && request.method === "POST") { const raw = await body(request); mutated = raw.includes("UpdateFixture"); response.writeHead(200, { "content-type": "application/json" }).end('{"data":{"updateFixture":{"ok":true,"token":"response-private-value"}}}'); return; }
      if (request.url === "/inspect-upload" && request.method === "POST") { const raw = await rawBody(request); binaryUploadObserved = raw.indexOf(Buffer.from([0, 255, 1])) >= 0; response.writeHead(binaryUploadObserved ? 200 : 400, { "content-type": "application/json" }).end('{"ok":true}'); return; }
      if (request.url === "/fixtures/reset" && request.method === "POST") { if (request.headers.authorization !== "Bearer header-private-value") return void response.writeHead(401).end(); mutated = false; cleanupCount += 1; response.writeHead(204).end(); return; }
      response.writeHead(404).end();
    });
    server.on("upgrade", (_request, socket) => socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve)); const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-protocol-")); directories.push(directory); const now = Date.now();
    const manifest = { schemaVersion: 1, maxRequests: 5, maxDurationMs: 3000, actors: [{ id: "member", safeAlias: "member", authSlot: "primary", relationship: "self" }], cases: [
      { id: "events", label: "events", kind: "SSE", actorId: "member", requireVerifiedIdentity: false, url: `${origin}/events`, headers: {}, method: "GET", maxEvents: 1, expectation: { decision: "ALLOW", allowedStatuses: [200], deniedStatuses: [401, 403], messageType: "ready", minMessages: 1 } },
      { id: "denied-socket", label: "denied socket", kind: "WEBSOCKET", actorId: "member", requireVerifiedIdentity: false, url: origin.replace(/^http:/, "ws:") + "/denied-socket", headers: {}, subprotocols: ["routecairn-test"], messages: [], maxMessages: 1, readOnly: true, expectation: { decision: "DENY", allowedStatuses: [101], deniedStatuses: [401, 403], minMessages: 0 } },
      { id: "upload", label: "read-only upload inspection", kind: "MULTIPART_UPLOAD", actorId: "member", requireVerifiedIdentity: false, url: `${origin}/inspect-upload`, headers: {}, fields: { purpose: "fixture" }, files: [{ fieldName: "file", fileName: "fixture.bin", contentType: "application/octet-stream", contentSecretRef: "upload_fixture" }], readOnly: true, expectation: { decision: "ALLOW", allowedStatuses: [200], deniedStatuses: [400, 401, 403], minMessages: 0 } },
      { id: "mutation", label: "controlled mutation", kind: "GRAPHQL_MUTATION", actorId: "member", requireVerifiedIdentity: false, url: `${origin}/graphql`, headers: {}, operationName: "UpdateFixture", document: "mutation UpdateFixture { updateFixture { ok } }", variables: { input: "{{SECRET:mutation_input}}" }, expectation: { decision: "ALLOW", allowedStatuses: [200], deniedStatuses: [400, 401, 403], jsonPath: "data.updateFixture.ok", equals: true, minMessages: 0 }, authorization: { environment: "TEST", operator: "operator-private-name", ticket: "ticket-private-123", authorizedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES", disposableResources: true }, cleanup: { url: `${origin}/fixtures/reset`, method: "POST", headers: {}, body: { fixture: "{{SECRET:fixture_id}}" }, statusIn: [204] } }
    ] };
    const scope = await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"], rateLimitPerSecond: 50, concurrency: 2 });
    const auth = await writeJson(directory, "auth.json", { label: "member", safeAlias: "member", principalId: "member-private-id", headers: { Authorization: "Bearer header-private-value" }, lifecycleSecrets: { mutation_input: "input-private-value", fixture_id: "fixture-private-value", upload_fixture: "base64:AP8B" } });
    const result = await runScanCommand(`${origin}/`, { scope, auth, protocolSecurity: await writeJson(directory, "protocol.json", manifest), output: join(directory, "reports") }); const text = await readFile(result.reportPath, "utf8"); const markdown = await readFile(result.markdownReportPath, "utf8"); const html = await readFile(result.htmlReportPath, "utf8"); const report = JSON.parse(text) as { protocolSecurity: ProtocolSecurityReport };
    expect(report.protocolSecurity).toMatchObject({ plannedCases: 4, executedCases: 4, passedCases: 4, failedCases: 0, blockedCases: 0 }); expect(report.protocolSecurity.observations.find((value) => value.caseId === "denied-socket")).toMatchObject({ outcome: "PASS", statusCode: 403 }); expect(report.protocolSecurity.observations.find((value) => value.caseId === "mutation")).toMatchObject({ cleanupOutcome: "ROLLBACK_VERIFIED" }); expect(mutated).toBe(false); expect(cleanupCount).toBe(1); expect(binaryUploadObserved).toBe(true); expect(markdown).toContain("## Protocol-Level Security"); expect(html).toContain("Protocol-Level Security");
    for (const secret of ["member-private-value", "response-private-value", "operator-private-name", "ticket-private-123", "member-private-id", "header-private-value", "input-private-value", "fixture-private-value"]) { expect(text).not.toContain(secret); expect(html).not.toContain(secret); }
  }, 30_000);
});

async function body(request: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks).toString("utf8"); }
async function rawBody(request: IncomingMessage): Promise<Buffer> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, JSON.stringify(value)); return path; }
