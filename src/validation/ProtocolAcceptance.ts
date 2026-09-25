import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createSecureServer, type Http2SecureServer, type ServerHttp2Stream } from "node:http2";
import { createServer as createNetServer, type AddressInfo } from "node:net";
import { resolve } from "node:path";
import quico, { type QuicoServer } from "quico";
import selfsigned from "selfsigned";
import { runBoundedHttp, runHttp2, runHttp3Authorization, runHttp3Desync, runWebSocket, type ProtocolTransportOptions } from "../modules/protocolSecurity/ProtocolTransports.js";

export interface ProtocolAcceptanceLane {
  name: "websocket-authorization" | "graphql-websocket" | "multipart-cleanup" | "grpc-tls" | "http2-tls" | "http3-native";
  status: "PASSED" | "FAILED";
  checks: Readonly<Record<string, string | number | boolean>>;
  reason?: string;
}

export interface ProtocolAcceptanceSummary {
  schemaVersion: 1;
  status: "PASSED" | "FAILED";
  generatedAt: string;
  lanes: ProtocolAcceptanceLane[];
  nativeHttp3: true;
  externalCurlRequired: false;
  evidenceSha256: string;
  outputDirectory: string;
}

export async function runProtocolAcceptance(parentDirectory = ".routecairn-protocol-acceptance"): Promise<ProtocolAcceptanceSummary> {
  const parent = resolve(parentDirectory);
  await mkdir(parent, { recursive: true });
  const outputDirectory = await mkdtemp(resolve(parent, "run-"));
  const certificate = await createFixtureCertificate();
  const fixtures = new ProtocolAcceptanceFixtures(certificate);
  const lanes: ProtocolAcceptanceLane[] = [];
  try {
    const origins = await fixtures.start();
    const plainOptions: ProtocolTransportOptions = { allowedPrivateOrigins: [origins.httpOrigin], timeoutMs: 5_000, maxBytes: 64 * 1024 };
    const tlsOptions: ProtocolTransportOptions = { allowedPrivateOrigins: [origins.tlsOrigin], timeoutMs: 8_000, maxBytes: 64 * 1024, tlsCa: certificate.ca, dnsResolver: async () => ["127.0.0.1"] };
    const h3Options: ProtocolTransportOptions = { allowedPrivateOrigins: [origins.http3Origin], timeoutMs: 10_000, maxBytes: 64 * 1024, tlsCa: certificate.ca, dnsResolver: async () => ["127.0.0.1"] };

    lanes.push(await lane("websocket-authorization", async () => {
      const url = origins.httpOrigin.replace(/^http:/, "ws:") + "/ws/authorized";
      const denied = await runWebSocket(url, {}, ["routecairn-test"], [], 1, plainOptions);
      const allowed = await runWebSocket(url, { Authorization: "Bearer websocket-fixture-token" }, ["routecairn-test"], [], 1, plainOptions);
      const passed = denied.statusCode === 403 && allowed.statusCode === 101 && allowed.protocol === "routecairn-test" && allowed.messages.some((message) => message.type === "ready");
      if (!passed) throw new Error("WEBSOCKET_AUTHORIZATION_ACCEPTANCE_FAILED");
      return { deniedStatus: denied.statusCode, allowedStatus: allowed.statusCode, negotiatedProtocol: allowed.protocol ?? "none", messageCount: allowed.messages.length };
    }));

    lanes.push(await lane("graphql-websocket", async () => {
      const url = origins.httpOrigin.replace(/^http:/, "ws:") + "/graphql";
      const denied = await runWebSocket(url, {}, ["graphql-transport-ws"], [
        { type: "connection_init", payload: { authorization: "Bearer invalid" } }
      ], 1, plainOptions);
      const modern = await runWebSocket(url, {}, ["graphql-transport-ws"], [
        { type: "connection_init", payload: { authorization: "Bearer graphql-fixture-token" } },
        { id: "modern", type: "subscribe", payload: { query: "subscription Fixture { fixtureChanged { id } }" } }
      ], 2, plainOptions, "connection_ack");
      const legacy = await runWebSocket(url, {}, ["graphql-ws"], [
        { type: "connection_init", payload: { authorization: "Bearer graphql-fixture-token" } },
        { id: "legacy", type: "start", payload: { query: "subscription Fixture { fixtureChanged { id } }" } }
      ], 2, plainOptions, "connection_ack");
      const modernData = modern.messages.some((message) => message.type === "next");
      const legacyData = legacy.messages.some((message) => message.type === "data");
      const deniedRejected = denied.messages.some((message) => message.type === "error");
      if (!deniedRejected || modern.protocol !== "graphql-transport-ws" || legacy.protocol !== "graphql-ws" || !modernData || !legacyData) throw new Error("GRAPHQL_WEBSOCKET_ACCEPTANCE_FAILED");
      return { deniedRejected, modernMessages: modern.messages.length, legacyMessages: legacy.messages.length, modernData, legacyData };
    }));

    lanes.push(await lane("multipart-cleanup", async () => {
      const boundary = `routecairn-${randomBytes(12).toString("hex")}`;
      const body = Buffer.concat([
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\nacceptance\r\n`),
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`),
        Buffer.from([0, 255, 1, 2, 3]), Buffer.from(`\r\n--${boundary}--\r\n`)
      ]);
      const upload = await runBoundedHttp(`${origins.httpOrigin}/multipart`, "POST", { "content-type": `multipart/form-data; boundary=${boundary}` }, body, plainOptions);
      const deniedCleanup = await runBoundedHttp(`${origins.httpOrigin}/multipart/reset`, "POST", { authorization: "Bearer invalid", "content-type": "application/json" }, Buffer.from('{"cleanup":true}'), plainOptions);
      const deniedPreservedState = fixtures.multipartCreated;
      const cleanup = await runBoundedHttp(`${origins.httpOrigin}/multipart/reset`, "POST", { authorization: "Bearer cleanup-fixture-token", "content-type": "application/json" }, Buffer.from('{"cleanup":true}'), plainOptions);
      if (upload.statusCode !== 201 || deniedCleanup.statusCode !== 401 || !deniedPreservedState || cleanup.statusCode !== 204 || fixtures.multipartCreated) throw new Error("MULTIPART_CLEANUP_ACCEPTANCE_FAILED");
      return { uploadStatus: upload.statusCode, deniedCleanupStatus: deniedCleanup.statusCode, cleanupStatus: cleanup.statusCode, restored: !fixtures.multipartCreated };
    }));

    lanes.push(await lane("grpc-tls", async () => {
      const requestFrame = grpcFrame(Buffer.from([0x08, 0x2a]));
      const denied = await runHttp2(`${origins.tlsOrigin}/fixture.Service/Unary`, "POST", { "content-type": "application/grpc", te: "trailers" }, requestFrame, 4, tlsOptions);
      const unary = await runHttp2(`${origins.tlsOrigin}/fixture.Service/Unary`, "POST", { "content-type": "application/grpc", te: "trailers", authorization: "Bearer grpc-fixture-token" }, requestFrame, 4, tlsOptions);
      const stream = await runHttp2(`${origins.tlsOrigin}/fixture.Service/Stream`, "POST", { "content-type": "application/grpc", te: "trailers", authorization: "Bearer grpc-fixture-token" }, requestFrame, 4, tlsOptions);
      if (denied.grpcStatus !== 7 || unary.protocol !== "h2" || unary.grpcStatus !== 0 || unary.grpcMessages.length !== 1 || stream.grpcStatus !== 0 || stream.grpcMessages.length !== 2) throw new Error("GRPC_TLS_ACCEPTANCE_FAILED");
      return { protocol: unary.protocol, deniedGrpcStatus: denied.grpcStatus ?? -1, unaryMessages: unary.grpcMessages.length, streamMessages: stream.grpcMessages.length, grpcStatus: unary.grpcStatus ?? -1, trailersVerified: true };
    }));

    lanes.push(await lane("http2-tls", async () => {
      const denied = await runHttp2(`${origins.tlsOrigin}/h2/authorization`, "GET", {}, undefined, 1, tlsOptions);
      const allowed = await runHttp2(`${origins.tlsOrigin}/h2/authorization`, "GET", { authorization: "Bearer h2-fixture-token" }, undefined, 1, tlsOptions);
      if (denied.statusCode !== 403 || allowed.statusCode !== 200 || allowed.protocol !== "h2") throw new Error("HTTP2_TLS_ACCEPTANCE_FAILED");
      return { protocol: allowed.protocol, deniedStatus: denied.statusCode ?? 0, allowedStatus: allowed.statusCode ?? 0, alpnRequired: true };
    }));

    lanes.push(await lane("http3-native", async () => {
      const denied = await runHttp3Authorization(`${origins.http3Origin}/h3/authorization`, "GET", {}, h3Options);
      const allowed = await runHttp3Authorization(`${origins.http3Origin}/h3/authorization`, "GET", { authorization: "Bearer h3-fixture-token" }, h3Options);
      const desyncBody = Buffer.from("bounded-http3-probe");
      const desync = await runHttp3Desync(`${origins.http3Origin}/h3/desync`, {}, desyncBody, desyncBody.length + 1, "/h3/sentinel", [200], h3Options);
      if (denied.statusCode !== 403 || allowed.statusCode !== 200 || allowed.protocol !== "h3" || allowed.body.toString("utf8") !== "native-http3" || desync.probeStatus !== 400 || desync.sentinelStatus !== 200 || desync.probeAccepted || !desync.sentinelClean) throw new Error("HTTP3_NATIVE_ACCEPTANCE_FAILED");
      return { protocol: allowed.protocol, deniedStatus: denied.statusCode, allowedStatus: allowed.statusCode, desyncProbeStatus: desync.probeStatus, sentinelStatus: desync.sentinelStatus, sameConnection: desync.sameConnectionProcess, externalCurlRequired: false };
    }));
  } finally {
    await fixtures.close();
  }

  const status: ProtocolAcceptanceSummary["status"] = lanes.every((item) => item.status === "PASSED") ? "PASSED" : "FAILED";
  const core = { schemaVersion: 1 as const, status, generatedAt: new Date().toISOString(), lanes, nativeHttp3: true as const, externalCurlRequired: false as const };
  const evidenceSha256 = createHash("sha256").update(JSON.stringify(core)).digest("hex");
  const summary: ProtocolAcceptanceSummary = { ...core, evidenceSha256, outputDirectory };
  await writeFile(resolve(outputDirectory, "protocol-acceptance.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await writeFile(resolve(outputDirectory, "protocol-acceptance.md"), markdown(summary), "utf8");
  return summary;
}

class ProtocolAcceptanceFixtures {
  private httpServer: Server | undefined;
  private h2Server: Http2SecureServer | undefined;
  private h3Server: QuicoServer | undefined;
  public multipartCreated = false;

  public constructor(private readonly certificate: { cert: string; privateKey: string; ca: string }) {}

  public async start(): Promise<{ httpOrigin: string; tlsOrigin: string; http3Origin: string }> {
    this.httpServer = createServer((request, response) => { void this.handleHttp(request, response); });
    this.httpServer.on("upgrade", (request, socket) => this.handleUpgrade(request, socket));
    await listen(this.httpServer, 0, "127.0.0.1");

    this.h2Server = createSecureServer({ key: this.certificate.privateKey, cert: this.certificate.cert, allowHTTP1: false });
    this.h2Server.on("stream", (stream, headers) => this.handleHttp2(stream, headers));
    await listen(this.h2Server, 0, "127.0.0.1");

    const h3Port = await availablePort();
    this.h3Server = quico.createServer({ key: this.certificate.privateKey, cert: this.certificate.cert }, (request, response) => {
      if (request.url === "/h3/desync") {
        const chunks: Buffer[] = [];
        request.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        request.on("end", () => { const valid = Number(request.headers["content-length"] ?? -1) === Buffer.concat(chunks).length; response.writeHead(valid ? 200 : 400, { "content-type": "text/plain" }); response.end(valid ? "accepted" : "rejected"); });
        return;
      }
      if (request.url === "/h3/sentinel") { response.writeHead(200, { "content-type": "text/plain" }); response.end("clean"); return; }
      const allowed = request.url === "/h3/authorization" && request.headers.authorization === "Bearer h3-fixture-token";
      response.writeHead(allowed ? 200 : 403, { "content-type": "text/plain" });
      response.end(allowed ? "native-http3" : "denied");
    });
    await new Promise<void>((resolveStart, reject) => { this.h3Server!.once("error", reject); this.h3Server!.listen(h3Port, "127.0.0.1", () => { this.h3Server!.off("error", reject); resolveStart(); }); });

    const httpPort = (this.httpServer.address() as AddressInfo).port;
    const h2Port = (this.h2Server.address() as AddressInfo).port;
    return { httpOrigin: `http://127.0.0.1:${httpPort}`, tlsOrigin: `https://localhost:${h2Port}`, http3Origin: `https://localhost:${h3Port}` };
  }

  public async close(): Promise<void> {
    const http = this.httpServer; const h2 = this.h2Server; const h3 = this.h3Server;
    this.httpServer = undefined; this.h2Server = undefined; this.h3Server = undefined;
    await Promise.all([
      http ? boundedClose((done) => http.close(done)) : Promise.resolve(),
      h2 ? boundedClose((done) => h2.close(done)) : Promise.resolve(),
      h3 ? boundedClose((done) => h3.close(done)) : Promise.resolve()
    ]);
  }

  private async handleHttp(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const body = await requestBody(request);
    if (request.method === "POST" && request.url === "/multipart" && /^multipart\/form-data;\s*boundary=/i.test(String(request.headers["content-type"] ?? "")) && body.includes(Buffer.from([0, 255, 1, 2, 3]))) {
      this.multipartCreated = true; response.writeHead(201, { "content-type": "application/json" }).end('{"created":true}'); return;
    }
    if (request.method === "POST" && request.url === "/multipart/reset") {
      if (request.headers.authorization !== "Bearer cleanup-fixture-token") { response.writeHead(401).end(); return; }
      this.multipartCreated = false; response.writeHead(204).end(); return;
    }
    response.writeHead(404).end();
  }

  private handleUpgrade(request: IncomingMessage, socket: import("node:stream").Duplex): void {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path === "/ws/authorized" && request.headers.authorization !== "Bearer websocket-fixture-token") { socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); return; }
    const requested = String(request.headers["sec-websocket-protocol"] ?? "").split(/\s*,\s*/).filter(Boolean);
    const protocol = path === "/graphql" ? requested.find((value) => value === "graphql-transport-ws" || value === "graphql-ws") : requested.find((value) => value === "routecairn-test");
    const key = String(request.headers["sec-websocket-key"] ?? "");
    if (!protocol || !key) { socket.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); return; }
    const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: ${protocol}\r\n\r\n`);
    if (path === "/ws/authorized") { socket.write(serverFrame({ type: "ready", data: { authorized: true } })); return; }
    let pending = Buffer.alloc(0);
    let authorized = false;
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, Buffer.from(chunk)]);
      while (true) {
        const frame = clientFrame(pending); if (!frame) break; pending = pending.subarray(frame.bytes);
        if (frame.opcode === 8) { socket.end(); break; }
        if (frame.opcode !== 1) continue;
        let message: Record<string, unknown>; try { message = JSON.parse(frame.payload.toString("utf8")) as Record<string, unknown>; } catch { continue; }
        if (message.type === "connection_init") {
          const payload = message.payload && typeof message.payload === "object" ? message.payload as Record<string, unknown> : {};
          authorized = payload.authorization === "Bearer graphql-fixture-token";
          socket.write(serverFrame(authorized ? { type: "connection_ack" } : { type: "error", payload: { code: "UNAUTHORIZED" } }));
        } else if (authorized && protocol === "graphql-transport-ws" && message.type === "subscribe") socket.write(serverFrame({ id: message.id, type: "next", payload: { data: { fixtureChanged: { id: "fixture" } } } }));
        else if (authorized && protocol === "graphql-ws" && message.type === "start") socket.write(serverFrame({ id: message.id, type: "data", payload: { data: { fixtureChanged: { id: "fixture" } } } }));
      }
    });
  }

  private handleHttp2(stream: ServerHttp2Stream, headers: import("node:http2").IncomingHttpHeaders): void {
    const path = String(headers[":path"] ?? "/");
    if (path === "/h2/authorization") {
      const allowed = headers.authorization === "Bearer h2-fixture-token";
      stream.respond({ ":status": allowed ? 200 : 403, "content-type": "application/json" }); stream.end(allowed ? '{"allowed":true}' : '{"allowed":false}'); return;
    }
    const chunks: Buffer[] = [];
    stream.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => {
      const authorized = headers.authorization === "Bearer grpc-fixture-token";
      const request = Buffer.concat(chunks);
      if (!authorized || !validGrpcFrame(request)) { respondGrpc(stream, Buffer.alloc(0), authorized ? 3 : 7, authorized ? 400 : 403); return; }
      const frames = path.endsWith("/Stream") ? [grpcFrame(Buffer.from([0x08, 0x01])), grpcFrame(Buffer.from([0x08, 0x02]))] : [grpcFrame(Buffer.from([0x08, 0x2a]))];
      respondGrpc(stream, Buffer.concat(frames), 0, 200);
    });
  }
}

async function lane(name: ProtocolAcceptanceLane["name"], operation: () => Promise<Record<string, string | number | boolean>>): Promise<ProtocolAcceptanceLane> {
  try { return { name, status: "PASSED", checks: await operation() }; }
  catch (error) { return { name, status: "FAILED", checks: {}, reason: safeReason(error) }; }
}

function serverFrame(value: unknown): Buffer { const payload = Buffer.from(JSON.stringify(value)); if (payload.length >= 126) { const head = Buffer.alloc(4); head[0] = 0x81; head[1] = 126; head.writeUInt16BE(payload.length, 2); return Buffer.concat([head, payload]); } return Buffer.concat([Buffer.from([0x81, payload.length]), payload]); }
function clientFrame(value: Buffer): { opcode: number; payload: Buffer; bytes: number } | undefined { if (value.length < 6) return; const opcode = value[0]! & 0x0f; let length = value[1]! & 0x7f; let offset = 2; if (length === 126) { if (value.length < 8) return; length = value.readUInt16BE(2); offset = 4; } else if (length === 127) { if (value.length < 14) return; const size = value.readBigUInt64BE(2); if (size > BigInt(1024 * 1024)) throw new Error("WEBSOCKET_FIXTURE_FRAME_LIMIT"); length = Number(size); offset = 10; } if (!(value[1]! & 0x80) || value.length < offset + 4 + length) return; const mask = value.subarray(offset, offset + 4); offset += 4; const payload = Buffer.alloc(length); for (let index = 0; index < length; index++) payload[index] = value[offset + index]! ^ mask[index % 4]!; return { opcode, payload, bytes: offset + length }; }
function grpcFrame(payload: Buffer): Buffer { const frame = Buffer.alloc(5 + payload.length); frame.writeUInt32BE(payload.length, 1); payload.copy(frame, 5); return frame; }
function validGrpcFrame(value: Buffer): boolean { return value.length >= 5 && value[0] === 0 && value.readUInt32BE(1) === value.length - 5; }
async function requestBody(request: IncomingMessage): Promise<Buffer> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of request) { const value = Buffer.from(chunk); size += value.length; if (size > 1024 * 1024) throw new Error("PROTOCOL_FIXTURE_REQUEST_LIMIT"); chunks.push(value); } return Buffer.concat(chunks); }
function listen(server: Server | Http2SecureServer, port: number, host: string): Promise<void> { return new Promise((resolveListen, reject) => { server.once("error", reject); server.listen(port, host, () => { server.off("error", reject); resolveListen(); }); }); }
async function availablePort(): Promise<number> { const server = createNetServer(); await new Promise<void>((resolveListen, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolveListen(); }); }); const port = (server.address() as AddressInfo).port; await new Promise<void>((resolveClose) => server.close(() => resolveClose())); return port; }
async function createFixtureCertificate(): Promise<{ cert: string; privateKey: string; ca: string }> { const notBeforeDate = new Date(Date.now() - 60_000); const notAfterDate = new Date(Date.now() + 24 * 60 * 60 * 1000); const generated = await selfsigned.generate([{ name: "commonName", value: "localhost" }], { keyType: "ec", curve: "P-256", algorithm: "sha256", notBeforeDate, notAfterDate, extensions: [{ name: "basicConstraints", cA: true, pathLenConstraint: 0, critical: true }, { name: "keyUsage", digitalSignature: true, keyCertSign: true, cRLSign: true, critical: true }, { name: "extKeyUsage", serverAuth: true }, { name: "subjectAltName", altNames: [{ type: 2, value: "localhost" }, { type: 7, ip: "127.0.0.1" }] }] }); return { cert: generated.cert, privateKey: generated.private, ca: generated.cert }; }
function respondGrpc(stream: ServerHttp2Stream, body: Buffer, grpcStatus: number, httpStatus: number): void { stream.respond({ ":status": httpStatus, "content-type": "application/grpc+proto", "grpc-encoding": "identity" }, { waitForTrailers: true }); stream.once("wantTrailers", () => stream.sendTrailers({ "grpc-status": String(grpcStatus) })); stream.end(body); }
function boundedClose(close: (done: () => void) => void): Promise<void> { return new Promise((resolveClose) => { let settled = false; const done = () => { if (settled) return; settled = true; clearTimeout(timer); resolveClose(); }; const timer = setTimeout(done, 1_000); try { close(done); } catch { done(); } }); }
function safeReason(error: unknown): string { const value = error instanceof Error ? error.message : String(error); const normalized = value.toUpperCase().replace(/[^A-Z0-9_.:-]+/g, "_").slice(0, 160); return normalized || "PROTOCOL_ACCEPTANCE_FAILURE"; }
function markdown(summary: ProtocolAcceptanceSummary): string { return `# Protocol acceptance\n\nStatus: **${summary.status}**\n\n${summary.lanes.map((item) => `- ${item.name}: ${item.status}${item.reason ? ` (${item.reason})` : ""}`).join("\n")}\n\n- Native HTTP/3: ${summary.nativeHttp3}\n- External curl required: ${summary.externalCurlRequired}\n- Evidence SHA-256: \`${summary.evidenceSha256}\`\n`; }
