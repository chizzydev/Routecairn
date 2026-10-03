import { createHash } from "node:crypto";
import { createServer as createHttp2Server } from "node:http2";
import { createServer } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { decodeBoundedContent, runBoundedHttp, runGrpcStream, runHttp2, runInterruptedUpload, runSse, runWebSocket } from "../../src/modules/protocolSecurity/ProtocolTransports.js";

const closers: Array<() => Promise<void>> = [];
afterEach(async () => { while (closers.length) await closers.pop()!(); });

describe("protocol transports", () => {
  it("sends no request when the shared deadline is already cancelled", async () => {
    let connections = 0; const server = createServer(); server.on("connection", () => { connections += 1; });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve())));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const controller = new AbortController(); controller.abort(new Error("TEST_DEADLINE_CANCELLED"));
    const options = { allowedPrivateOrigins: [origin], timeoutMs: 2000, maxBytes: 4096, abortSignal: controller.signal };
    await expect(runBoundedHttp(origin, "GET", {}, undefined, options)).rejects.toThrow("TEST_DEADLINE_CANCELLED");
    await expect(runSse(origin, "GET", {}, undefined, 1, options)).rejects.toThrow("TEST_DEADLINE_CANCELLED");
    await expect(runWebSocket(origin.replace("http", "ws"), {}, [], [], 1, options)).rejects.toThrow("TEST_DEADLINE_CANCELLED");
    expect(connections).toBe(0);
  });

  it("closes a stalled WebSocket handshake when its shared deadline expires", async () => {
    const server = createServer(); let stalled: Socket | undefined; let closed = false;
    server.on("upgrade", (_request, socket) => { stalled = socket as Socket; socket.on("close", () => { closed = true; }); socket.on("end", () => socket.end()); socket.resume(); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => { stalled?.destroy(); return new Promise((resolve) => server.close(() => resolve())); });
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await expect(runWebSocket(origin.replace("http", "ws"), {}, [], [], 1, { allowedPrivateOrigins: [origin], timeoutMs: 2000, maxBytes: 4096, abortSignal: AbortSignal.timeout(100) })).rejects.toThrow();
    await new Promise<void>((resolve) => { if (closed) resolve(); else stalled?.once("close", () => resolve()); });
    expect(closed).toBe(true);
  });

  it("uses a pinned RFC6455 handshake and bounded message frames", async () => {
    const server = createServer();
    server.on("upgrade", (request, socket) => {
      const key = String(request.headers["sec-websocket-key"] ?? ""); const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: routecairn-test\r\n\r\n`);
      const payload = Buffer.from(JSON.stringify({ type: "ready", data: { allowed: true } })); socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
      setTimeout(() => socket.destroy(), 50).unref();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port;
    const result = await runWebSocket(`ws://127.0.0.1:${port}/socket`, {}, ["routecairn-test"], [], 1, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 2000, maxBytes: 4096 });
    expect(result).toMatchObject({ statusCode: 101, protocol: "routecairn-test" }); expect(result.messages[0]).toMatchObject({ type: "ready" });
  });

  it("drives WebSocket authorization states in order on one connection", async () => {
    const received: string[] = []; const server = createServer(); server.on("upgrade", (request, socket) => { const key = String(request.headers["sec-websocket-key"] ?? ""); const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64"); socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`); let pending = Buffer.alloc(0); socket.on("data", (chunk) => { pending = Buffer.concat([pending, chunk]); while (true) { const parsed = parseClientFrame(pending); if (!parsed) break; pending = pending.subarray(parsed.bytes); if (parsed.opcode === 8) { socket.destroy(); return; } const message = JSON.parse(parsed.payload.toString("utf8")) as { type: string }; received.push(message.type); if (message.type === "authenticate") socket.write(serverFrame({ type: "authenticated" })); if (message.type === "read") socket.write(serverFrame({ type: "result", data: { allowed: true } })); } }); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port; const states = [{ send: { type: "authenticate" } }, { expectType: "authenticated" }, { send: { type: "read" } }, { expectType: "result", expectJsonPath: "data.allowed", equals: true }];
    const result = await runWebSocket(`ws://127.0.0.1:${port}/socket`, {}, [], [], 2, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 2000, maxBytes: 4096 }, undefined, states);
    expect(received).toEqual(["authenticate", "read"]); expect(result.messages.map((message) => message.type)).toEqual(["authenticated", "result"]);
  });

  it("executes h2c requests and parses gRPC frames without retaining them in reports", async () => {
    const server = createHttp2Server();
    server.on("stream", (stream) => { const payload = Buffer.from([1, 2, 3]); const frame = Buffer.alloc(8); frame.writeUInt32BE(payload.length, 1); payload.copy(frame, 5); stream.respond({ ":status": 200, "content-type": "application/grpc", "grpc-status": "0" }); stream.end(frame); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port;
    const result = await runHttp2(`http://127.0.0.1:${port}/service/Call`, "POST", { "content-type": "application/grpc" }, Buffer.from([0, 0, 0, 0, 0]), 2, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 2000, maxBytes: 4096 });
    expect(result).toMatchObject({ statusCode: 200, protocol: "h2c", grpcStatus: 0 }); expect(result.grpcMessages).toHaveLength(1); expect([...result.grpcMessages[0]!]).toEqual([1, 2, 3]);
  });

  it("writes bounded gRPC client streams and receives bidirectional responses", async () => {
    let requestMessages = 0; const server = createHttp2Server(); server.on("stream", (stream) => { const chunks: Buffer[] = []; stream.on("data", (chunk) => chunks.push(Buffer.from(chunk))); stream.on("end", () => { const body = Buffer.concat(chunks); let offset = 0; while (offset + 5 <= body.length) { const size = body.readUInt32BE(offset + 1); if (offset + 5 + size > body.length) break; requestMessages += 1; offset += 5 + size; } const responsePayload = Buffer.from([9]); const responseFrame = Buffer.alloc(6); responseFrame.writeUInt32BE(1, 1); responsePayload.copy(responseFrame, 5); stream.respond({ ":status": 200, "content-type": "application/grpc", "grpc-status": "0" }); stream.end(responseFrame); }); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port;
    const result = await runGrpcStream(`http://127.0.0.1:${port}/service/Upload`, { "content-type": "application/grpc", te: "trailers" }, [Buffer.from([1]), Buffer.from([2, 3])], 2, 1, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 2000, maxBytes: 4096 });
    expect(requestMessages).toBe(2); expect(result).toMatchObject({ statusCode: 200, grpcStatus: 0 }); expect(result.grpcMessages).toHaveLength(1);
  });

  it("enforces decompression expansion bounds", () => {
    const compressed = gzipSync(Buffer.alloc(8192, 65));
    expect(decodeBoundedContent(compressed, "gzip", 16384)).toHaveLength(8192);
    expect(() => decodeBoundedContent(compressed, "gzip", 1024)).toThrow(/DECOMPRESSION_EXPANSION_LIMIT_EXCEEDED/);
  });

  it("interrupts a streaming upload at the exact configured byte boundary", async () => {
    let received = 0; let aborted = false; let settle!: () => void; const observed = new Promise<void>((resolve) => { settle = resolve; }); const server = createServer((request) => { request.on("data", (chunk) => { received += Buffer.byteLength(chunk); }); request.on("aborted", () => { aborted = true; settle(); }); request.on("close", settle); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port; const result = await runInterruptedUpload(`http://127.0.0.1:${port}/upload`, "POST", { "content-type": "application/octet-stream" }, Buffer.alloc(8192, 65), 256, 1024, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 2000, maxBytes: 4096 }); await Promise.race([observed, new Promise((resolve) => setTimeout(resolve, 1000))]);
    expect(result).toEqual({ transmittedBytes: 1024, interrupted: true }); expect(received).toBeLessThanOrEqual(1024); expect(aborted || received <= 1024).toBe(true);
  });

  it("stops an open SSE stream at the configured event bound", async () => {
    const server = createServer((_request, response) => { response.writeHead(200, { "content-type": "text/event-stream" }); response.write("event: ready\ndata: {\"ok\":true}\n\n"); response.write("event: item\ndata: {\"id\":1}\n\n"); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port;
    const result = await runSse(`http://127.0.0.1:${port}/events`, "GET", {}, undefined, 2, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 2000, maxBytes: 4096 });
    expect(result).toMatchObject({ statusCode: 200, eventCount: 2, contentType: "text/event-stream" });
  });

  it("returns completed SSE events when the duration bound expires", async () => {
    const server = createServer((_request, response) => { response.writeHead(200, { "content-type": "text/event-stream" }); response.write("event: ready\ndata: {\"ok\":true}\n\n"); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port;
    const result = await runSse(`http://127.0.0.1:${port}/events`, "GET", {}, undefined, 5, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 100, maxBytes: 4096 });
    expect(result).toMatchObject({ statusCode: 200, eventCount: 1, contentType: "text/event-stream" });
  });
});

function serverFrame(value: unknown): Buffer { const payload = Buffer.from(JSON.stringify(value)); return Buffer.concat([Buffer.from([0x81, payload.length]), payload]); }
function parseClientFrame(buffer: Buffer): { payload: Buffer; bytes: number; opcode: number } | undefined { if (buffer.length < 6) return; let length = buffer[1]! & 0x7f, offset = 2; if (length === 126) { if (buffer.length < 8) return; length = buffer.readUInt16BE(2); offset = 4; } if (length === 127) return; const mask = buffer.subarray(offset, offset + 4); offset += 4; if (buffer.length < offset + length) return; const payload = Buffer.alloc(length); for (let i = 0; i < length; i++) payload[i] = buffer[offset + i]! ^ mask[i % 4]!; return { payload, bytes: offset + length, opcode: buffer[0]! & 0x0f }; }
