import { createHash } from "node:crypto";
import { createServer as createHttp2Server } from "node:http2";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { runHttp2, runSse, runWebSocket } from "../../src/modules/protocolSecurity/ProtocolTransports.js";

const closers: Array<() => Promise<void>> = [];
afterEach(async () => { while (closers.length) await closers.pop()!(); });

describe("protocol transports", () => {
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

  it("executes h2c requests and parses gRPC frames without retaining them in reports", async () => {
    const server = createHttp2Server();
    server.on("stream", (stream) => { const payload = Buffer.from([1, 2, 3]); const frame = Buffer.alloc(8); frame.writeUInt32BE(payload.length, 1); payload.copy(frame, 5); stream.respond({ ":status": 200, "content-type": "application/grpc", "grpc-status": "0" }); stream.end(frame); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)); closers.push(() => new Promise((resolve) => server.close(() => resolve()))); const port = (server.address() as AddressInfo).port;
    const result = await runHttp2(`http://127.0.0.1:${port}/service/Call`, "POST", { "content-type": "application/grpc" }, Buffer.from([0, 0, 0, 0, 0]), 2, { allowedPrivateOrigins: [`http://127.0.0.1:${port}`], timeoutMs: 2000, maxBytes: 4096 });
    expect(result).toMatchObject({ statusCode: 200, protocol: "h2c", grpcStatus: 0 }); expect(result.grpcMessages).toHaveLength(1); expect([...result.grpcMessages[0]!]).toEqual([1, 2, 3]);
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
