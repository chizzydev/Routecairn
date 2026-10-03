import { createHash } from "node:crypto";
import { createSecureServer, type Http2ServerRequest, type Http2ServerResponse } from "node:http2";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import { gzipSync, deflateSync, brotliCompressSync } from "node:zlib";
import quico from "quico";
import { generate } from "selfsigned";

/** Disposable listeners on loopback only; real TLS, H2, QUIC and application
 * state. Counters prove that the engine exercised each actual runtime path. */
export async function createProtocolSemanticsLab() {
  const certificate = await generate([{ name: "commonName", value: "localhost" }], { keySize: 2048, days: 1, extensions: [{ name: "basicConstraints", cA: true }, { name: "keyUsage", digitalSignature: true, keyCertSign: true, keyEncipherment: true }, { name: "subjectAltName", altNames: [{ type: 2, value: "localhost" }, { type: 7, ip: "127.0.0.1" }] }] });
  const counters: Record<string, number> = {};
  const increment = (name: string) => { counters[name] = (counters[name] ?? 0) + 1; };
  let partialBytes = 0, aborted = false, dirty = false, cleanupCount = 0;
  const sockets = new Set<Duplex>();
  const sessions = new Set<import("node:http2").ServerHttp2Session>();
  const document = "query Viewer { viewer { id } }";
  const persistedHash = createHash("sha256").update(document).digest("hex");
  let registered = false;
  const identity = { subject: "protocol-private-subject", tenant: "protocol-private-tenant" };
  const server = createSecureServer({ cert: certificate.cert, key: certificate.private, allowHTTP1: true });
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.on("session", (session) => { sessions.add(session); session.once("close", () => sessions.delete(session)); });
  server.on("request", (req, res) => { if (req.httpVersionMajor === 1) void http(req as IncomingMessage, res as ServerResponse); else http2(req as Http2ServerRequest, res as Http2ServerResponse); });
  server.on("upgrade", (req, socket) => websocket(req, socket));
  const http = async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const path = new URL(req.url ?? "/", "https://localhost").pathname;
      increment(`HTTP1:${path}`);
      if (path === "/upload") {
        dirty = true;
        req.on("data", (data: Buffer) => { partialBytes += data.length; });
        req.once("aborted", () => { aborted = true; increment("upload-aborted"); });
        req.on("error", () => undefined);
        return;
      }
      if (path === "/upload/state") { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ aborted, partial: partialBytes > 0 && partialBytes < 8192 })); return; }
      if (path === "/cleanup") {
        if (req.headers.authorization !== "Bearer protocol-fixture-session") { res.writeHead(403).end(); return; }
        dirty = false; partialBytes = 0; cleanupCount++; res.writeHead(204).end(); return;
      }
      if (path === "/identity" || path === "/identity/missing" || path === "/identity/mismatch") {
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(path.endsWith("missing") ? {} : path.endsWith("mismatch") ? { ...identity, subject: "other-private-subject" } : identity)); return;
      }
      if (path.startsWith("/compressed/")) {
        const encoding = path.split("/")[2];
        const input = Buffer.from(path.endsWith("/large") ? "A".repeat(8192) : '{"ok":true}');
        const compressed = encoding === "gzip" ? gzipSync(input) : encoding === "deflate" ? deflateSync(input) : brotliCompressSync(input);
        res.writeHead(200, { "content-encoding": encoding!, "content-type": "application/json" }).end(compressed); return;
      }
      if (path === "/graphql") {
        const data = JSON.parse((await body(req)).toString()) as { query?: string; extensions?: { persistedQuery?: { sha256Hash?: string } } };
        if (data.query?.includes("@stream")) {
          increment("incremental-parts"); res.writeHead(200, { "content-type": "multipart/mixed; boundary=fixture" });
          res.write('--fixture\r\ncontent-type: application/json\r\n\r\n{"data":{"feed":[]},"hasNext":true}\r\n');
          await new Promise((done) => setTimeout(done, 5));
          res.end('--fixture\r\ncontent-type: application/json\r\n\r\n{"incremental":[{"path":["feed",0],"items":[{"id":"private-id"}]}],"hasNext":false}\r\n--fixture--\r\n'); return;
        }
        if (data.query?.includes("_entities")) { increment("federation-entities"); res.writeHead(200, { "content-type": "application/json" }).end('{"data":{"_entities":[{"__typename":"OwnedObject"}]}}'); return; }
        if (data.extensions?.persistedQuery?.sha256Hash === persistedHash) {
          if (data.query === document) { registered = true; increment("persisted-register"); }
          else if (registered) increment("persisted-hit");
          res.writeHead(200, { "content-type": "application/json" }).end(registered ? '{"data":{"viewer":{"id":"private-id"}}}' : '{"errors":[{"message":"PERSISTED_QUERY_NOT_FOUND"}]}'); return;
        }
      }
      res.writeHead(404).end();
    } catch { res.writeHead(400).end(); }
  };
  const http2 = (req: Http2ServerRequest, res: Http2ServerResponse) => {
    req.on("error", () => undefined);
    const path = req.url; increment(`HTTP2:${path}`);
    if (path.startsWith("/identity")) { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(path.endsWith("missing") ? {} : identity)); return; }
    let pending = Buffer.alloc(0); let count = 0;
    const authorized = req.headers.authorization === "Bearer protocol-fixture-session";
    res.writeHead(authorized ? 200 : 403, { "content-type": "application/grpc" });
    req.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 5 && pending.length >= 5 + pending.readUInt32BE(1)) {
        const size = 5 + pending.readUInt32BE(1); const frame = pending.subarray(0, size); pending = pending.subarray(size); count++;
        if (path.endsWith("/Bidi") && authorized) { res.write(frame); increment("bidi-before-half-close"); }
      }
    });
    req.on("end", () => {
      increment(`grpc-received:${count}`);
      res.addTrailers({ "grpc-status": authorized && !pending.length ? "0" : "7" });
      if (authorized && !path.endsWith("/Bidi")) res.write(grpcFrame(Buffer.from(JSON.stringify({ count }))));
      res.end();
    });
  };
  const websocket = (req: IncomingMessage, socket: Duplex) => {
    socket.on("error", () => undefined);
    const path = new URL(req.url ?? "/", "https://localhost").pathname; increment(`WS:${path}`);
    const protocol = String(req.headers["sec-websocket-protocol"] ?? "");
    const accept = createHash("sha1").update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${protocol ? `Sec-WebSocket-Protocol: ${protocol}\r\n` : ""}\r\n`);
    if (path === "/identity") { socket.write(serverFrame(identity)); return; }
    let pending = Buffer.alloc(0), authorized = false;
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      while (true) {
        const frame = clientFrame(pending); if (!frame) break; pending = pending.subarray(frame.bytes);
        if (frame.opcode === 8) { socket.end(); return; }
        if (frame.opcode !== 1) continue;
        let value: { type?: string; id?: string; payload?: { authorization?: string } }; try { value = JSON.parse(frame.payload.toString()); } catch { socket.destroy(); return; }
        if (value.type === "connection_init" || value.type === "login") {
          authorized = value.payload?.authorization === "protocol-fixture-session";
          socket.write(serverFrame({ type: authorized ? value.type === "login" ? "authenticated" : "connection_ack" : "error" }));
          if (!authorized && path === "/graphql") socket.write(Buffer.from([0x88, 0]));
        } else if (value.type === "logout") { authorized = false; socket.write(serverFrame({ type: "logged_out" })); }
        else if (value.type === "read" || value.type === "subscribe" || value.type === "start") {
          socket.write(serverFrame({ type: authorized ? value.type === "read" ? "data" : protocol === "graphql-ws" ? "data" : "next" : "error", id: value.id, payload: { data: { allowed: authorized } } }));
          increment(authorized ? "ws-allowed" : "ws-denied");
          if (path === "/graphql") socket.write(Buffer.from([0x88, 0]));
        }
      }
    });
  };
  await new Promise<void>((done, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", done); });
  const port = (server.address() as AddressInfo).port;
  const h3 = quico.createServer({ key: certificate.private, cert: certificate.cert, http1: false, http2: false }, (req, res) => {
    increment(`HTTP3:${req.url}`);
    if (req.headers[":protocol"] === "webtransport") {
      if (req.url === "/datagrams/denied") { res.writeHead(403); res.end(); return; }
      res.writeHead(200);
      res.flushHeaders();
      req.on("datagram", (data) => { increment("wt-datagram"); const value = Buffer.from(data).toString(); res.sendDatagram!(Buffer.from(JSON.stringify(req.url === "/datagrams/large" ? { data: "A".repeat(700) } : req.url === "/identity" ? identity : { authorized: value === "protocol-fixture-session", echo: "safe" }))); }); return;
    }
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(identity));
  });
  try { await new Promise<void>((done, reject) => { h3.once("error", reject); h3.listen(port, "127.0.0.1", done); }); }
  catch (error) { server.close(); throw error; }
  return { origin: `https://localhost:${port}`, ca: certificate.cert, document, persistedHash, counters,
    state: () => ({ dirty, partialBytes, aborted, cleanupCount }),
    close: async () => { for (const session of sessions) session.destroy(); for (const socket of sockets) socket.destroy(); await Promise.all([new Promise<void>((done) => server.close(() => done())), new Promise<void>((done) => h3.close(() => done()))]); }
  };
}
async function body(req: IncomingMessage) { const chunks: Buffer[] = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > 65536) throw new Error("FIXTURE_LIMIT"); chunks.push(Buffer.from(chunk)); } return Buffer.concat(chunks); }
function grpcFrame(payload: Buffer) { const frame = Buffer.alloc(5 + payload.length); frame.writeUInt32BE(payload.length, 1); payload.copy(frame, 5); return frame; }
function serverFrame(value: unknown) { const payload = Buffer.from(JSON.stringify(value)); if (payload.length < 126) return Buffer.concat([Buffer.from([0x81, payload.length]), payload]); const head = Buffer.alloc(4); head[0] = 0x81; head[1] = 126; head.writeUInt16BE(payload.length, 2); return Buffer.concat([head, payload]); }
function clientFrame(buffer: Buffer): { bytes: number; opcode: number; payload: Buffer } | undefined { if (buffer.length < 6) return; let size = buffer[1]! & 127, offset = 2; if (size === 126) { if (buffer.length < 8) return; size = buffer.readUInt16BE(2); offset = 4; } if (size === 127 || size > 8192) return; if (buffer.length < offset + 4 + size) return; const mask = buffer.subarray(offset, offset + 4); offset += 4; const payload = Buffer.alloc(size); for (let index = 0; index < size; index++) payload[index] = buffer[offset + index]! ^ mask[index % 4]!; return { bytes: offset + size, opcode: buffer[0]! & 15, payload }; }
