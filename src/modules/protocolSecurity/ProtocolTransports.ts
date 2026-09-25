import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { connect as connectHttp2, constants as h2, type ClientHttp2Session } from "node:http2";
import { connect as connectTcp, isIP, type Socket } from "node:net";
import { connect as connectTls, type TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";
import { Agent, request as undiciRequest } from "undici";
import { createPinnedConnector, resolvePinnedDestination } from "../../core/http/PinnedHttpTransport.js";
import type { DnsResolver } from "../../core/http/HttpTypes.js";

export interface ProtocolTransportOptions { allowedPrivateOrigins: readonly string[]; timeoutMs: number; maxBytes: number; abortSignal?: AbortSignal; dnsResolver?: DnsResolver; tlsCa?: string | Buffer; }
export interface StreamMessage { type?: string; value: unknown; }
export interface WebSocketResult { statusCode: number; protocol?: string; messages: StreamMessage[]; }
export interface Http2Result { statusCode?: number; protocol: "h2" | "h2c"; headers: Record<string, string | string[]>; body: Buffer; grpcStatus?: number; grpcMessages: Buffer[]; errorCode?: string; }
export interface Http2DesyncResult { probe: Http2Result; sentinel: Http2Result; sameSession: true; }
export interface SseResult { statusCode: number; body: string; eventCount: number; contentType?: string; }
export interface BoundedHttpResult { statusCode: number; headers: Record<string, string | string[]>; body: Buffer; }
export interface Http3Result { statusCode: number; protocol: "h3"; body: Buffer; }
export interface Http3DesyncResult { probeStatus?: number; sentinelStatus?: number; protocol: "h3"; sameConnectionProcess: true; probeAccepted: boolean; sentinelClean: boolean; }

export async function ensureHttp3Runtime(options: ProtocolTransportOptions): Promise<void> { await runNativeHttp3Worker({ hostname: "127.0.0.1", port: 9, pinnedAddress: "127.0.0.1", family: 4, timeoutMs: Math.min(options.timeoutMs, 1000), maxBytes: 1024, requests: [], ...(options.tlsCa ? { ca: Buffer.isBuffer(options.tlsCa) ? options.tlsCa.toString("utf8") : options.tlsCa } : {}) }); }

export async function runHttp3Authorization(urlValue: string, method: "GET" | "HEAD" | "OPTIONS", headers: Readonly<Record<string, string>>, options: ProtocolTransportOptions): Promise<Http3Result> {
  const url = new URL(urlValue); if (url.protocol !== "https:") throw new Error("HTTP3_HTTPS_REQUIRED"); const pin = await resolvePinnedDestination({ hostname: url.hostname, protocol: "https:", port: url.port || "443" }, { allowedPrivateOrigins: options.allowedPrivateOrigins, dnsTimeoutMs: Math.min(options.timeoutMs, 5000), maxDnsAnswers: 16, ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}) });
  const result = await nativeHttp3(url, pin.address.address, pin.address.family, [{ method, path: `${url.pathname}${url.search}`, headers }], options); const response = result.responses[0]; if (!response) throw new Error("HTTP3_RESPONSE_MISSING"); return { statusCode: response.statusCode, protocol: "h3", body: Buffer.from(response.bodyBase64, "base64") };
}

export async function runHttp3Desync(urlValue: string, headers: Readonly<Record<string, string>>, body: Buffer, declaredLength: number, sentinelPath: string, allowedStatuses: readonly number[], options: ProtocolTransportOptions): Promise<Http3DesyncResult> {
  const url = new URL(urlValue); if (url.protocol !== "https:") throw new Error("HTTP3_HTTPS_REQUIRED"); const sentinel = new URL(sentinelPath, url); if (sentinel.origin !== url.origin) throw new Error("HTTP3_SENTINEL_ORIGIN_MISMATCH"); const pin = await resolvePinnedDestination({ hostname: url.hostname, protocol: "https:", port: url.port || "443" }, { allowedPrivateOrigins: options.allowedPrivateOrigins, dnsTimeoutMs: Math.min(options.timeoutMs, 5000), maxDnsAnswers: 16, ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}) });
  const result = await nativeHttp3(url, pin.address.address, pin.address.family, [
    { method: "POST", path: `${url.pathname}${url.search}`, headers: { ...headers, "content-length": String(declaredLength), "content-type": "application/octet-stream" }, bodyBase64: body.toString("base64") },
    { method: "GET", path: `${sentinel.pathname}${sentinel.search}`, headers }
  ], { ...options, timeoutMs: options.timeoutMs * 2, maxBytes: options.maxBytes * 2 });
  const probe = result.responses[0], sentinelResult = result.responses[1]; if (!probe || !sentinelResult) throw new Error("HTTP3_SENTINEL_NOT_EXECUTED"); if (!result.sameConnection) throw new Error("HTTP3_CONNECTION_REUSE_FAILED"); return { probeStatus: probe.statusCode, sentinelStatus: sentinelResult.statusCode, protocol: "h3", sameConnectionProcess: true, probeAccepted: allowedStatuses.includes(probe.statusCode), sentinelClean: allowedStatuses.includes(sentinelResult.statusCode) };
}

export async function runBoundedHttp(urlValue: string, method: string, headers: Readonly<Record<string, string>>, body: Buffer | undefined, options: ProtocolTransportOptions): Promise<BoundedHttpResult> {
  const controller = new AbortController(); const abort = () => controller.abort(); options.abortSignal?.addEventListener("abort", abort, { once: true }); const timer = setTimeout(abort, options.timeoutMs); const dispatcher = new Agent({ connect: createPinnedConnector({ allowedPrivateOrigins: options.allowedPrivateOrigins, dnsTimeoutMs: Math.min(options.timeoutMs, 5000), maxDnsAnswers: 16, ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}) }), pipelining: 0 });
  try { const response = await undiciRequest(new URL(urlValue), { method, headers, ...(body ? { body } : {}), dispatcher, signal: controller.signal }); const chunks: Buffer[] = []; let size = 0; try { for await (const chunk of response.body) { const value = Buffer.from(chunk); size += value.length; if (size > options.maxBytes) throw new Error("HTTP_RESPONSE_LIMIT_EXCEEDED"); chunks.push(value); } } finally { response.body.destroy(); } return { statusCode: response.statusCode, headers: normalizeUndiciHeaders(response.headers), body: Buffer.concat(chunks) }; }
  finally { clearTimeout(timer); options.abortSignal?.removeEventListener("abort", abort); await dispatcher.close(); }
}

export async function runSse(urlValue: string, method: "GET" | "POST", headers: Readonly<Record<string, string>>, body: string | undefined, maxEvents: number, options: ProtocolTransportOptions): Promise<SseResult> {
  const url = new URL(urlValue); const controller = new AbortController(); let timedOut = false; const abort = () => controller.abort(); options.abortSignal?.addEventListener("abort", abort, { once: true }); const timer = setTimeout(() => { timedOut = true; controller.abort(); }, options.timeoutMs);
  const dispatcher = new Agent({ connect: createPinnedConnector({ allowedPrivateOrigins: options.allowedPrivateOrigins, dnsTimeoutMs: Math.min(options.timeoutMs, 5000), maxDnsAnswers: 16, ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}) }), pipelining: 0 });
  try {
    const response = await undiciRequest(url, { method, headers: { Accept: "text/event-stream", ...headers }, ...(body !== undefined ? { body } : {}), dispatcher, signal: controller.signal }); const chunks: Buffer[] = []; let size = 0; let eventCount = 0;
    try { for await (const chunk of response.body) { const value = Buffer.from(chunk); size += value.length; if (size > options.maxBytes) throw new Error("SSE_RESPONSE_LIMIT_EXCEEDED"); chunks.push(value); eventCount = completeSseEvents(Buffer.concat(chunks).toString("utf8")); if (eventCount >= maxEvents) break; } } catch (error) { if (!timedOut || error instanceof Error && error.message === "SSE_RESPONSE_LIMIT_EXCEEDED") throw error; } finally { response.body.destroy(); }
    const rawContentType = response.headers["content-type"]; const contentType = Array.isArray(rawContentType) ? rawContentType.join(", ") : rawContentType;
    return { statusCode: response.statusCode, body: Buffer.concat(chunks).toString("utf8"), eventCount, ...(contentType ? { contentType } : {}) };
  } finally { clearTimeout(timer); options.abortSignal?.removeEventListener("abort", abort); await dispatcher.close(); }
}

export async function runWebSocket(urlValue: string, headers: Readonly<Record<string, string>>, subprotocols: readonly string[], outbound: readonly unknown[], maxMessages: number, options: ProtocolTransportOptions, waitForTypeBeforeRest?: string): Promise<WebSocketResult> {
  const url = new URL(urlValue); const socket = await pinnedSocket(url, options, ["http/1.1"]); const key = randomBytes(16).toString("base64");
  const requestHeaders: Record<string, string> = { Host: url.host, Upgrade: "websocket", Connection: "Upgrade", "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13", ...headers };
  if (subprotocols.length) requestHeaders["Sec-WebSocket-Protocol"] = subprotocols.join(", ");
  const request = `GET ${url.pathname}${url.search} HTTP/1.1\r\n${Object.entries(requestHeaders).map(([name, value]) => `${name}: ${value}`).join("\r\n")}\r\n\r\n`;
  socket.write(request); const initial = await readUntil(socket, Buffer.from("\r\n\r\n"), options.timeoutMs, 32 * 1024, options.abortSignal); const boundary = initial.indexOf("\r\n\r\n");
  const head = initial.subarray(0, boundary).toString("latin1"); const lines = head.split("\r\n"); const statusCode = Number(lines[0]?.split(" ")[1]); const responseHeaders = Object.fromEntries(lines.slice(1).map((line) => { const p = line.indexOf(":"); return p > 0 ? [line.slice(0, p).toLowerCase(), line.slice(p + 1).trim()] : [line, ""]; }));
  const expected = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
  if (statusCode !== 101 || responseHeaders["sec-websocket-accept"] !== expected || responseHeaders.upgrade?.toLowerCase() !== "websocket" || !responseHeaders.connection?.toLowerCase().split(/\s*,\s*/).includes("upgrade")) { socket.destroy(); return { statusCode: Number.isFinite(statusCode) ? statusCode : 0, messages: [] }; }
  const initialOutbound = waitForTypeBeforeRest ? outbound.slice(0, 1) : outbound; for (const message of initialOutbound) socket.write(encodeFrame(Buffer.from(JSON.stringify(message), "utf8"), 1)); let deferredSent = !waitForTypeBeforeRest;
  const messages: StreamMessage[] = []; let pending = initial.subarray(boundary + 4); let totalBytes = pending.length; if (totalBytes > options.maxBytes) { socket.destroy(); throw new Error("WEBSOCKET_RESPONSE_LIMIT_EXCEEDED"); } let fragmented: { opcode: number; chunks: Buffer[] } | undefined; const deadline = Date.now() + options.timeoutMs;
  try {
    while (messages.length < maxMessages && Date.now() < deadline) {
      const parsed = parseFrame(pending); if (!parsed) { let chunk: Buffer; try { chunk = await readChunk(socket, Math.max(1, deadline - Date.now()), options.abortSignal); } catch (error) { if (error instanceof Error && error.message === "PROTOCOL_READ_TIMEOUT") break; throw error; } totalBytes += chunk.length; if (totalBytes > options.maxBytes) throw new Error("WEBSOCKET_RESPONSE_LIMIT_EXCEEDED"); pending = Buffer.concat([pending, chunk]); continue; }
      pending = pending.subarray(parsed.bytes); if (parsed.opcode === 8) break; if (parsed.opcode === 9) { socket.write(encodeFrame(parsed.payload, 10)); continue; } if (parsed.opcode !== 0 && parsed.opcode !== 1 && parsed.opcode !== 2) continue;
      let payload = parsed.payload; if (parsed.opcode === 0) { if (!fragmented) continue; fragmented.chunks.push(parsed.payload); if (!parsed.fin) continue; payload = Buffer.concat(fragmented.chunks); fragmented = undefined; } else if (!parsed.fin) { fragmented = { opcode: parsed.opcode, chunks: [parsed.payload] }; continue; }
      const text = payload.toString("utf8"); let value: unknown = text; try { value = JSON.parse(text); } catch { /* text frame */ } const type = value && typeof value === "object" && typeof (value as Record<string, unknown>).type === "string" ? String((value as Record<string, unknown>).type) : undefined; messages.push({ ...(type ? { type } : {}), value }); if (!deferredSent && type === waitForTypeBeforeRest) { for (const message of outbound.slice(1)) socket.write(encodeFrame(Buffer.from(JSON.stringify(message), "utf8"), 1)); deferredSent = true; }
    }
  } finally { if (!socket.destroyed) { socket.write(encodeFrame(Buffer.alloc(0), 8)); socket.destroy(); } }
  return { statusCode, ...(responseHeaders["sec-websocket-protocol"] ? { protocol: responseHeaders["sec-websocket-protocol"] } : {}), messages };
}

export async function runHttp2(urlValue: string, method: string, headers: Readonly<Record<string, string>>, body: Buffer | undefined, maxMessages: number, options: ProtocolTransportOptions, declaredLength?: number): Promise<Http2Result> {
  const url = new URL(urlValue); const opened = await openHttp2(url, options);
  try { return await requestOnSession(opened.session, url, method, headers, body, maxMessages, options, declaredLength); }
  finally { opened.session.close(); if (!opened.socket.destroyed) opened.socket.destroy(); }
}

export async function runHttp2Desync(urlValue: string, method: string, headers: Readonly<Record<string, string>>, body: Buffer, declaredLength: number, sentinelPath: string, options: ProtocolTransportOptions): Promise<Http2DesyncResult> {
  const url = new URL(urlValue); const sentinelUrl = new URL(sentinelPath, url); if (sentinelUrl.origin !== url.origin) throw new Error("HTTP2_SENTINEL_ORIGIN_MISMATCH"); const opened = await openHttp2(url, options); const protocol = url.protocol === "https:" ? "h2" : "h2c";
  try {
    const probe = await requestOnSession(opened.session, url, method, headers, body, 1, options, declaredLength);
    let sentinel: Http2Result;
    try { sentinel = await requestOnSession(opened.session, sentinelUrl, "GET", headers, undefined, 1, options); }
    catch (error) { sentinel = { protocol, headers: {}, body: Buffer.alloc(0), grpcMessages: [], errorCode: error instanceof Error ? error.message : "HTTP2_SENTINEL_FAILURE" }; }
    return { probe, sentinel, sameSession: true };
  } finally { opened.session.close(); if (!opened.socket.destroyed) opened.socket.destroy(); }
}

async function openHttp2(url: URL, options: ProtocolTransportOptions): Promise<{ session: ClientHttp2Session; socket: Socket | TLSSocket }> {
  const socket = await pinnedSocket(url, options, url.protocol === "https:" ? ["h2"] : undefined); if (url.protocol === "https:" && (socket as TLSSocket).alpnProtocol !== "h2") { socket.destroy(); throw new Error("HTTP2_NEGOTIATION_FAILED"); }
  const session = connectHttp2(`${url.protocol}//${url.host}`, { createConnection: () => socket });
  session.on("error", () => { /* individual request/session state is reported by the active case */ });
  try { await onceSession(session, options.timeoutMs, options.abortSignal); return { session, socket }; }
  catch (error) { session.destroy(); socket.destroy(); throw error; }
}

async function requestOnSession(session: ClientHttp2Session, url: URL, method: string, headers: Readonly<Record<string, string>>, body: Buffer | undefined, maxMessages: number, options: ProtocolTransportOptions, declaredLength?: number): Promise<Http2Result> {
  const requestHeaders: Record<string, string | number> = { [h2.HTTP2_HEADER_METHOD]: method, [h2.HTTP2_HEADER_PATH]: `${url.pathname}${url.search}`, [h2.HTTP2_HEADER_SCHEME]: url.protocol.slice(0, -1), [h2.HTTP2_HEADER_AUTHORITY]: url.host, ...headers }; if (declaredLength !== undefined) requestHeaders[h2.HTTP2_HEADER_CONTENT_LENGTH] = declaredLength;
  return await new Promise<Http2Result>((resolve, reject) => {
    let stream: ReturnType<ClientHttp2Session["request"]>; try { stream = session.request(requestHeaders, { endStream: !body?.length }); } catch (error) { reject(error); return; }
    let responseHeaders: Record<string, string | string[]> = {}; const chunks: Buffer[] = []; let size = 0; let settled = false;
    const timer = setTimeout(() => finish(new Error("HTTP2_REQUEST_TIMEOUT")), options.timeoutMs); const abort = () => finish(new Error("HTTP2_REQUEST_ABORTED")); options.abortSignal?.addEventListener("abort", abort, { once: true });
    const finish = (error?: Error, errorCode?: string) => { if (settled) return; settled = true; clearTimeout(timer); options.abortSignal?.removeEventListener("abort", abort); stream.close(); if (error && !errorCode) reject(error); else { const bodyBuffer = Buffer.concat(chunks); const grpc = parseGrpcFrames(bodyBuffer, maxMessages); const statusCode = Number(responseHeaders[":status"]); const status = grpcStatus(responseHeaders); resolve({ ...(Number.isFinite(statusCode) && statusCode > 0 ? { statusCode } : {}), protocol: url.protocol === "https:" ? "h2" : "h2c", headers: responseHeaders, body: bodyBuffer, ...(status !== undefined ? { grpcStatus: status } : {}), grpcMessages: grpc, ...(errorCode ? { errorCode } : {}) }); } };
    stream.on("response", (incoming) => { responseHeaders = normalizeHeaders(incoming); }); stream.on("trailers", (incoming) => { responseHeaders = { ...responseHeaders, ...normalizeHeaders(incoming) }; }); stream.on("data", (chunk: Buffer) => { size += chunk.byteLength; if (size > options.maxBytes) { finish(undefined, "HTTP2_RESPONSE_LIMIT_EXCEEDED"); return; } chunks.push(Buffer.from(chunk)); }); stream.on("end", () => finish()); stream.on("error", (error: NodeJS.ErrnoException) => finish(undefined, error.code ?? error.message)); if (body?.length) stream.end(body); else stream.end();
  });
}

async function pinnedSocket(url: URL, options: ProtocolTransportOptions, alpn?: string[]): Promise<Socket | TLSSocket> {
  const secure = url.protocol === "https:" || url.protocol === "wss:"; const protocol = secure ? "https:" : "http:";
  const pin = await resolvePinnedDestination({ hostname: url.hostname, protocol, port: url.port || (secure ? "443" : "80") }, { allowedPrivateOrigins: options.allowedPrivateOrigins, dnsTimeoutMs: Math.min(options.timeoutMs, 5000), maxDnsAnswers: 16, ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}) });
  return await new Promise<Socket | TLSSocket>((resolve, reject) => {
    let settled = false; const finish = (error?: Error, socket?: Socket | TLSSocket) => { if (settled) return; settled = true; clearTimeout(timer); options.abortSignal?.removeEventListener("abort", abort); if (error) { socket?.destroy(); reject(error); } else resolve(socket!); };
    const timer = setTimeout(() => finish(new Error("PROTOCOL_CONNECT_TIMEOUT"), socket), options.timeoutMs); const abort = () => finish(new Error("PROTOCOL_CONNECT_ABORTED"), socket); let socket: Socket | TLSSocket;
    if (secure) socket = connectTls({ host: pin.address.address, port: Number(pin.port), servername: isIP(pin.hostname) ? undefined : pin.hostname, ALPNProtocols: alpn ?? ["http/1.1"], rejectUnauthorized: true, ...(options.tlsCa ? { ca: options.tlsCa } : {}) }, () => remoteMatches(socket, pin.address.address) ? finish(undefined, socket) : finish(new Error("PINNED_REMOTE_ADDRESS_MISMATCH"), socket));
    else socket = connectTcp({ host: pin.address.address, port: Number(pin.port), family: pin.address.family }, () => remoteMatches(socket, pin.address.address) ? finish(undefined, socket) : finish(new Error("PINNED_REMOTE_ADDRESS_MISMATCH"), socket));
    socket.once("error", (e) => finish(e, socket)); options.abortSignal?.addEventListener("abort", abort, { once: true });
  });
}

function encodeFrame(payload: Buffer, opcode: number): Buffer { const mask = randomBytes(4); const length = payload.byteLength; const extra = length < 126 ? 0 : length <= 0xffff ? 2 : 8; const frame = Buffer.alloc(2 + extra + 4 + length); frame[0] = 0x80 | opcode; frame[1] = 0x80 | (length < 126 ? length : length <= 0xffff ? 126 : 127); let offset = 2; if (extra === 2) { frame.writeUInt16BE(length, offset); offset += 2; } else if (extra === 8) { frame.writeBigUInt64BE(BigInt(length), offset); offset += 8; } mask.copy(frame, offset); offset += 4; for (let i = 0; i < length; i++) frame[offset + i] = payload[i]! ^ mask[i % 4]!; return frame; }
function parseFrame(buffer: Buffer): { fin: boolean; opcode: number; payload: Buffer; bytes: number } | undefined { if (buffer.length < 2) return; if ((buffer[0]! & 0x70) !== 0) throw new Error("WEBSOCKET_RESERVED_BITS_SET"); const fin = Boolean(buffer[0]! & 0x80), opcode = buffer[0]! & 0x0f, masked = Boolean(buffer[1]! & 0x80); if (masked) throw new Error("WEBSOCKET_SERVER_MASKED_FRAME"); let length = buffer[1]! & 0x7f, offset = 2; if (length === 126) { if (buffer.length < 4) return; length = buffer.readUInt16BE(2); offset = 4; } else if (length === 127) { if (buffer.length < 10) return; const n = buffer.readBigUInt64BE(2); if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("WEBSOCKET_FRAME_TOO_LARGE"); length = Number(n); offset = 10; } if (opcode >= 8 && (!fin || length > 125)) throw new Error("WEBSOCKET_CONTROL_FRAME_INVALID"); if (buffer.length < offset + length) return; const payload = Buffer.from(buffer.subarray(offset, offset + length)); return { fin, opcode, payload, bytes: offset + length }; }
function readUntil(socket: Socket | TLSSocket, delimiter: Buffer, timeout: number, max: number, signal?: AbortSignal): Promise<Buffer> { return new Promise((resolve, reject) => { let value = Buffer.alloc(0), settled = false; const timer = setTimeout(() => done(new Error("PROTOCOL_READ_TIMEOUT")), timeout); const abort = () => done(new Error("PROTOCOL_READ_ABORTED")); const closed = () => done(new Error("PROTOCOL_SOCKET_CLOSED")); const failed = (error: Error) => done(error); const data = (chunk: Buffer) => { value = Buffer.concat([value, chunk]); if (value.length > max) done(new Error("PROTOCOL_HEADER_LIMIT_EXCEEDED")); else if (value.indexOf(delimiter) >= 0) done(); }; const done = (error?: Error) => { if (settled) return; settled = true; clearTimeout(timer); socket.off("data", data); socket.off("error", failed); socket.off("end", closed); socket.off("close", closed); signal?.removeEventListener("abort", abort); error ? reject(error) : resolve(value); }; socket.on("data", data); socket.once("error", failed); socket.once("end", closed); socket.once("close", closed); signal?.addEventListener("abort", abort, { once: true }); }); }
function readChunk(socket: Socket | TLSSocket, timeout: number, signal?: AbortSignal): Promise<Buffer> { return new Promise((resolve, reject) => { let settled = false; const timer = setTimeout(() => done(new Error("PROTOCOL_READ_TIMEOUT")), timeout); const abort = () => done(new Error("PROTOCOL_READ_ABORTED")); const closed = () => done(new Error("PROTOCOL_SOCKET_CLOSED")); const failed = (error: Error) => done(error); const data = (chunk: Buffer) => done(undefined, chunk); const done = (error?: Error, value?: Buffer) => { if (settled) return; settled = true; clearTimeout(timer); socket.off("data", data); socket.off("error", failed); socket.off("end", closed); socket.off("close", closed); signal?.removeEventListener("abort", abort); error ? reject(error) : resolve(value!); }; socket.once("data", data); socket.once("error", failed); socket.once("end", closed); socket.once("close", closed); signal?.addEventListener("abort", abort, { once: true }); }); }
function onceSession(session: ClientHttp2Session, timeout: number, signal?: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { if (!session.connecting) return resolve(); const timer = setTimeout(() => done(new Error("HTTP2_SESSION_TIMEOUT")), timeout); const abort = () => done(new Error("HTTP2_SESSION_ABORTED")); const done = (error?: Error) => { clearTimeout(timer); signal?.removeEventListener("abort", abort); session.off("connect", connected); session.off("error", failed); error ? reject(error) : resolve(); }; const connected = () => done(); const failed = (e: Error) => done(e); session.once("connect", connected); session.once("error", failed); signal?.addEventListener("abort", abort, { once: true }); }); }
function normalizeHeaders(value: Record<string, string | string[] | number | undefined>): Record<string, string | string[]> { return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, Array.isArray(v) ? v : String(v)])); }
function parseGrpcFrames(body: Buffer, max: number): Buffer[] { const frames: Buffer[] = []; let offset = 0; while (offset + 5 <= body.length && frames.length < max) { const length = body.readUInt32BE(offset + 1); if (offset + 5 + length > body.length) break; frames.push(body.subarray(offset + 5, offset + 5 + length)); offset += 5 + length; } return frames; }
function grpcStatus(headers: Record<string, string | string[]>): number | undefined { const value = headers["grpc-status"]; const parsed = Number(Array.isArray(value) ? value[0] : value); return Number.isFinite(parsed) ? parsed : undefined; }
function remoteMatches(socket: Socket | TLSSocket, expected: string): boolean { const actual = socket.remoteAddress?.toLowerCase(); const wanted = expected.toLowerCase(); return actual === wanted || actual === `::ffff:${wanted}` || (actual?.replace(/^::ffff:/, "") === wanted); }
function completeSseEvents(value: string): number { return value.split(/\r?\n\r?\n/).slice(0, -1).filter((block) => block.split(/\r?\n/).some((line) => line.startsWith("data:") || line.startsWith("event:"))).length; }
function normalizeUndiciHeaders(value: Record<string, string | string[] | undefined>): Record<string, string | string[]> { return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, string | string[]] => entry[1] !== undefined)); }

interface NativeHttp3Request { method: string; path: string; headers: Readonly<Record<string, string>>; bodyBase64?: string; }
interface NativeHttp3Response { statusCode: number; protocol: "h3"; headers: Record<string, string | string[]>; bodyBase64: string; }

async function nativeHttp3(url: URL, pinnedAddress: string, family: 4 | 6, requests: readonly NativeHttp3Request[], options: ProtocolTransportOptions): Promise<{ responses: NativeHttp3Response[]; sameConnection: boolean }> {
  return runNativeHttp3Worker({ hostname: url.hostname, port: Number(url.port || "443"), pinnedAddress, family, timeoutMs: options.timeoutMs, maxBytes: options.maxBytes, requests: requests.map((item) => ({ ...item, headers: { ...item.headers } })), ...(options.tlsCa ? { ca: Buffer.isBuffer(options.tlsCa) ? options.tlsCa.toString("utf8") : options.tlsCa } : {}) }, options.abortSignal);
}

function runNativeHttp3Worker(input: { hostname: string; port: number; pinnedAddress: string; family: 4 | 6; timeoutMs: number; maxBytes: number; ca?: string; requests: Array<{ method: string; path: string; headers: Record<string, string>; bodyBase64?: string }> }, signal?: AbortSignal): Promise<{ responses: NativeHttp3Response[]; sameConnection: boolean }> {
  return new Promise((resolve, reject) => {
    const javascriptEntry = new URL("./NativeHttp3Worker.js", import.meta.url);
    const typescriptEntry = new URL("./NativeHttp3Worker.ts", import.meta.url);
    const sourceMode = fileURLToPath(import.meta.url).endsWith(".ts");
    const entry = fileURLToPath(sourceMode ? typescriptEntry : javascriptEntry);
    const childEnvironment = { ...(process.env.SYSTEMROOT ? { SYSTEMROOT: process.env.SYSTEMROOT } : {}), ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
    const child = spawn(process.execPath, [...(sourceMode ? ["--import", "tsx"] : []), entry], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env: childEnvironment });
    let settled = false;
    const output: Buffer[] = [], errorOutput: Buffer[] = [];
    let outputSize = 0, errorSize = 0;
    const outputLimit = Math.max(64 * 1024, input.maxBytes * Math.max(1, input.requests.length) * 2 + 64 * 1024);
    const timer = setTimeout(() => finish(new Error("HTTP3_NATIVE_TIMEOUT")), Math.max(1000, input.timeoutMs * Math.max(1, input.requests.length) + 1000));
    const abort = () => finish(new Error("HTTP3_NATIVE_ABORTED"));
    const finish = (error?: Error, value?: { responses: NativeHttp3Response[]; sameConnection: boolean }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (!child.killed) child.kill();
      error ? reject(error) : resolve(value!);
    };
    child.stdout.on("data", (chunk: Buffer) => {
      outputSize += chunk.length;
      if (outputSize > outputLimit) finish(new Error("HTTP3_NATIVE_OUTPUT_LIMIT"));
      else output.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk: Buffer) => { errorSize += chunk.length; if (errorSize <= 64 * 1024) errorOutput.push(Buffer.from(chunk)); });
    child.once("error", (error) => finish(error));
    child.once("close", (code) => {
      if (settled) return;
      if (code !== 0) return finish(new Error(`HTTP3_NATIVE_EXIT_${code ?? "UNKNOWN"}`));
      let message: unknown;
      try { message = JSON.parse(Buffer.concat(output).toString("utf8")); } catch { return finish(new Error("HTTP3_NATIVE_INVALID_RESULT")); }
      if (!message || typeof message !== "object") return finish(new Error("HTTP3_NATIVE_INVALID_RESULT"));
      const result = message as { ok?: boolean; error?: string; responses?: NativeHttp3Response[]; sameConnection?: boolean };
      if (!result.ok || !Array.isArray(result.responses)) return finish(new Error(result.error ?? `HTTP3_NATIVE_FAILURE${errorOutput.length ? ":RUNTIME" : ""}`));
      finish(undefined, { responses: result.responses, sameConnection: result.sameConnection === true });
    });
    signal?.addEventListener("abort", abort, { once: true });
    child.stdin.end(JSON.stringify(input));
  });
}
