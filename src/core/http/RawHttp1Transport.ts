import { lookup } from "node:dns/promises";
import { createHash } from "node:crypto";
import { connect as tcpConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { isProhibitedAddress } from "../net/AddressClassifier.js";

export interface RawHttp1Request {
  url: string;
  method: "POST";
  headers: Readonly<Record<string, string>>;
  body: string;
  sentinelPath: string;
  marker?: string;
  variant: "CL_TE" | "TE_CL";
  timeoutMs: number;
  maxResponseBytes: number;
  userAgent: string;
  abortSignal?: AbortSignal;
  targetOrigin: string;
  dnsResolver?: (hostname: string) => Promise<readonly (string | { address: string; family: 4 | 6 })[]>;
}

export interface RawHttp1Response {
  requestedUrl: string;
  statusCodes: readonly number[];
  responseCount: number;
  bodyPreview: string;
  bodyHash: string;
  responseTimeMs: number;
  transmittedRequests: number;
  markerObserved: boolean;
  error?: { name: string; message: string };
}

const framingHeaders = new Set(["host", "content-length", "transfer-encoding", "connection", "proxy-connection", "expect", "upgrade", "trailer"]);

export async function sendRawHttp1(request: RawHttp1Request): Promise<RawHttp1Response> {
  const parsed = new URL(request.url);
  const sentinel = new URL(request.sentinelPath, parsed.origin);
  const startedAt = performance.now();
  try {
    const address = await selectAddress(request, parsed.hostname);
    const wire = buildWireRequest(request, parsed, sentinel);
    const bytes = await exchange(request, address, parsed, wire);
    const parsedResponse = parseResponses(bytes, request.maxResponseBytes);
    const bodyPreview = parsedResponse.body.subarray(0, request.maxResponseBytes).toString("utf8");
    return {
      requestedUrl: request.url,
      statusCodes: parsedResponse.statusCodes,
      responseCount: parsedResponse.statusCodes.length,
      bodyPreview,
      bodyHash: createHash("sha256").update(parsedResponse.body).digest("hex"),
      responseTimeMs: Math.round(performance.now() - startedAt),
      transmittedRequests: 2,
      markerObserved: Boolean(request.marker && parsedResponse.body.includes(request.marker))
    };
  } catch (error) {
    return {
      requestedUrl: request.url,
      statusCodes: [],
      responseCount: 0,
      bodyPreview: "",
      bodyHash: createHash("sha256").update("").digest("hex"),
      responseTimeMs: Math.round(performance.now() - startedAt),
      transmittedRequests: 2,
      markerObserved: false,
      error: { name: error instanceof Error ? error.name : "RawHttp1TransportError", message: error instanceof Error ? error.message.slice(0, 240) : "Raw HTTP/1 transport failed." }
    };
  }
}

async function selectAddress(request: RawHttp1Request, hostname: string): Promise<{ address: string; family: 4 | 6 }> {
  const answers = request.dnsResolver
    ? await request.dnsResolver(hostname)
    : (await lookup(hostname, { all: true, verbatim: true })).map((item) => ({ address: item.address, family: item.family as 4 | 6 }));
  const normalized = answers.map((item) => typeof item === "string" ? { address: item, family: item.includes(":") ? 6 as const : 4 as const } : item).filter((item) => item.address);
  if (normalized.length === 0) throw new Error("RAW_HTTP1_DNS_EMPTY");
  const target = new URL(request.targetOrigin);
  const exactPrivateOrigin = target.hostname.toLowerCase() === hostname.toLowerCase() && target.port === new URL(request.url).port;
  const safe = normalized.filter((item) => !isProhibitedAddress(item.address) || exactPrivateOrigin);
  if (safe.length !== normalized.length) throw new Error("RAW_HTTP1_DNS_PROHIBITED_ADDRESS");
  if (safe.length === 0) throw new Error("RAW_HTTP1_DNS_PROHIBITED_ADDRESS");
  return safe[0]!;
}

function buildWireRequest(request: RawHttp1Request, parsed: URL, sentinel: URL): Buffer {
  const target = `${parsed.pathname || "/"}${parsed.search}`;
  const host = parsed.host;
  const safeBody = request.body.replace(/[\r\n\0]/g, " ").slice(0, 4096);
  const bodyBytes = Buffer.from(safeBody, "utf8");
  const chunked = bodyBytes.length > 0 ? `${bodyBytes.length.toString(16)}\r\n${safeBody}\r\n0\r\n\r\n` : "0\r\n\r\n";
  const smuggled = `GET ${sentinel.pathname || "/"}${sentinel.search} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n${request.marker ? `X-RouteCairn-Sentinel: ${request.marker}\r\n` : ""}\r\n`;
  const payload = `${chunked}${smuggled}`;
  const ambiguousLength = Buffer.byteLength(chunked, "utf8") + (request.variant === "TE_CL" ? 1 : 0);
  const customHeaders = Object.entries(request.headers)
    .filter(([name]) => !framingHeaders.has(name.toLowerCase()))
    .map(([name, value]) => `${name}: ${value}`)
    .join("\r\n");
  const framing = request.variant === "CL_TE"
    ? `Content-Length: ${ambiguousLength}\r\nTransfer-Encoding: chunked`
    : `Transfer-Encoding: chunked\r\nContent-Length: ${ambiguousLength}`;
  const headers = [`${request.method} ${target} HTTP/1.1`, `Host: ${host}`, `User-Agent: ${request.userAgent}`, "Connection: close", framing, customHeaders].filter(Boolean).join("\r\n");
  return Buffer.from(`${headers}\r\n\r\n${payload}`, "utf8");
}

function exchange(request: RawHttp1Request, address: { address: string; family: 4 | 6 }, parsed: URL, wire: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let socket: Socket | TLSSocket;
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      request.abortSignal?.removeEventListener("abort", abort);
      if (error) reject(error); else resolve(Buffer.concat(chunks));
    };
    const abort = () => { socket?.destroy(); finish(new Error("RAW_HTTP1_ABORTED")); };
    const options = { host: address.address, port: Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80)), family: address.family, timeout: request.timeoutMs };
    socket = parsed.protocol === "https:" ? tlsConnect({ ...options, servername: parsed.hostname, rejectUnauthorized: true }) : tcpConnect(options);
    socket.setTimeout(request.timeoutMs, () => { socket.destroy(); finish(new Error("RAW_HTTP1_TIMEOUT")); });
    if (parsed.protocol === "https:") socket.on("secureConnect", () => socket.write(wire));
    else socket.on("connect", () => socket.write(wire));
    socket.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > request.maxResponseBytes) { finish(new Error("RAW_HTTP1_RESPONSE_LIMIT")); socket.destroy(); return; } chunks.push(Buffer.from(chunk)); });
    socket.on("end", () => finish());
    socket.on("close", () => finish());
    socket.on("error", (error) => finish(error));
    request.abortSignal?.addEventListener("abort", abort, { once: true });
  });
}

function parseResponses(buffer: Buffer, maxBytes: number): { statusCodes: number[]; body: Buffer } {
  const bounded = buffer.subarray(0, maxBytes);
  const marker = Buffer.from("HTTP/1.", "latin1");
  const statusCodes: number[] = [];
  const bodyParts: Buffer[] = [];
  let cursor = 0;
  while (cursor < bounded.length) {
    const start = bounded.indexOf(marker, cursor);
    if (start < 0) break;
    const headerEnd = bounded.indexOf(Buffer.from("\r\n\r\n", "latin1"), start);
    if (headerEnd < 0) break;
    const header = bounded.subarray(start, headerEnd).toString("latin1");
    const status = /HTTP\/1\.[01]\s+(\d{3})\b/.exec(header)?.[1];
    if (status) statusCodes.push(Number(status));
    const bodyStart = headerEnd + 4;
    const contentLength = /(?:^|\r\n)content-length:\s*(\d+)/i.exec(header)?.[1];
    const nextStart = bounded.indexOf(marker, bodyStart);
    const bodyEnd = contentLength !== undefined ? Math.min(bounded.length, bodyStart + Number(contentLength)) : nextStart >= 0 ? nextStart : bounded.length;
    if (bodyEnd > bodyStart) bodyParts.push(bounded.subarray(bodyStart, bodyEnd));
    cursor = Math.max(bodyEnd, bodyStart + 1);
  }
  return { statusCodes, body: Buffer.concat(bodyParts).subarray(0, maxBytes) };
}
