import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createSocket, type Socket as UdpSocket } from "node:dgram";
import { createServer as createTcpServer, type Server as TcpServer, type Socket } from "node:net";
import { readFile } from "node:fs/promises";
import { createHash, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type { Server } from "node:http";
import type { OastServiceConfig } from "./OastConfig.js";
import { OastStore } from "./OastStore.js";

const leaseRequestSchema = z.object({
  tenantId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/), workerId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/), jobId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/), caseId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/),
  ttlSeconds: z.number().int().min(30).max(7 * 24 * 60 * 60), protocols: z.array(z.enum(["DNS", "HTTP", "HTTPS"])).min(1).max(3).refine((value) => new Set(value).size === value.length)
}).strict();

export class OastService {
  private readonly store: OastStore;
  private http?: Server;
  private https?: Server;
  private udp?: UdpSocket;
  private tcp?: TcpServer;

  public constructor(private readonly config: OastServiceConfig, private readonly secrets: { signingKey: Buffer; tenantTokens: ReadonlyMap<string, string> }) {
    const httpBase = config.publicHttpBaseUrl ?? (config.mode === "SELF_HOSTED" ? `http://${displayHost(config.listenHost)}:${config.httpPort}/` : undefined);
    const httpsBase = config.publicHttpsBaseUrl ?? (config.mode === "SELF_HOSTED" && config.httpsPort ? `https://${displayHost(config.listenHost)}:${config.httpsPort}/` : undefined);
    this.store = new OastStore(config.databasePath, secrets.signingKey, config.baseDomain.toLowerCase(), httpBase, httpsBase, config.maxLeaseSeconds, config.maxEventsPerLease);
  }

  public async start(): Promise<void> {
    try {
    this.http = createHttpServer((request, response) => { void this.handleHttp(request, response, "HTTP"); });
    hardenHttpServer(this.http);
    await listen(this.http, this.config.httpPort, this.config.listenHost);
    if (this.config.httpsPort && this.config.tlsKeyPath && this.config.tlsCertPath) {
      const [key, cert] = await Promise.all([readFile(this.config.tlsKeyPath), readFile(this.config.tlsCertPath)]);
      this.https = createHttpsServer({ key, cert }, (request, response) => { void this.handleHttp(request, response, "HTTPS"); });
      hardenHttpServer(this.https);
      await listen(this.https, this.config.httpsPort, this.config.listenHost);
    }
    this.udp = createSocket(this.config.listenHost.includes(":") ? "udp6" : "udp4");
    this.udp.on("message", (message, remote) => { try { const response = this.handleDns(message, remote.address); if (response) this.udp?.send(response, remote.port, remote.address, () => undefined); } catch { /* Reject malformed or failed callbacks without terminating the listener. */ } });
    await bindUdp(this.udp, this.config.dnsUdpPort, this.config.listenHost);
    this.tcp = createTcpServer((socket) => this.handleDnsTcp(socket));
    await listenTcp(this.tcp, this.config.dnsTcpPort, this.config.listenHost);
    } catch (error) {
      await this.close().catch(() => undefined);
      throw error;
    }
  }

  public async close(): Promise<void> {
    await Promise.all([closeServer(this.http), closeServer(this.https), closeUdp(this.udp), closeTcp(this.tcp)]);
    this.store.close();
  }

  private async handleHttp(request: IncomingMessage, response: ServerResponse, protocol: "HTTP" | "HTTPS"): Promise<void> {
    try {
      const url = new URL(request.url ?? "/", `${protocol.toLowerCase()}://oast.invalid`);
      if (request.method === "GET" && url.pathname === "/healthz") return json(response, 200, { status: "ok", mode: this.config.mode });
      const management = url.pathname === "/v1/leases" || /^\/v1\/leases\/[a-z0-9_-]{16,32}\/events$/.test(url.pathname);
      if (management && this.config.mode === "HOSTED" && protocol !== "HTTPS") return json(response, 426, { error: "https_required" });
      if (request.method === "POST" && url.pathname === "/v1/leases") {
        if (!String(request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) return json(response, 415, { error: "application_json_required" });
        const body = leaseRequestSchema.safeParse(JSON.parse((await readBody(request, this.config.maxRequestBytes)).toString("utf8")));
        if (!body.success) return json(response, 400, { error: "invalid_lease_request" });
        const tenantToken = this.secrets.tenantTokens.get(body.data.tenantId);
        if (!tenantToken || !bearerMatches(request, tenantToken)) return json(response, 401, { error: "unauthorized" });
        if (body.data.ttlSeconds > this.config.maxLeaseSeconds) return json(response, 400, { error: "lease_ttl_exceeds_service_limit" });
        if (body.data.protocols.includes("HTTP") && this.config.mode === "HOSTED" && !this.config.publicHttpBaseUrl) return json(response, 400, { error: "http_callback_unavailable" });
        if (body.data.protocols.includes("HTTPS") && !this.https) return json(response, 400, { error: "https_callback_unavailable" });
        return json(response, 201, this.store.createLease(body.data));
      }
      const poll = /^\/v1\/leases\/([a-z0-9_-]{16,32})\/events$/.exec(url.pathname);
      if (poll && request.method === "GET") {
        const result = this.store.poll(poll[1]!, bearer(request) ?? "");
        return result ? json(response, 200, result) : json(response, 401, { error: "invalid_poll_token" });
      }
      if (poll && request.method === "DELETE") {
        return this.store.revoke(poll[1]!, bearer(request) ?? "") ? json(response, 204, undefined) : json(response, 401, { error: "invalid_poll_token" });
      }
      const callback = /^\/c\/([a-f0-9]{32})\/([a-f0-9]{32})$/.exec(url.pathname);
      if (callback) {
        const lease = this.store.validateIdentity(callback[1]!, callback[2]!, protocol);
        if (!lease) return json(response, 404, { error: "callback_identity_invalid_or_expired" });
        const body = await readBody(request, this.config.maxRequestBytes);
        const material = [request.method ?? "GET", url.pathname, canonicalQueryKeys(url), canonicalHeaderNames(request), body.length, bodyHash(body)].join("\0");
        const recorded = this.store.record(lease, protocol, request.socket.remoteAddress ?? "unknown", material);
        return json(response, recorded.replay ? 409 : recorded.accepted ? 202 : 429, { accepted: recorded.accepted, replay: recorded.replay });
      }
      json(response, 404, { error: "not_found" });
    } catch (error) { json(response, error instanceof Error && error.message === "REQUEST_TOO_LARGE" ? 413 : 400, { error: "invalid_request" }); }
  }

  private handleDns(message: Buffer, source: string): Buffer | undefined {
    const parsed = parseDnsQuery(message);
    if (!parsed) return;
    const identity = identityFromDnsName(parsed.name, this.config.baseDomain);
    if (!identity) return dnsResponse(message, parsed, undefined, this.config);
    const lease = this.store.validateIdentity(identity.leaseId, identity.signature, "DNS");
    if (!lease) return dnsResponse(message, parsed, undefined, this.config);
    this.store.record(lease, "DNS", source, `${parsed.name}\0${parsed.type}`);
    return dnsResponse(message, parsed, parsed.type === 28 ? "AAAA" : parsed.type === 1 ? "A" : undefined, this.config);
  }

  private handleDnsTcp(socket: Socket): void {
    let pending = Buffer.alloc(0); let expected: number | undefined;
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length > 65537) return socket.destroy();
      if (expected === undefined && pending.length >= 2) { expected = pending.readUInt16BE(0); pending = pending.subarray(2); }
      if (expected === undefined || pending.length < expected) return;
      try { const response = this.handleDns(pending.subarray(0, expected), socket.remoteAddress ?? "unknown"); if (response) { const prefix = Buffer.alloc(2); prefix.writeUInt16BE(response.length); socket.end(Buffer.concat([prefix, response])); } else socket.end(); }
      catch { socket.destroy(); }
    });
    socket.setTimeout(5000, () => socket.destroy());
  }
}

interface DnsQuery { name: string; type: number; questionEnd: number }
function parseDnsQuery(message: Buffer): DnsQuery | undefined {
  const flags = message.length >= 4 ? message.readUInt16BE(2) : 0xffff;
  if (message.length < 17 || message.readUInt16BE(4) !== 1 || (flags & 0x8000) !== 0 || (flags & 0x7800) !== 0) return;
  let offset = 12; const labels: string[] = [];
  while (offset < message.length) { const size = message[offset++]!; if (size === 0) break; if (size > 63 || offset + size > message.length) return; const label = message.subarray(offset, offset + size).toString("ascii"); if (!/^[A-Za-z0-9_-]+$/.test(label)) return; labels.push(label); offset += size; }
  if (labels.length < 3 || offset + 4 > message.length) return;
  if (message.readUInt16BE(offset + 2) !== 1) return;
  return { name: labels.join(".").toLowerCase(), type: message.readUInt16BE(offset), questionEnd: offset + 4 };
}
function dnsResponse(query: Buffer, parsed: DnsQuery, answer: "A" | "AAAA" | undefined, config: OastServiceConfig): Buffer {
  const header = Buffer.from(query.subarray(0, 12)); header.writeUInt16BE(answer ? 0x8180 : 0x8183, 2); header.writeUInt16BE(answer ? 1 : 0, 6); header.writeUInt16BE(0, 8); header.writeUInt16BE(0, 10);
  const question = query.subarray(12, parsed.questionEnd);
  if (!answer) return Buffer.concat([header, question]);
  const data = answer === "A" ? Buffer.from(config.dnsAnswerIpv4.split(".").map(Number)) : ipv6Bytes(config.dnsAnswerIpv6);
  const record = Buffer.alloc(12); record.writeUInt16BE(0xc00c, 0); record.writeUInt16BE(answer === "A" ? 1 : 28, 2); record.writeUInt16BE(1, 4); record.writeUInt32BE(30, 6); record.writeUInt16BE(data.length, 10);
  return Buffer.concat([header, question, record, data]);
}
function identityFromDnsName(name: string, baseDomain: string): { leaseId: string; signature: string } | undefined { const suffix = `.${baseDomain.toLowerCase()}`; if (!name.endsWith(suffix)) return; const labels = name.slice(0, -suffix.length).split("."); return labels.length === 2 ? { leaseId: labels[0]!, signature: labels[1]! } : undefined; }
function ipv6Bytes(value: string): Buffer { const normalized = value.includes(".") ? replaceEmbeddedIpv4(value) : value; const [left, right = ""] = normalized.split("::"); const a = left ? left.split(":") : []; const b = right ? right.split(":") : []; const parts = [...a, ...Array(Math.max(0, 8 - a.length - b.length)).fill("0"), ...b]; const output = Buffer.alloc(16); parts.slice(0, 8).forEach((part, index) => output.writeUInt16BE(Number.parseInt(part || "0", 16), index * 2)); return output; }
function replaceEmbeddedIpv4(value: string): string { const boundary = value.lastIndexOf(":"); const octets = value.slice(boundary + 1).split(".").map(Number); return `${value.slice(0, boundary)}:${((octets[0]! << 8) | octets[1]!).toString(16)}:${((octets[2]! << 8) | octets[3]!).toString(16)}`; }
async function readBody(request: IncomingMessage, maximum: number): Promise<Buffer> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of request) { const value = Buffer.from(chunk); size += value.length; if (size > maximum) throw new Error("REQUEST_TOO_LARGE"); chunks.push(value); } return Buffer.concat(chunks); }
function json(response: ServerResponse, status: number, value: unknown): void { response.statusCode = status; response.setHeader("cache-control", "no-store"); response.setHeader("pragma", "no-cache"); response.setHeader("x-content-type-options", "nosniff"); response.setHeader("content-type", "application/json; charset=utf-8"); response.end(value === undefined ? undefined : JSON.stringify(value)); }
function bearer(request: IncomingMessage): string | undefined { const match = /^Bearer ([A-Za-z0-9._~-]{20,200})$/.exec(String(request.headers.authorization ?? "")); return match?.[1]; }
function bearerMatches(request: IncomingMessage, expected: string): boolean { const value = bearer(request); if (!value) return false; const a = Buffer.from(value), b = Buffer.from(expected); return a.length === b.length && timingSafeEqual(a, b); }
function canonicalQueryKeys(url: URL): string { return [...new Set([...url.searchParams.keys()])].sort().join(","); }
function canonicalHeaderNames(request: IncomingMessage): string { return Object.keys(request.headers).map((name) => name.toLowerCase()).filter((name) => !["authorization", "cookie", "proxy-authorization"].includes(name)).sort().join(","); }
function bodyHash(value: Buffer): string { return value.length ? createHash("sha256").update(value).digest("hex") : "empty"; }
function displayHost(value: string): string { return value.includes(":") ? `[${value}]` : value; }
function hardenHttpServer(server: Server): void { server.requestTimeout = 10_000; server.headersTimeout = 5_000; server.keepAliveTimeout = 5_000; server.maxHeadersCount = 50; server.maxRequestsPerSocket = 100; }
function listen(server: Server, port: number, host: string): Promise<void> { return new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => { server.off("error", reject); resolve(); }); }); }
function listenTcp(server: TcpServer, port: number, host: string): Promise<void> { return new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => { server.off("error", reject); resolve(); }); }); }
function bindUdp(socket: UdpSocket, port: number, host: string): Promise<void> { return new Promise((resolve, reject) => { socket.once("error", reject); socket.bind(port, host, () => { socket.off("error", reject); resolve(); }); }); }
function closeServer(server?: Server): Promise<void> { return !server ? Promise.resolve() : new Promise((resolve) => server.close(() => resolve())); }
function closeTcp(server?: TcpServer): Promise<void> { return !server ? Promise.resolve() : new Promise((resolve) => server.close(() => resolve())); }
function closeUdp(socket?: UdpSocket): Promise<void> { return !socket ? Promise.resolve() : new Promise((resolve) => { socket.once("close", resolve); socket.close(); }); }
