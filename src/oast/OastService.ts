import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createSocket, type Socket as UdpSocket } from "node:dgram";
import { createServer as createTcpServer, isIP, type Server as TcpServer, type Socket } from "node:net";
import { readFile } from "node:fs/promises";
import { createHash, timingSafeEqual, X509Certificate } from "node:crypto";
import type { Server as HttpsServer } from "node:https";
import { z } from "zod";
import type { Server } from "node:http";
import type { OastServiceConfig } from "./OastConfig.js";
import { OastStore } from "./OastStore.js";
import { answerOastDns, oastDnsIdentity, parseOastDnsQuery } from "./OastDns.js";

const leaseRequestSchema = z.object({
  tenantId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/), workerId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/), jobId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/), caseId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/),
  ttlSeconds: z.number().int().min(30).max(7 * 24 * 60 * 60), protocols: z.array(z.enum(["DNS", "HTTP", "HTTPS"])).min(1).max(3).refine((value) => new Set(value).size === value.length)
}).strict();

export class OastService {
  private readonly store: OastStore;
  private http?: Server;
  private https?: HttpsServer;
  private udp?: UdpSocket;
  private tcp?: TcpServer;
  private readonly sockets = new Set<Socket>();
  private closed = false;
  private closing?: Promise<void>;
  private tlsExpiresAt = 0;
  private windowStartedAt = 0;
  private requestsInWindow = 0;
  private maintenance?: NodeJS.Timeout;

  public constructor(private readonly config: OastServiceConfig, private readonly secrets: { signingKey: Buffer; tenantTokens: ReadonlyMap<string, string> }) {
    const httpBase = config.publicHttpBaseUrl ?? (config.mode === "SELF_HOSTED" ? `http://${displayHost(config.listenHost)}:${config.httpPort}/` : undefined);
    const httpsBase = config.publicHttpsBaseUrl ?? (config.mode === "SELF_HOSTED" && config.httpsPort ? `https://${displayHost(config.listenHost)}:${config.httpsPort}/` : undefined);
    this.store = new OastStore(config.databasePath, secrets.signingKey, config.baseDomain.toLowerCase(), httpBase, httpsBase, config.maxLeaseSeconds, config.maxEventsPerLease, Date.now, { maxLeases: config.maxLeases ?? 10000, evidenceRetentionSeconds: config.evidenceRetentionSeconds ?? 7 * 86400 });
  }

  public async start(): Promise<void> {
    if (this.http || this.closed) throw new Error("OAST_SERVICE_ALREADY_STARTED_OR_CLOSED");
    try {
    this.http = createHttpServer((request, response) => { void this.handleHttp(request, response, "HTTP"); });
    hardenHttpServer(this.http);
    this.http.on("connection", (socket) => this.trackSocket(socket));
    await listen(this.http, this.config.httpPort, this.config.listenHost);
    if (this.config.httpsPort && this.config.tlsKeyPath && this.config.tlsCertPath) {
      const [key, cert] = await Promise.all([readFile(this.config.tlsKeyPath), readFile(this.config.tlsCertPath)]);
      this.validateCertificate(cert);
      this.https = createHttpsServer({ key, cert, minVersion: "TLSv1.2", handshakeTimeout: 5000 }, (request, response) => { void this.handleHttp(request, response, "HTTPS"); });
      hardenHttpServer(this.https);
      this.https.on("connection", (socket) => this.trackSocket(socket as Socket));
      await listen(this.https, this.config.httpsPort, this.config.listenHost);
    }
    this.udp = createSocket(this.config.listenHost.includes(":") ? "udp6" : "udp4");
    this.udp.on("message", (message, remote) => { try { const response = this.handleDns(message, remote.address); if (response) this.udp?.send(response, remote.port, remote.address, () => undefined); } catch { /* Reject malformed or failed callbacks without terminating the listener. */ } });
    await bindUdp(this.udp, this.config.dnsUdpPort, this.config.listenHost);
    this.tcp = createTcpServer((socket) => { if (this.trackSocket(socket)) this.handleDnsTcp(socket); });
    await listenTcp(this.tcp, this.config.dnsTcpPort, this.config.listenHost);
    this.store.prune();
    this.maintenance = setInterval(() => this.store.prune(), 60000); this.maintenance.unref();
    } catch (error) {
      await this.close().catch(() => undefined);
      throw error;
    }
  }

  public async close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true; clearInterval(this.maintenance);
    for (const socket of this.sockets) socket.destroy();
    this.closing = (async () => { await Promise.all([closeServer(this.http), closeServer(this.https), closeUdp(this.udp), closeTcp(this.tcp)]); this.store.close(); })();
    return this.closing;
  }

  /** Renew certificates atomically, without restarting or losing leases. */
  public async reloadTls(): Promise<void> {
    if (!this.https || this.closed || !this.config.tlsKeyPath || !this.config.tlsCertPath) throw new Error("OAST_TLS_LISTENER_UNAVAILABLE");
    const [key, cert] = await Promise.all([readFile(this.config.tlsKeyPath), readFile(this.config.tlsCertPath)]);
    const expiry = this.validateCertificate(cert, false);
    this.https.setSecureContext({ key, cert, minVersion: "TLSv1.2" }); this.tlsExpiresAt = expiry;
  }

  private validateCertificate(cert: Buffer, update = true): number {
    const leaf = new X509Certificate(cert), expiry = Date.parse(leaf.validTo);
    if (Date.parse(leaf.validFrom) > Date.now() || expiry <= Date.now()) throw new Error("OAST_TLS_CERTIFICATE_NOT_CURRENT");
    const host = new URL(this.config.publicHttpsBaseUrl ?? `https://${displayHost(this.config.listenHost)}`).hostname.replace(/^\[|\]$/g, "");
    if (!(isIP(host) ? leaf.checkIP(host) : leaf.checkHost(host))) throw new Error("OAST_TLS_CERTIFICATE_HOST_MISMATCH");
    if (update) this.tlsExpiresAt = expiry; return expiry;
  }

  private trackSocket(socket: Socket): boolean {
    socket.on("error", () => undefined);
    if (this.closed || this.sockets.size >= (this.config.maxConnections ?? 200)) { socket.destroy(); return false; }
    this.sockets.add(socket); socket.once("close", () => this.sockets.delete(socket)); return true;
  }
  private allowRequest(): boolean {
    const now = Date.now(); if (now - this.windowStartedAt >= 1000) { this.windowStartedAt = now; this.requestsInWindow = 0; }
    return ++this.requestsInWindow <= (this.config.maxRequestsPerSecond ?? 500);
  }

  private async handleHttp(request: IncomingMessage, response: ServerResponse, protocol: "HTTP" | "HTTPS"): Promise<void> {
    try {
      const url = new URL(request.url ?? "/", `${protocol.toLowerCase()}://oast.invalid`);
      if (request.method === "GET" && url.pathname === "/healthz") return json(response, 200, { status: "ok", mode: this.config.mode });
      if (request.method === "GET" && url.pathname === "/readyz") { const ready = !this.closed && !!this.tcp?.listening && (!this.https || this.tlsExpiresAt > Date.now() + 60000); return json(response, ready ? 200 : 503, { ready, serviceConfigSha256: this.config.sourceSha256 ?? createHash("sha256").update(JSON.stringify(this.config)).digest("hex") }); }
      if (!this.allowRequest()) return json(response, 429, { error: "service_request_limit" });
      const management = url.pathname === "/v1/leases" || /^\/v1\/leases\/[a-z0-9_-]{16,32}\/events$/.test(url.pathname);
      if (management && protocol !== "HTTPS" && (this.config.mode === "HOSTED" || !isLoopbackAddress(request.socket.remoteAddress))) return json(response, 426, { error: "https_required" });
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
    } catch (error) { if (!response.destroyed) json(response, error instanceof Error && error.message === "OAST_LEASE_LIMIT" ? 429 : error instanceof Error && error.message === "REQUEST_TOO_LARGE" ? 413 : 400, { error: "invalid_request" }); }
  }

  private handleDns(message: Buffer, source: string, tcp = false): Buffer | undefined {
    if (!this.allowRequest()) return;
    const parsed = parseOastDnsQuery(message);
    if (!parsed) return;
    const identity = oastDnsIdentity(parsed.name, this.config.baseDomain);
    const lease = identity ? this.store.validateIdentity(identity.leaseId, identity.signature, "DNS") : undefined;
    if (lease) this.store.record(lease, "DNS", source, `${parsed.name}\0${parsed.type}`);
    return answerOastDns(message, parsed, !!lease, this.config, tcp);
  }

  private handleDnsTcp(socket: Socket): void {
    let pending = Buffer.alloc(0); let expected: number | undefined; let handled = false;
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      pending = Buffer.concat([pending, chunk]);
      if (pending.length > 4098) return socket.destroy();
      if (expected === undefined && pending.length >= 2) { expected = pending.readUInt16BE(0); pending = pending.subarray(2); }
      if (expected !== undefined && (expected < 17 || expected > 4096)) return socket.destroy();
      if (expected === undefined || pending.length < expected) return;
      handled = true;
      try { const response = this.handleDns(pending.subarray(0, expected), socket.remoteAddress ?? "unknown", true); if (response) { const prefix = Buffer.alloc(2); prefix.writeUInt16BE(response.length); socket.end(Buffer.concat([prefix, response])); } else socket.end(); }
      catch { socket.destroy(); }
    });
    socket.setTimeout(5000, () => socket.destroy());
  }
}

async function readBody(request: IncomingMessage, maximum: number): Promise<Buffer> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of request) { const value = Buffer.from(chunk); size += value.length; if (size > maximum) throw new Error("REQUEST_TOO_LARGE"); chunks.push(value); } return Buffer.concat(chunks); }
function json(response: ServerResponse, status: number, value: unknown): void { response.statusCode = status; response.setHeader("cache-control", "no-store"); response.setHeader("pragma", "no-cache"); response.setHeader("x-content-type-options", "nosniff"); response.setHeader("content-type", "application/json; charset=utf-8"); response.end(value === undefined ? undefined : JSON.stringify(value)); }
function bearer(request: IncomingMessage): string | undefined { const match = /^Bearer ([A-Za-z0-9._~-]{20,200})$/.exec(String(request.headers.authorization ?? "")); return match?.[1]; }
function bearerMatches(request: IncomingMessage, expected: string): boolean { const value = bearer(request); if (!value) return false; const a = Buffer.from(value), b = Buffer.from(expected); return a.length === b.length && timingSafeEqual(a, b); }
function canonicalQueryKeys(url: URL): string { return [...new Set([...url.searchParams.keys()])].sort().join(","); }
function canonicalHeaderNames(request: IncomingMessage): string { return Object.keys(request.headers).map((name) => name.toLowerCase()).filter((name) => !["authorization", "cookie", "proxy-authorization"].includes(name)).sort().join(","); }
function bodyHash(value: Buffer): string { return value.length ? createHash("sha256").update(value).digest("hex") : "empty"; }
function displayHost(value: string): string { return value.includes(":") ? `[${value}]` : value; }
function isLoopbackAddress(value?: string): boolean { return !!value && (value === "::1" || /^127\./.test(value) || /^::ffff:127\./i.test(value)); }
function hardenHttpServer(server: Server): void { server.requestTimeout = 10_000; server.headersTimeout = 5_000; server.keepAliveTimeout = 5_000; server.maxHeadersCount = 50; server.maxRequestsPerSocket = 100; }
function listen(server: Server, port: number, host: string): Promise<void> { return new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => { server.off("error", reject); resolve(); }); }); }
function listenTcp(server: TcpServer, port: number, host: string): Promise<void> { return new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => { server.off("error", reject); resolve(); }); }); }
function bindUdp(socket: UdpSocket, port: number, host: string): Promise<void> { return new Promise((resolve, reject) => { socket.once("error", reject); socket.bind(port, host, () => { socket.off("error", reject); resolve(); }); }); }
function closeServer(server?: Server): Promise<void> { return !server ? Promise.resolve() : new Promise((resolve) => server.close(() => resolve())); }
function closeTcp(server?: TcpServer): Promise<void> { return !server ? Promise.resolve() : new Promise((resolve) => server.close(() => resolve())); }
function closeUdp(socket?: UdpSocket): Promise<void> { return !socket ? Promise.resolve() : new Promise((resolve) => { socket.once("close", resolve); try { socket.close(); } catch { resolve(); } }); }
