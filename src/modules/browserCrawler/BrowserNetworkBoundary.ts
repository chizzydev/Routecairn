import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, request as createHttpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { connect, isIP, type Socket } from "node:net";
import type { Duplex } from "node:stream";
import type { DnsResolver } from "../../core/http/HttpTypes.js";
import { PinnedConnectionError, resolvePinnedDestination } from "../../core/http/PinnedHttpTransport.js";
import type { BrowserPolicy } from "./BrowserPolicy.js";

export type BrowserNetworkBoundaryState = "STARTING" | "HEALTHY" | "DEGRADED" | "STOPPED";

export interface BrowserNetworkBoundaryDiagnostics {
  state: BrowserNetworkBoundaryState;
  generation: number;
  connectionsAttempted: number;
  connectionsAllowed: number;
  connectionsBlocked: number;
  activeConnections: number;
  pinnedDestinationCount: number;
  lastFailureCode?: string;
  startedAt: string;
  stoppedAt?: string;
  coverage: readonly ["pages", "frames", "workers", "downloads", "websockets", "browser-api"];
}

export interface BrowserNetworkBoundaryOptions {
  targetUrl: string;
  policy: BrowserPolicy;
  timeoutMs: number;
  dnsResolver?: DnsResolver;
  generation?: number;
  onStatus?(diagnostics: BrowserNetworkBoundaryDiagnostics): void;
}

interface PinnedSocket {
  socket: Socket;
  addressFingerprint: string;
}

/**
 * Loopback-only authenticated browser proxy. Every upstream connection is made
 * to a DNS answer selected and classified immediately before net.connect().
 * Chromium retains the original hostname for HTTP Host and TLS SNI.
 */
export class BrowserNetworkBoundary {
  private readonly username = `routecairn-${randomBytes(9).toString("hex")}`;
  private readonly password = randomBytes(24).toString("base64url");
  private readonly sockets = new Set<Duplex>();
  private readonly pinnedDestinations = new Set<string>();
  private readonly server = createServer((request, response) => { void this.forwardHttp(request, response); });
  private state: BrowserNetworkBoundaryState = "STARTING";
  private startedAt = new Date().toISOString();
  private stoppedAt: string | undefined;
  private connectionsAttempted = 0;
  private connectionsAllowed = 0;
  private connectionsBlocked = 0;
  private lastFailureCode: string | undefined;
  private fatalFailure: PinnedConnectionError | undefined;
  private port = 0;

  public constructor(private readonly options: BrowserNetworkBoundaryOptions) {
    this.server.on("connection", (socket) => this.track(socket));
    this.server.on("connect", (request, socket, head) => { void this.forwardConnect(request, socket, head); });
    this.server.on("upgrade", (request, socket, head) => { void this.forwardWebSocket(request, socket, head); });
    this.server.on("clientError", (_error, socket) => socket.destroy());
    this.server.on("error", () => this.recordFatal("PROXY_SERVER_ERROR"));
    this.server.on("close", () => {
      if (this.state !== "STOPPED") this.recordFatal("PROXY_SERVER_CLOSED");
    });
  }

  public async start(): Promise<void> {
    if (this.port) return;
    this.startedAt = new Date().toISOString();
    await new Promise<void>((resolveStart, rejectStart) => {
      const onError = (error: Error) => { this.server.off("listening", onListening); rejectStart(error); };
      const onListening = () => { this.server.off("error", onError); resolveStart(); };
      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen(0, "127.0.0.1");
    });
    const address = this.server.address();
    if (!address || typeof address === "string") throw new Error("Browser network boundary did not acquire a loopback port.");
    this.port = address.port;
    this.state = "HEALTHY";
    this.publish();
  }

  public playwrightProxy(): { server: string; username: string; password: string } {
    this.assertOperational();
    return { server: `http://127.0.0.1:${this.port}`, username: this.username, password: this.password };
  }

  public assertOperational(): void {
    if (this.fatalFailure) throw this.fatalFailure;
    if (!this.port || !this.server.listening || this.state === "STOPPED") {
      throw new PinnedConnectionError("Browser network boundary is not operational.", "PROXY_NOT_OPERATIONAL");
    }
  }

  public diagnostics(): BrowserNetworkBoundaryDiagnostics {
    return {
      state: this.state,
      generation: this.options.generation ?? 0,
      connectionsAttempted: this.connectionsAttempted,
      connectionsAllowed: this.connectionsAllowed,
      connectionsBlocked: this.connectionsBlocked,
      activeConnections: this.sockets.size,
      pinnedDestinationCount: this.pinnedDestinations.size,
      ...(this.lastFailureCode ? { lastFailureCode: this.lastFailureCode } : {}),
      startedAt: this.startedAt,
      ...(this.stoppedAt ? { stoppedAt: this.stoppedAt } : {}),
      coverage: ["pages", "frames", "workers", "downloads", "websockets", "browser-api"]
    };
  }

  public async close(): Promise<void> {
    if (this.state === "STOPPED") return;
    this.state = "STOPPED";
    this.stoppedAt = new Date().toISOString();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    if (this.server.listening) {
      await new Promise<void>((resolveClose) => this.server.close(() => resolveClose()));
    }
    this.publish();
  }

  private async forwardHttp(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (!this.authorized(request)) { proxyAuthenticationRequired(response); return; }
    let url: URL;
    try { url = new URL(request.url ?? ""); }
    catch { this.blockHttp(response, "PROXY_ABSOLUTE_URL_REQUIRED"); return; }
    if (url.protocol !== "http:" && url.protocol !== "ws:") { this.blockHttp(response, "PROXY_PROTOCOL_BLOCKED"); return; }

    try {
      const pin = await this.openPinned(url.hostname, url.port || "80", "http:");
      const headers = sanitizedProxyHeaders(request.headers, url.host);
      const upstream = createHttpRequest({ hostname: pin.socket.remoteAddress, family: pin.socket.remoteFamily === "IPv6" ? 6 : 4, port: Number(url.port || 80), method: request.method, path: `${url.pathname}${url.search}`, headers, agent: false, createConnection: () => pin.socket }, (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, sanitizedResponseHeaders(upstreamResponse.headers));
        upstreamResponse.once("aborted", () => { pin.socket.destroy(); response.destroy(); });
        upstreamResponse.once("error", () => { pin.socket.destroy(); response.destroy(); });
        upstreamResponse.once("end", () => pin.socket.destroy());
        upstreamResponse.pipe(response);
      });
      upstream.on("error", (error) => {
        pin.socket.destroy();
        this.failHttp(response, error);
      });
      request.pipe(upstream);
    } catch (error) {
      this.failHttp(response, error);
    }
  }

  private async forwardConnect(request: IncomingMessage, client: Duplex, head: Buffer): Promise<void> {
    if (!this.authorized(request)) { client.end("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=RouteCairn\r\nConnection: close\r\n\r\n"); return; }
    const authority = parseAuthority(request.url ?? "", 443);
    if (!authority) { this.blockSocket(client, "PROXY_AUTHORITY_INVALID"); return; }
    try {
      // Chromium also uses CONNECT for ws:// on some platforms. Select the
      // declared application protocol by exact authority; the browser still
      // owns any TLS handshake and therefore preserves the original SNI.
      const protocol = this.declaredProtocolForAuthority(authority.hostname, String(authority.port));
      const pin = await this.openPinned(authority.hostname, String(authority.port), protocol);
      client.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: RouteCairn\r\n\r\n");
      if (head.length) pin.socket.write(head);
      this.bridge(client, pin.socket);
    } catch (error) {
      this.failSocket(client, error);
    }
  }

  private async forwardWebSocket(request: IncomingMessage, client: Duplex, head: Buffer): Promise<void> {
    if (!this.authorized(request)) { client.destroy(); return; }
    let url: URL;
    try { url = new URL(request.url ?? ""); }
    catch { this.blockSocket(client, "PROXY_WEBSOCKET_URL_INVALID"); return; }
    if (url.protocol !== "ws:" && url.protocol !== "http:") { this.blockSocket(client, "PROXY_WEBSOCKET_PROTOCOL_BLOCKED"); return; }
    try {
      const pin = await this.openPinned(url.hostname, url.port || "80", "http:");
      const headers = sanitizedProxyHeaders(request.headers, url.host, true);
      const upstream = createHttpRequest({ hostname: pin.socket.remoteAddress, family: pin.socket.remoteFamily === "IPv6" ? 6 : 4, port: Number(url.port || 80), method: request.method, path: `${url.pathname}${url.search}`, headers, agent: false, createConnection: () => pin.socket });
      upstream.on("upgrade", (upstreamResponse, upstreamSocket, upstreamHead) => {
        client.write(serializeUpgradeResponse(upstreamResponse));
        if (head.length) upstreamSocket.write(head);
        if (upstreamHead.length) client.write(upstreamHead);
        this.bridge(client, upstreamSocket);
      });
      upstream.on("response", (upstreamResponse) => { client.end(`HTTP/1.1 ${upstreamResponse.statusCode ?? 502} ${upstreamResponse.statusMessage ?? "Bad Gateway"}\r\nConnection: close\r\n\r\n`); });
      upstream.on("error", (error) => this.failSocket(client, error));
      upstream.end();
    } catch (error) {
      this.failSocket(client, error);
    }
  }

  private async openPinned(hostname: string, port: string, protocol: "http:" | "https:"): Promise<PinnedSocket> {
    this.connectionsAttempted += 1;
    this.publish();
    this.assertOriginAllowed(hostname, port, protocol);
    const pin = await resolvePinnedDestination({ hostname, protocol, port }, {
      allowedPrivateOrigins: this.options.policy.allowPrivateNetwork ? connectionOrigins(this.options.policy.allowedPrivateOrigins) : [],
      dnsTimeoutMs: Math.min(this.options.timeoutMs, 3_000),
      maxDnsAnswers: 16,
      ...(this.options.dnsResolver ? { dnsResolver: this.options.dnsResolver } : {})
    });
    const socket = await connectPinnedSocket(pin.address.address, Number(pin.port), pin.address.family, this.options.timeoutMs);
    if (!sameIp(socket.remoteAddress, pin.address.address)) {
      socket.destroy();
      throw new PinnedConnectionError("Pinned socket destination mismatch.", "PINNED_REMOTE_ADDRESS_MISMATCH");
    }
    this.connectionsAllowed += 1;
    this.pinnedDestinations.add(pin.addressFingerprint);
    this.track(socket);
    this.publish();
    return { socket, addressFingerprint: pin.addressFingerprint };
  }

  private assertOriginAllowed(hostname: string, port: string, protocol: "http:" | "https:"): void {
    if (!this.options.policy.blockThirdParty) return;
    const origin = canonicalOrigin(protocol, hostname, port);
    const target = new URL(this.options.targetUrl).origin;
    const allowed = new Set(connectionOrigins([target, ...this.options.policy.allowedThirdPartyOrigins, ...this.options.policy.allowedPrivateOrigins]));
    if (!allowed.has(origin)) throw new PinnedConnectionError("Browser proxy blocked an undeclared third-party origin.", "PROXY_ORIGIN_BLOCKED");
  }

  private declaredProtocolForAuthority(hostname: string, port: string): "http:" | "https:" {
    const declared = connectionOrigins([
      new URL(this.options.targetUrl).origin,
      ...this.options.policy.allowedThirdPartyOrigins,
      ...this.options.policy.allowedPrivateOrigins
    ]);
    return declared.includes(canonicalOrigin("http:", hostname, port)) ? "http:" : "https:";
  }

  private authorized(request: IncomingMessage): boolean {
    const expected = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
    const actual = typeof request.headers["proxy-authorization"] === "string" ? request.headers["proxy-authorization"] : "";
    return constantEqual(expected, actual);
  }

  private bridge(left: Duplex, right: Duplex): void {
    this.track(left);
    this.track(right);
    left.pipe(right);
    right.pipe(left);
    const close = () => { left.destroy(); right.destroy(); };
    left.once("error", close); right.once("error", close);
  }

  private track(socket: Duplex): void {
    if (this.sockets.has(socket)) return;
    this.sockets.add(socket);
    const remove = () => { this.sockets.delete(socket); this.publish(); };
    socket.once("close", remove);
  }

  private blockHttp(response: ServerResponse, code: string): void {
    this.recordBlock(code);
    response.writeHead(403, { "content-type": "text/plain", connection: "close" });
    response.end("RouteCairn browser network policy blocked this destination.");
  }

  private failHttp(response: ServerResponse, error: unknown): void {
    this.recordBlock(safeFailureCode(error));
    if (!response.headersSent) response.writeHead(502, { "content-type": "text/plain", connection: "close" });
    response.end("RouteCairn browser network connection failed.");
  }

  private blockSocket(socket: Duplex, code: string): void {
    this.recordBlock(code);
    socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
  }

  private failSocket(socket: Duplex, error: unknown): void {
    this.recordBlock(safeFailureCode(error));
    socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
  }

  private recordBlock(code: string): void {
    this.connectionsBlocked += 1;
    this.lastFailureCode = code;
    this.publish();
  }

  private recordFatal(code: string): void {
    if (this.state === "STOPPED") return;
    this.state = "DEGRADED";
    this.lastFailureCode = code;
    this.fatalFailure = new PinnedConnectionError("Browser network boundary stopped unexpectedly.", code);
    this.publish();
  }

  private publish(): void { this.options.onStatus?.(this.diagnostics()); }
}

function connectPinnedSocket(address: string, port: number, family: 4 | 6, timeoutMs: number): Promise<Socket> {
  return new Promise((resolveConnect, rejectConnect) => {
    const socket = connect({ host: address, port, family });
    const timer = setTimeout(() => { socket.destroy(); rejectConnect(new PinnedConnectionError("Pinned browser connection timed out.", "PINNED_CONNECTION_TIMEOUT")); }, timeoutMs);
    timer.unref();
    socket.once("connect", () => { clearTimeout(timer); resolveConnect(socket); });
    socket.once("error", (error) => { clearTimeout(timer); rejectConnect(error); });
  });
}

function parseAuthority(value: string, defaultPort: number): { hostname: string; port: number } | undefined {
  try {
    const parsed = new URL(`https://${value}`);
    const port = Number(parsed.port || defaultPort);
    if (!parsed.hostname || parsed.username || parsed.password || parsed.pathname !== "/" || !Number.isInteger(port) || port < 1 || port > 65535) return undefined;
    return { hostname: parsed.hostname, port };
  } catch { return undefined; }
}

function canonicalOrigin(protocol: "http:" | "https:", hostname: string, port: string): string {
  const host = hostname.includes(":") && !hostname.startsWith("[") ? `[${hostname}]` : hostname;
  const defaultPort = protocol === "https:" ? "443" : "80";
  return `${protocol}//${host.toLowerCase()}${port === defaultPort ? "" : `:${port}`}`;
}

function connectionOrigins(origins: readonly string[]): string[] {
  return origins.flatMap((origin) => {
    try {
      const parsed = new URL(origin);
      if (parsed.protocol === "ws:") parsed.protocol = "http:";
      else if (parsed.protocol === "wss:") parsed.protocol = "https:";
      return [parsed.origin];
    } catch { return []; }
  });
}

function sanitizedProxyHeaders(headers: IncomingMessage["headers"], host: string, upgrade = false): Record<string, string | string[]> {
  return Object.fromEntries(Object.entries(headers).flatMap(([name, value]) => {
    if (value === undefined || ["proxy-authorization", "proxy-connection", "connection"].includes(name.toLowerCase())) return [];
    return [[name, value]];
  }).concat([["host", host], ["connection", upgrade ? "Upgrade" : "close"]]));
}

function sanitizedResponseHeaders(headers: IncomingMessage["headers"]): Record<string, string | string[]> {
  return Object.fromEntries(Object.entries(headers).flatMap(([name, value]) => value === undefined || ["proxy-authenticate", "proxy-authorization"].includes(name.toLowerCase()) ? [] : [[name, value]]));
}

function serializeUpgradeResponse(response: IncomingMessage): string {
  const status = `HTTP/${response.httpVersion} ${response.statusCode ?? 101} ${response.statusMessage ?? "Switching Protocols"}\r\n`;
  const headers = Object.entries(response.headers).flatMap(([name, value]) => Array.isArray(value) ? value.map((item) => `${name}: ${item}\r\n`) : value === undefined ? [] : [`${name}: ${value}\r\n`]).join("");
  return `${status}${headers}\r\n`;
}

function proxyAuthenticationRequired(response: ServerResponse): void {
  response.writeHead(407, { "proxy-authenticate": "Basic realm=RouteCairn", connection: "close" });
  response.end();
}

function constantEqual(left: string, right: string): boolean {
  const leftHash = createHash("sha256").update(left).digest();
  const rightHash = createHash("sha256").update(right).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function safeFailureCode(error: unknown): string {
  if (error instanceof PinnedConnectionError) return error.code;
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") return `SOCKET_${error.code.slice(0, 40).toUpperCase()}`;
  return "PINNED_CONNECTION_FAILED";
}

function sameIp(left: string | undefined, right: string): boolean {
  if (!left) return false;
  if (left.toLowerCase() === right.toLowerCase()) return true;
  if (isIP(right) === 4 && left.toLowerCase() === `::ffff:${right.toLowerCase()}`) return true;
  return false;
}
