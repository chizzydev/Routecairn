import { createServer, request as httpRequest, type Server } from "node:http";
import { connect, createServer as createTcpServer, type Server as TcpServer } from "node:net";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { BrowserNetworkBoundary } from "../../src/modules/browserCrawler/BrowserNetworkBoundary.js";
import { BrowserPolicyEngine, type BrowserPolicy } from "../../src/modules/browserCrawler/BrowserPolicy.js";

const servers: Array<Server | TcpServer> = [];
const boundaries: BrowserNetworkBoundary[] = [];

afterEach(async () => {
  await Promise.all(boundaries.splice(0).map((boundary) => boundary.close()));
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    if (!server.listening) { resolve(); return; }
    server.close(() => resolve());
  })));
});

describe("BrowserNetworkBoundary", () => {
  it("authenticates the loopback proxy and pins an allowed HTTP connection", async () => {
    let observedHost = "";
    const upstream = createServer((request, response) => {
      observedHost = request.headers.host ?? "";
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("pinned-ok");
    });
    servers.push(upstream);
    const port = await listen(upstream);
    const target = `http://public-alias.test:${port}/resource`;
    const boundary = await startBoundary(target, policy({
      allowPrivateNetwork: true,
      allowedPrivateOrigins: [`http://public-alias.test:${port}`]
    }), async () => [{ address: "127.0.0.1", family: 4 }]);

    const unauthorized = await proxyGet(boundary, target, false);
    const authorized = await proxyGet(boundary, target, true);

    expect(unauthorized.statusCode).toBe(407);
    expect(authorized).toMatchObject({ statusCode: 200, body: "pinned-ok" });
    expect(observedHost).toBe(`public-alias.test:${port}`);
    expect(boundary.diagnostics()).toMatchObject({ state: "HEALTHY", connectionsAttempted: 1, connectionsAllowed: 1, connectionsBlocked: 0, pinnedDestinationCount: 1 });
    expect(JSON.stringify(boundary.diagnostics())).not.toContain("127.0.0.1");
  });

  it("blocks cloud metadata even when an exact private-origin exception is declared", async () => {
    const target = "http://metadata.test/latest/meta-data";
    const boundary = await startBoundary(target, policy({ allowPrivateNetwork: true, allowedPrivateOrigins: ["http://metadata.test"] }), async () => ["169.254.169.254"]);

    const result = await proxyGet(boundary, target, true);

    expect(result.statusCode).toBe(502);
    expect(boundary.diagnostics()).toMatchObject({ state: "HEALTHY", connectionsAttempted: 1, connectionsAllowed: 0, connectionsBlocked: 1, lastFailureCode: "DNS_PROHIBITED_ADDRESS" });
  });

  it("rejects mixed public and private DNS answers before choosing a socket", async () => {
    const target = "http://mixed.test/resource";
    const boundary = await startBoundary(target, policy({ allowPrivateNetwork: true, allowedPrivateOrigins: ["http://mixed.test"] }), async () => ["93.184.216.34", "127.0.0.1"]);

    const result = await proxyGet(boundary, target, true);

    expect(result.statusCode).toBe(502);
    expect(boundary.diagnostics().lastFailureCode).toBe("DNS_MIXED_DESTINATION_CLASSES");
  });

  it("closes the policy-check to connection DNS-rebinding gap", async () => {
    let resolutions = 0;
    let upstreamRequests = 0;
    const upstream = createServer((_request, response) => {
      upstreamRequests += 1;
      response.end("must-not-arrive");
    });
    servers.push(upstream);
    const port = await listen(upstream);
    const target = `http://rebind.test:${port}/`;
    const dnsResolver = async () => [++resolutions === 1 ? "93.184.216.34" : "127.0.0.1"];
    const selectedPolicy = policy();
    const policyEngine = new BrowserPolicyEngine(target, selectedPolicy, dnsResolver);
    const preflight = await policyEngine.evaluateRequest({ url: target, pageUrl: target, resourceType: "document", requestsSeenForPage: 1 });
    expect(preflight.allowed).toBe(true);
    const boundary = await startBoundary(target, selectedPolicy, dnsResolver);

    const result = await proxyGet(boundary, target, true);

    expect(result.statusCode).toBe(502);
    expect(upstreamRequests).toBe(0);
    expect(resolutions).toBe(2);
    expect(boundary.diagnostics().lastFailureCode).toBe("DNS_PRIVATE_ORIGIN_NOT_ALLOWED");
  });

  it("enforces every redirect destination again at the connection boundary", async () => {
    let upstreamRequests = 0;
    const upstream = createServer((_request, response) => {
      upstreamRequests += 1;
      response.writeHead(302, { location: "http://metadata.test/latest/meta-data" });
      response.end();
    });
    servers.push(upstream);
    const port = await listen(upstream);
    const first = `http://redirect.test:${port}/`;
    const policyWithHop = policy({
      allowPrivateNetwork: true,
      allowedPrivateOrigins: [`http://redirect.test:${port}`, "http://metadata.test"],
      allowedThirdPartyOrigins: ["http://metadata.test"]
    });
    const boundary = await startBoundary(first, policyWithHop, async (hostname) => hostname === "redirect.test" ? ["127.0.0.1"] : ["169.254.169.254"]);

    const firstResult = await proxyGet(boundary, first, true);
    const redirectedResult = await proxyGet(boundary, firstResult.headers.location ?? "", true);

    expect(firstResult.statusCode).toBe(302);
    expect(redirectedResult.statusCode).toBe(502);
    expect(upstreamRequests).toBe(1);
    expect(boundary.diagnostics()).toMatchObject({ connectionsAttempted: 2, connectionsAllowed: 1, connectionsBlocked: 1, lastFailureCode: "DNS_PROHIBITED_ADDRESS" });
  });

  it("pins CONNECT tunnels used by HTTPS and secure WebSockets", async () => {
    const upstream = createTcpServer((socket) => socket.on("data", (data) => socket.write(data)));
    servers.push(upstream);
    const port = await listen(upstream);
    const target = `https://secure-alias.test:${port}/`;
    const boundary = await startBoundary(target, policy({ allowPrivateNetwork: true, allowedPrivateOrigins: [`https://secure-alias.test:${port}`] }), async () => ["127.0.0.1"]);

    const response = await proxyConnect(boundary, `secure-alias.test:${port}`);

    expect(response).toContain("200 Connection Established");
    expect(boundary.diagnostics()).toMatchObject({ state: "HEALTHY", connectionsAttempted: 1, connectionsAllowed: 1, connectionsBlocked: 0 });
  });

  it("shuts down idempotently and rejects reuse of stopped proxy credentials", async () => {
    const boundary = await startBoundary("https://public.example/", policy(), async () => ["93.184.216.34"]);

    await boundary.close();
    await boundary.close();

    expect(boundary.diagnostics()).toMatchObject({ state: "STOPPED", activeConnections: 0 });
    expect(() => boundary.playwrightProxy()).toThrowError(/not operational/i);
  });
});

async function startBoundary(targetUrl: string, selectedPolicy: BrowserPolicy, dnsResolver: (hostname: string) => Promise<readonly (string | { address: string; family: 4 | 6 })[]>): Promise<BrowserNetworkBoundary> {
  const boundary = new BrowserNetworkBoundary({ targetUrl, policy: selectedPolicy, timeoutMs: 2_000, dnsResolver });
  boundaries.push(boundary);
  await boundary.start();
  return boundary;
}

async function proxyGet(boundary: BrowserNetworkBoundary, targetUrl: string, authenticated: boolean): Promise<{ statusCode?: number; body: string; headers: Record<string, string> }> {
  const proxy = boundary.playwrightProxy();
  const parsedProxy = new URL(proxy.server);
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: parsedProxy.hostname,
      port: Number(parsedProxy.port),
      path: targetUrl,
      method: "GET",
      headers: authenticated ? { "proxy-authorization": `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}` } : {}
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolve({ statusCode: response.statusCode, body, headers: Object.fromEntries(Object.entries(response.headers).flatMap(([key, value]) => typeof value === "string" ? [[key, value]] : [])) }));
    });
    request.once("error", reject);
    request.end();
  });
}

async function proxyConnect(boundary: BrowserNetworkBoundary, authority: string): Promise<string> {
  const proxy = boundary.playwrightProxy();
  const parsedProxy = new URL(proxy.server);
  return new Promise((resolve, reject) => {
    const socket = connect({ host: parsedProxy.hostname, port: Number(parsedProxy.port) });
    let response = "";
    socket.once("connect", () => socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nProxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64")}\r\n\r\n`));
    socket.on("data", (data) => {
      response += data.toString("utf8");
      if (response.includes("\r\n\r\n")) { socket.destroy(); resolve(response); }
    });
    socket.once("error", reject);
  });
}

async function listen(server: Server | TcpServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

function policy(overrides: Partial<BrowserPolicy> = {}): BrowserPolicy {
  return {
    maxDepth: 1,
    maxPages: 1,
    maxLinksPerPage: 5,
    maxPolicyEvents: 20,
    maxRequestsPerPage: 20,
    navigationTimeoutMs: 2_000,
    pageLifetimeMs: 2_000,
    blockThirdParty: true,
    allowedResourceTypes: ["document", "script", "xhr", "fetch", "other"],
    captureScreenshot: false,
    allowPopups: false,
    allowDownloads: false,
    allowUploads: false,
    allowServiceWorkers: false,
    allowWebSockets: true,
    allowPrivateNetwork: false,
    allowedPrivateOrigins: [],
    allowedThirdPartyOrigins: [],
    evidence: { level: "minimal", includeHeaders: false, includeBodyPreview: false, screenshotMode: "none" },
    ...overrides
  };
}
