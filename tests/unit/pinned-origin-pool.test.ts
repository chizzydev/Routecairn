import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { HttpClient } from "../../src/core/http/HttpClient.js";
import { PinnedOriginPool } from "../../src/core/http/PinnedOriginPool.js";
import { routeCairnConfigSchema } from "../../src/config/ConfigSchema.js";

let server: Server | undefined;
afterEach(async () => { if (server) await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve())); server = undefined; });

describe("origin-isolated pinned connection pool", () => {
  it("validates bounded pool and HTTP/2 configuration", () => {
    const parsed = routeCairnConfigSchema.parse({ transport: { http2Enabled: true, maxConnectionsPerOrigin: 8, maxConcurrentHttp2Streams: 64, dnsCacheTtlMs: 500 } });
    expect(parsed.transport).toMatchObject({ poolingEnabled: true, http2Enabled: true, maxConnectionsPerOrigin: 8, maxConcurrentHttp2Streams: 64, dnsCacheTtlMs: 500 });
    expect(() => routeCairnConfigSchema.parse({ transport: { keepAliveTimeoutMs: 5000, keepAliveMaxTimeoutMs: 1000 } })).toThrow();
    expect(() => routeCairnConfigSchema.parse({ transport: { dnsCacheTtlMs: 60001 } })).toThrow();
    expect(() => new PinnedOriginPool({ maxOrigins: 0 })).toThrow("PINNED_TRANSPORT_SETTING_INVALID:maxOrigins");
  });

  it("reuses a verified connection while revalidating DNS before each dispatch", async () => {
    let connections = 0; let resolutions = 0; const fixture = await start((request, response) => response.end(request.url)); fixture.server.on("connection", () => { connections += 1; });
    const origin = `http://pool.test:${fixture.port}`; const pool = new PinnedOriginPool({ keepAliveTimeoutMs: 5000, keepAliveMaxTimeoutMs: 5000 });
    const client = httpClient(pool, [origin], async () => { resolutions += 1; return ["127.0.0.1"]; });
    try {
      for (let index = 0; index < 6; index += 1) expect((await client.send({ url: `${origin}/${index}`, method: "GET" })).statusCode).toBe(200);
      expect(resolutions).toBe(6); expect(connections).toBeLessThanOrEqual(4);
      expect(pool.diagnostics()).toMatchObject({ requestsDispatched: 6, poolHits: 5, poolMisses: 1, http2Connections: 0 });
      expect(pool.diagnostics().estimatedConnectionReuses).toBeGreaterThanOrEqual(2);
    } finally { await pool.close(); }
  });

  it("blocks a rebinding answer instead of sending over an already pooled socket", async () => {
    let resolutions = 0; let requests = 0; const fixture = await start((_request, response) => { requests += 1; response.end("ok"); });
    const origin = `http://rebind.test:${fixture.port}`; const pool = new PinnedOriginPool();
    const client = httpClient(pool, [origin], async () => (++resolutions === 1 ? ["127.0.0.1"] : ["169.254.169.254"]));
    try {
      expect((await client.send({ url: `${origin}/first`, method: "GET" })).statusCode).toBe(200);
      const blocked = await client.send({ url: `${origin}/second`, method: "GET" });
      expect(blocked.error?.name).toBe("DNS_PROHIBITED_ADDRESS"); expect(requests).toBe(1);
      expect(pool.diagnostics().blockedResolutions).toBe(1);
    } finally { await pool.close(); }
  });

  it("uses separate physical pools for distinct origins even when they resolve to one IP", async () => {
    let connections = 0; const fixture = await start((_request, response) => response.end("ok")); fixture.server.on("connection", () => { connections += 1; });
    const first = `http://one.test:${fixture.port}`; const second = `http://two.test:${fixture.port}`; const pool = new PinnedOriginPool({ http2Enabled: true });
    const client = httpClient(pool, [first, second], async () => ["127.0.0.1"]);
    try {
      expect((await client.send({ url: `${first}/`, method: "GET" })).statusCode).toBe(200);
      expect((await client.send({ url: `${second}/`, method: "GET" })).statusCode).toBe(200);
      expect(connections).toBe(2); expect(pool.diagnostics()).toMatchObject({ activeOriginPools: 2, peakOriginPools: 2, http2Connections: 0 });
    } finally { await pool.close(); }
  });

  it("bounds retained origins and gracefully evicts the least-recently-used pool", async () => {
    const fixture = await start((_request, response) => response.end("ok")); const first = `http://oldest.test:${fixture.port}`; const second = `http://newest.test:${fixture.port}`;
    const pool = new PinnedOriginPool({ maxOrigins: 1 }); const client = httpClient(pool, [first, second], async () => ["127.0.0.1"]);
    try { await client.send({ url: `${first}/`, method: "GET" }); await client.send({ url: `${second}/`, method: "GET" }); expect(pool.diagnostics()).toMatchObject({ activeOriginPools: 1, peakOriginPools: 1, originEvictions: 1 }); }
    finally { await pool.close(); }
  });

  it("can cache only an already validated pin without following changed DNS", async () => {
    let resolutions = 0; let requests = 0; const fixture = await start((_request, response) => { requests += 1; response.end("ok"); });
    const origin = `http://lease.test:${fixture.port}`; const pool = new PinnedOriginPool({ dnsCacheTtlMs: 1000 });
    const client = httpClient(pool, [origin], async () => { resolutions += 1; return resolutions === 1 ? ["127.0.0.1"] : ["169.254.169.254"]; });
    try {
      await client.send({ url: `${origin}/one`, method: "GET" }); await client.send({ url: `${origin}/two`, method: "GET" });
      expect({ resolutions, requests }).toEqual({ resolutions: 1, requests: 2 }); expect(pool.diagnostics().dnsCacheHits).toBe(1);
    } finally { await pool.close(); }
  });

  it("supports a bounded single-use compatibility mode", async () => {
    let connections = 0; const fixture = await start((_request, response) => response.end("ok")); fixture.server.on("connection", () => { connections += 1; });
    const origin = `http://single.test:${fixture.port}`; const pool = new PinnedOriginPool({ poolingEnabled: false }); const client = httpClient(pool, [origin], async () => ["127.0.0.1"]);
    try { await client.send({ url: `${origin}/one`, method: "GET" }); await client.send({ url: `${origin}/two`, method: "GET" }); expect(connections).toBe(2); expect(pool.diagnostics()).toMatchObject({ poolingEnabled: false, poolHits: 0, poolMisses: 2 }); }
    finally { await pool.close(); }
  });

  it("closes owned pools idempotently and refuses post-close dispatch", async () => {
    const fixture = await start((_request, response) => response.end("ok"));
    const origin = `http://lifecycle.test:${fixture.port}`;
    const client = new HttpClient({
      userAgent: "RouteCairn/Test",
      timeoutMs: 2000,
      bodyPreviewBytes: 1024,
      maxResponseBytes: 4096,
      allowedPrivateOrigins: [origin],
      dnsResolver: async () => ["127.0.0.1"]
    });
    expect((await client.send({ url: `${origin}/`, method: "GET" })).statusCode).toBe(200);
    await Promise.all([client.close(), client.close()]);
    expect((await client.send({ url: `${origin}/after-close`, method: "GET" })).error?.message).toBe("PINNED_ORIGIN_POOL_CLOSED");
  });

  it("bounds ordinary response streaming before buffering untrusted bodies", async () => {
    const fixture = await start((_request, response) => { response.writeHead(200, { "content-type": "application/octet-stream" }); response.end("x".repeat(10000)); });
    const origin = `http://bounded.test:${fixture.port}`; const pool = new PinnedOriginPool(); const client = httpClient(pool, [origin], async () => ["127.0.0.1"]);
    try { const response = await client.send({ url: `${origin}/large`, method: "GET" }); expect(response).toMatchObject({ statusCode: 200, bytesRead: 4096, streamTruncated: true, contentLength: 4096 }); expect(response.bodyPreview?.length).toBe(1024); }
    finally { await pool.close(); }
  });
});

function httpClient(pool: PinnedOriginPool, allowedPrivateOrigins: string[], dnsResolver: (hostname: string) => Promise<readonly string[]>) { return new HttpClient({ userAgent: "RouteCairn/Test", timeoutMs: 2000, bodyPreviewBytes: 1024, maxResponseBytes: 4096, allowedPrivateOrigins, dnsResolver, connectionPool: pool }); }
async function start(listener: Parameters<typeof createServer>[0]) { server = createServer(listener); await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve)); return { server, port: (server.address() as AddressInfo).port }; }
