import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { testPlan } from "../helpers/plan.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  })));
});

describe("scan-wide request ledger", () => {
  it("enforces one ordinary request across independently created engine transports", async () => {
    let actualRequests = 0;
    const origin = await fixtureServer((_request, response) => {
      actualRequests += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(origin, { maxRequests: 1, cleanupReservedRequests: 0, concurrency: 5, rateLimitPerSecond: 100 });
    const transports = [
      context.createApiGraphqlHttpClient(10, 1024),
      context.createAuthenticationLifecycleHttpClient(10, 1024),
      context.createLinkPortalSecurityHttpClient(10, 1024)
    ];

    const responses = [];
    for (let index = 0; index < transports.length; index += 1) {
      responses.push(await transports[index]!.send({ url: `${origin}/request-${index}`, method: "GET", skipCache: true }));
    }

    expect(actualRequests).toBe(1);
    expect(responses.filter((response) => response.statusCode === 200)).toHaveLength(1);
    expect(responses.filter((response) => response.error?.name === "RequestBudgetExceeded")).toHaveLength(2);
    expect(context.requestLedger.snapshot()).toMatchObject({ maxRequests: 1, scanTransmitted: 1, cleanupTransmitted: 0, totalTransmitted: 1, scanRemaining: 0 });
  });

  it("withholds cleanup capacity from attack traffic and permits restoration after exhaustion", async () => {
    let actualRequests = 0;
    const origin = await fixtureServer((_request, response) => {
      actualRequests += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(origin, { maxRequests: 3, cleanupReservedRequests: 1, concurrency: 3, rateLimitPerSecond: 100 });
    const attackA = context.createApiGraphqlHttpClient(10, 1024);
    const attackB = context.createAuthenticationLifecycleHttpClient(10, 1024);
    const cleanup = context.createWorkflowCleanupHttpClient(10, 1024);

    const first = await attackA.send({ url: `${origin}/attack-a`, method: "GET", skipCache: true });
    const second = await attackB.send({ url: `${origin}/attack-b`, method: "GET", skipCache: true });
    const blocked = await attackA.send({ url: `${origin}/attack-c`, method: "GET", skipCache: true });
    const restored = await cleanup.send({ url: `${origin}/cleanup`, method: "GET", skipCache: true });
    const cleanupBlocked = await cleanup.send({ url: `${origin}/cleanup-again`, method: "GET", skipCache: true });
    context.finishCleanup(cleanup);

    expect([first.statusCode, second.statusCode, restored.statusCode]).toEqual([200, 200, 200]);
    expect(blocked.error?.name).toBe("RequestBudgetExceeded");
    expect(cleanupBlocked.error?.name).toBe("RequestBudgetExceeded");
    expect(actualRequests).toBe(3);
    expect(context.requestLedger.snapshot()).toMatchObject({ maxRequests: 3, cleanupReservedRequests: 1, scanCapacity: 2, scanTransmitted: 2, cleanupTransmitted: 1, totalTransmitted: 3 });
  });

  it("enforces concurrency across brokers rather than per broker", async () => {
    let active = 0;
    let maximumActive = 0;
    const origin = await fixtureServer(async (_request, response) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await new Promise((resolve) => setTimeout(resolve, 35));
      active -= 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(origin, { maxRequests: 12, cleanupReservedRequests: 0, concurrency: 2, rateLimitPerSecond: 100 });
    const brokers = [
      context.createApiGraphqlHttpClient(12, 1024),
      context.createAuthenticationLifecycleHttpClient(12, 1024),
      context.createLinkPortalSecurityHttpClient(12, 1024)
    ];

    await Promise.all(Array.from({ length: 9 }, (_item, index) => brokers[index % brokers.length]!.send({ url: `${origin}/parallel-${index}`, method: "GET", skipCache: true })));

    expect(maximumActive).toBeLessThanOrEqual(2);
    expect(context.requestLedger.snapshot().totalTransmitted).toBe(9);
  });
});

async function fixtureServer(handler: Parameters<typeof createServer>[0]): Promise<string> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function contextFor(target: string, limits: { maxRequests: number; cleanupReservedRequests: number; concurrency: number; rateLimitPerSecond: number }): ScanContext {
  const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const, disallowedPaths: [], rateLimitPerSecond: limits.rateLimitPerSecond, concurrency: limits.concurrency };
  const plan = testPlan("quick", { scope });
  return new ScanContext({ target, scope, config: defaultConfig, outputDir: ".", plan: { ...plan, limits: { ...plan.limits, ...limits, retry: { ...plan.limits.retry, maxAttempts: 1 } } } });
}
