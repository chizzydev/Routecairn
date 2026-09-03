import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { scopeSchema } from "../../src/config/ConfigSchema.js";
import { targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
import { testPlan } from "../helpers/plan.js";

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }))); });

async function fixture() {
  const received: string[] = [];
  const server = createServer((request, response) => { received.push(`${request.method} ${request.url}`); if (request.url === "/redirect") response.writeHead(302, { location: "/never" }).end(); else response.writeHead(200, { "content-type": "application/json" }).end('{"ok":true}'); });
  servers.push(server); await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const scope = scopeSchema.parse({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "POST", "PATCH", "DELETE"] });
  const targetAuthorization = targetAuthorizationSchema.parse({ schemaVersion: 1, mode: "BUG_BOUNTY_AUTHORIZED", targetOrigin: origin, proof: { reference: "Owned fixture", sha256: "a".repeat(64) }, bugBounty: { program: "Local fixture", platform: "Local acceptance", scopeDocumentSha256: "b".repeat(64), inScope: [{ origin, pathPrefix: "/" }], outOfScope: [{ origin, pathPrefix: "/never" }], rules: ["Exact requests only"], prohibitedActions: ["No real payments"], startsAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", maxRequests: 5, rateLimitPerSecond: 50, reportMode: "BUG_BOUNTY_SAFE" } });
  const context = new ScanContext({ target: origin, scope, config: defaultConfig, outputDir: "unused", plan: { ...testPlan("quick", { scope }), targetAuthorization } });
  return { origin, received, context };
}

describe("authorization across real transports", () => {
  it("blocks out-of-program redirects, unauthorized bodies and credential headers before transmission", async () => {
    const { context, origin, received } = await fixture();
    const redirect = await context.httpClient.send({ url: `${origin}/redirect`, method: "GET" });
    expect(redirect.error).toBeDefined(); expect(received).toEqual(["GET /redirect"]);
    expect((await context.httpClient.send({ url: `${origin}/mutate`, method: "POST", body: "{}" })).error).toBeDefined();
    expect((await context.httpClient.send({ url: `${origin}/me`, method: "GET", headers: { "X-Custom-Session": "secret" } })).error).toBeDefined();
    expect(received).toEqual(["GET /redirect"]);
  });
  it("caps aggregate traffic across separate API, lifecycle, invariant and default brokers", async () => {
    const { context, origin, received } = await fixture();
    const brokers = [context.httpClient, context.createApiGraphqlHttpClient(20, 1024), context.createAuthenticationLifecycleHttpClient(1, 1024), context.createBusinessInvariantHttpClient(1, 1024, 1), context.createControlledRaceHttpClient(1, 1024, 2)];
    for (const broker of brokers) expect((await broker.send({ url: `${origin}/read`, method: "GET", skipCache: true })).statusCode).toBe(200);
    expect((await context.httpClient.send({ url: `${origin}/sixth`, method: "GET", skipCache: true })).error?.message).toBe("authorization-budget-exhausted");
    expect(received).toHaveLength(5);
    expect(() => context.createBusinessInvariantHttpClient(1, 1024, 1)).toThrow("INSUFFICIENT_EXECUTION_AND_CLEANUP_BUDGET");
  });
  it("rejects an entire unapproved synchronized group without dispatch", async () => {
    const { context, origin, received } = await fixture();
    await expect(context.createControlledRaceHttpClient(5, 1024, 2).sendSynchronizedMutations([{ url: `${origin}/mutate`, method: "POST" }, { url: `${origin}/mutate`, method: "POST" }])).rejects.toThrow("TARGET_RACE_TESTING_PROHIBITED");
    expect(received).toHaveLength(0);
  });
});
