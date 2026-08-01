import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exampleScope } from "../../src/config/defaults.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { testPlan } from "../helpers/plan.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error) reject(error);
            else resolve();
          });
        })
    )
  );
});

describe("RequestSafetyBroker", () => {
  it("blocks out-of-scope redirects and records safe skipped redirect evidence", async () => {
    const server = await testServer((request, response) => {
      if (request.url === "/start") {
        response.writeHead(302, { location: "http://example.net/out-of-scope" });
        response.end("redirecting");
        return;
      }

      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    const response = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/start`, method: "GET" });

    expect(response.error?.name).toBe("OutOfScopeRedirect");
    expect(response.redirectChain).toEqual([{ statusCode: 302, location: "http://example.net/out-of-scope" }]);
    expect(context.state.getRequestAudit()).toEqual([
      expect.objectContaining({
        outcome: "redirect-scope-skipped",
        requestedUrl: `http://127.0.0.1:${server.port}/start`,
        error: "Redirect blocked by scan-wide broker: different-origin."
      })
    ]);
  });

  it("deduplicates requests globally across clients created by the scan context", async () => {
    let requestCount = 0;
    const server = await testServer((_request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);
    const firstClient = context.createHttpClient();
    const secondClient = context.createHttpClient();

    const first = await firstClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET" });
    const second = await secondClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET" });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(second.error).toBeUndefined();
    expect(requestCount).toBe(1);
    expect(context.state.getRequestAudit().map((entry) => entry.outcome)).toEqual(["sent", "duplicate-skipped"]);
  });

  it("does not share cached responses between Account A and Account B", async () => {
    let requestCount = 0;
    const server = await testServer((request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(request.headers.cookie?.includes("account-a") ? "account-a" : "account-b");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    const accountA = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET", headers: { Cookie: "session=account-a-secret" } });
    const accountB = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET", headers: { Cookie: "session=account-b-secret" } });

    expect(accountA.bodyPreview).toBe("account-a");
    expect(accountB.bodyPreview).toBe("account-b");
    expect(requestCount).toBe(2);
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("account-a-secret");
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("account-b-secret");
  });

  it("does not share cached responses between anonymous and authenticated requests", async () => {
    let requestCount = 0;
    const server = await testServer((request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(request.headers.authorization ? "authenticated" : "anonymous");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    const anonymous = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET" });
    const authenticated = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET", headers: { Authorization: "Bearer auth-secret" } });

    expect(anonymous.bodyPreview).toBe("anonymous");
    expect(authenticated.bodyPreview).toBe("authenticated");
    expect(requestCount).toBe(2);
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("auth-secret");
  });

  it("does not share cached responses between tenant contexts", async () => {
    let requestCount = 0;
    const server = await testServer((request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(String(request.headers["x-tenant-id"]));
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    const tenantA = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET", headers: { "X-Tenant-Id": "tenant-a-secret" } });
    const tenantB = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET", headers: { "X-Tenant-Id": "tenant-b-secret" } });

    expect(tenantA.bodyPreview).toBe("tenant-a-secret");
    expect(tenantB.bodyPreview).toBe("tenant-b-secret");
    expect(requestCount).toBe(2);
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("tenant-a-secret");
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("tenant-b-secret");
  });

  it("reuses cached responses within the same safe authentication context", async () => {
    let requestCount = 0;
    const server = await testServer((_request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("same-auth");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    const first = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET", headers: { Cookie: "session=same-secret" } });
    const second = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/same`, method: "GET", headers: { Cookie: "session=same-secret" } });

    expect(first.bodyPreview).toBe("same-auth");
    expect(second.bodyPreview).toBe("same-auth");
    expect(requestCount).toBe(1);
    expect(context.state.getRequestAudit().map((entry) => entry.outcome)).toEqual(["sent", "duplicate-skipped"]);
  });

  it("preserves authentication-aware cache isolation across redirects and retries", async () => {
    const attemptsByPrincipal = new Map<string, number>();
    const server = await testServer((request, response) => {
      if (request.url === "/redirect") {
        response.writeHead(302, { location: "/retry" });
        response.end();
        return;
      }
      const principal = request.headers.cookie?.includes("account-a") ? "account-a" : "account-b";
      const attempts = (attemptsByPrincipal.get(principal) ?? 0) + 1;
      attemptsByPrincipal.set(principal, attempts);
      if (attempts === 1) {
        response.writeHead(500, { "content-type": "text/plain" });
        response.end("retry");
        return;
      }
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(principal);
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`, 20, 2);

    const accountA = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/redirect`, method: "GET", headers: { Cookie: "session=account-a-secret" } });
    const accountB = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/redirect`, method: "GET", headers: { Cookie: "session=account-b-secret" } });

    expect(accountA.bodyPreview).toBe("account-a");
    expect(accountB.bodyPreview).toBe("account-b");
    expect(attemptsByPrincipal.get("account-a")).toBe(2);
    expect(attemptsByPrincipal.get("account-b")).toBe(2);
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("account-a-secret");
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("account-b-secret");
  });

  it("redacts auth material from request audit metadata", async () => {
    const server = await testServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    await context.httpClient.send({
      url: `http://127.0.0.1:${server.port}/private`,
      method: "GET",
      headers: {
        Authorization: "Bearer secret-token",
        Cookie: "session=secret-cookie",
        "X-Request-Id": "routecairn-test"
      }
    });

    expect(context.state.getRequestAudit()).toEqual([
      expect.objectContaining({
        requestHeaders: {
          Authorization: "<redacted>",
          Cookie: "<redacted>",
          "X-Request-Id": "routecairn-test"
        }
      })
    ]);
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("secret-token");
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("secret-cookie");
  });

  it("enforces the scan-wide request budget from the resolved plan", async () => {
    let requestCount = 0;
    const server = await testServer((_request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`, 1);

    const first = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/one`, method: "GET" });
    const second = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/two`, method: "GET" });

    expect(first.statusCode).toBe(200);
    expect(second.error?.name).toBe("RequestBudgetExceeded");
    expect(requestCount).toBe(1);
    expect(context.state.getRequestAudit().map((entry) => entry.outcome)).toEqual(["sent", "budget-skipped"]);
  });

  it("counts redirects against the scan-wide request budget", async () => {
    let requestCount = 0;
    const server = await testServer((request, response) => {
      requestCount += 1;
      if (request.url === "/redirect") {
        response.writeHead(302, { location: "/final" });
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("final");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`, 1);

    const response = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/redirect`, method: "GET" });

    expect(response.error?.name).toBe("RequestBudgetExceeded");
    expect(requestCount).toBe(1);
  });

  it("counts retry attempts against the scan-wide request budget", async () => {
    let requestCount = 0;
    const server = await testServer((_request, response) => {
      requestCount += 1;
      response.writeHead(500, { "content-type": "text/plain" });
      response.end("temporary");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`, 1, 2);

    const response = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/retry`, method: "GET" });

    expect(response.error?.name).toBe("RequestBudgetExceeded");
    expect(requestCount).toBe(1);
  });

  it("does not exceed the global request budget during concurrent sends", async () => {
    let requestCount = 0;
    const server = await testServer(async (_request, response) => {
      requestCount += 1;
      await new Promise((resolve) => setTimeout(resolve, 20));
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`, 2);

    const responses = await Promise.all(
      Array.from({ length: 8 }, (_item, index) => context.httpClient.send({ url: `http://127.0.0.1:${server.port}/${index}`, method: "GET" }))
    );

    expect(responses.filter((response) => response.statusCode === 200)).toHaveLength(2);
    expect(responses.filter((response) => response.error?.name === "RequestBudgetExceeded")).toHaveLength(6);
    expect(requestCount).toBe(2);
  });

  it("accounts blocked browser requests as policy events without consuming network budget", async () => {
    const server = await testServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`, 1);
    context.httpClient.setBrowserPolicyEventLimit(5);

    const blocked = context.httpClient.evaluateBrowserRequest({
      url: `http://127.0.0.1:${server.port}/danger`,
      method: "POST",
      resourceType: "fetch",
      pageUrl: `http://127.0.0.1:${server.port}/`
    });
    const direct = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/safe`, method: "GET" });

    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toBe("mutating-method-blocked");
    expect(direct.statusCode).toBe(200);
    expect(context.httpClient.budgetSnapshot()).toMatchObject({ browserPolicyEvents: 1, transmittedRequests: 1 });
  });

  it.each(["POST", "PUT", "PATCH", "DELETE", "TRACE", "PROPFIND", "CUSTOM"])("blocks browser %s before network budget is consumed", (method) => {
    const context = contextFor("http://127.0.0.1/", 1);

    const decision = context.httpClient.evaluateBrowserRequest({
      url: "http://127.0.0.1/mutate",
      method,
      resourceType: "fetch",
      pageUrl: "http://127.0.0.1/"
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("mutating-method-blocked");
    expect(context.httpClient.budgetSnapshot()).toMatchObject({ browserPolicyEvents: 1, transmittedRequests: 0 });
  });

  it.each(["GET", "HEAD", "OPTIONS"])("permits browser %s when otherwise in scope", (method) => {
    const context = contextFor("http://127.0.0.1/", 3);

    const decision = context.httpClient.evaluateBrowserRequest({
      url: "http://127.0.0.1/safe",
      method,
      resourceType: "fetch",
      pageUrl: "http://127.0.0.1/"
    });

    expect(decision.allowed).toBe(true);
    expect(context.httpClient.budgetSnapshot().transmittedRequests).toBe(1);
  });

  it("uses one shared network budget for browser and direct HTTP requests", async () => {
    const server = await testServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`, 1);

    const browserDecision = context.httpClient.evaluateBrowserRequest({
      url: `http://127.0.0.1:${server.port}/browser`,
      method: "GET",
      resourceType: "document",
      pageUrl: `http://127.0.0.1:${server.port}/`
    });
    const direct = await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/direct`, method: "GET" });

    expect(browserDecision.allowed).toBe(true);
    expect(direct.error?.name).toBe("RequestBudgetExceeded");
    expect(context.httpClient.budgetSnapshot()).toMatchObject({ browserPolicyEvents: 1, transmittedRequests: 1 });
  });

  it("checks browser redirect hops against scope before network budget is spent", () => {
    const context = contextFor("http://127.0.0.1/");

    const redirectHop = context.httpClient.evaluateBrowserRequest({
      url: "http://example.net/out",
      method: "GET",
      resourceType: "document",
      pageUrl: "http://127.0.0.1/start",
      isRedirect: true
    });

    expect(redirectHop.allowed).toBe(false);
    expect(redirectHop.reason).toBe("scope-different-origin");
    expect(context.httpClient.budgetSnapshot()).toMatchObject({ browserPolicyEvents: 1, transmittedRequests: 0 });
    expect(context.state.getRequestAudit()).toEqual([
      expect.objectContaining({
        outcome: "browser-policy-blocked",
        browserPolicyReason: "scope-different-origin",
        transmittedRequests: 0
      })
    ]);
  });

  it("charges browser redirect hops that reach the network to the shared budget", () => {
    const context = contextFor("http://127.0.0.1/", 1);

    const redirectHop = context.httpClient.evaluateBrowserRequest({
      url: "http://127.0.0.1/final",
      method: "GET",
      resourceType: "document",
      pageUrl: "http://127.0.0.1/start",
      isRedirect: true
    });
    const direct = context.httpClient.evaluateBrowserRequest({
      url: "http://127.0.0.1/another",
      method: "GET",
      resourceType: "document",
      pageUrl: "http://127.0.0.1/final"
    });

    expect(redirectHop.allowed).toBe(true);
    expect(direct.allowed).toBe(false);
    expect(direct.reason).toBe("network-request-budget-exceeded");
    expect(context.httpClient.budgetSnapshot()).toMatchObject({ browserPolicyEvents: 2, transmittedRequests: 1 });
  });

  it("atomically reserves the final shared browser request budget under concurrent preflight calls", async () => {
    const context = contextFor("http://127.0.0.1/", 1);

    const decisions = await Promise.all(
      Array.from({ length: 10 }, (_item, index) =>
        Promise.resolve(
          context.httpClient.evaluateBrowserRequest({
            url: `http://127.0.0.1/resource-${index}`,
            method: "GET",
            resourceType: "fetch",
            pageUrl: "http://127.0.0.1/"
          })
        )
      )
    );

    expect(decisions.filter((decision) => decision.allowed)).toHaveLength(1);
    expect(decisions.filter((decision) => !decision.allowed && decision.reason === "network-request-budget-exceeded")).toHaveLength(9);
    expect(context.httpClient.budgetSnapshot()).toMatchObject({ browserPolicyEvents: 10, transmittedRequests: 1 });
  });

  it("does not expose secrets in browser cache diagnostics or audit events", () => {
    const context = contextFor("http://127.0.0.1/");
    context.httpClient.setBrowserPolicyEventLimit(5);

    context.httpClient.evaluateBrowserRequest({
      url: "http://127.0.0.1/private?token=secret-token",
      method: "POST",
      resourceType: "fetch",
      pageUrl: "http://127.0.0.1/?session=secret-cookie"
    });

    expect(JSON.stringify(context.httpClient.budgetSnapshot())).not.toContain("secret");
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("secret-token");
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("secret-cookie");
  });
});

interface TestServer {
  port: number;
}

async function testServer(handler: Parameters<typeof createServer>[0]): Promise<TestServer> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  servers.push(server);
  return { port: (server.address() as AddressInfo).port };
}

function contextFor(target: string, maxRequests?: number, retryMaxAttempts?: number): ScanContext {
  const scope = {
    ...exampleScope,
    allowedDomains: ["127.0.0.1"],
    disallowedPaths: [],
    rateLimitPerSecond: 100,
    concurrency: 5
  };
  const config = {
    defaultMode: "quick" as const,
    reportsDir: "./reports",
    defaultScopeFile: "./examples/scope.example.json",
    bodyPreviewBytes: 1024,
    requestTimeoutMs: 5000
  };
  const plan = testPlan("quick", { scope, config });
  return new ScanContext({
    target,
    scope,
    config,
    plan:
      maxRequests || retryMaxAttempts
        ? { ...plan, limits: { ...plan.limits, ...(maxRequests ? { maxRequests } : {}), retry: { ...plan.limits.retry, ...(retryMaxAttempts ? { maxAttempts: retryMaxAttempts } : {}) } } }
        : plan,
    outputDir: "."
  });
}
