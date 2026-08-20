import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exampleScope } from "../../src/config/defaults.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import type { DnsResolver } from "../../src/core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../src/core/http/TransientResponseAnalysis.js";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
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

    expect(tenantA.bodyPreview).toBe("<redacted>");
    expect(tenantB.bodyPreview).toBe("<redacted>");
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

  it("redacts sensitive query values from direct HTTP audit events without changing the transmitted URL", async () => {
    const seen: string[] = [];
    const server = await testServer((request, response) => {
      seen.push(request.url ?? "");
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    await context.httpClient.send({ url: `http://127.0.0.1:${server.port}/private?access_token=secret-token&status=active`, method: "GET" });

    expect(seen).toEqual(["/private?access_token=secret-token&status=active"]);
    expect(JSON.stringify(context.state.getRequestAudit())).not.toContain("secret-token");
    expect(context.state.getRequestAudit()[0]?.requestedUrl).toContain("access_token=%3Credacted%3E");
    expect(context.state.getRequestAudit()[0]?.requestedUrl).toContain("status=active");
  });

  it("attests sensitive query, header, and cookie values without retaining their raw material", async () => {
    const secrets = {
      query: "query-value-should-never-persist",
      bearer: "bearer-value-should-never-persist",
      cookie: "cookie-value-should-never-persist",
      tenant: "tenant-value-should-never-persist"
    };
    const server = await testServer((request, response) => {
      response.writeHead(200, { "content-type": "text/plain", "set-cookie": "issued=server-session-secret; HttpOnly" });
      response.end([
        request.url,
        request.headers.authorization,
        request.headers.cookie,
        request.headers["x-tenant-id"]
      ].join("|"));
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);

    const result = await context.httpClient.send({
      url: `http://127.0.0.1:${server.port}/private?access_token=${secrets.query}&state=active`,
      method: "GET",
      headers: {
        Authorization: `Bearer ${secrets.bearer}`,
        Cookie: `session=${secrets.cookie}`,
        "X-Tenant-Id": secrets.tenant
      }
    });

    expect(result.statusCode).toBe(200);
    for (const secret of Object.values(secrets)) expect(result.bodyPreview).not.toContain(secret);
    for (const secret of Object.values(secrets)) expect(bodyPreviewForAnalysis(result)).toContain(secret);
    expect(String(result.headers["set-cookie"])).toBe("<redacted>");
    expect(String(headersForAnalysis(result)["set-cookie"])).toBe("issued=server-session-secret; HttpOnly");
    const attestations = result.valueAttestations ?? [];
    expect(attestations).toHaveLength(4);
    expect(attestations).toEqual(expect.arrayContaining([
      expect.objectContaining({ location: "query", name: "access_token", valueLength: secrets.query.length }),
      expect.objectContaining({ location: "header", name: "Authorization", classification: "bearer-token", valueLength: secrets.bearer.length }),
      expect.objectContaining({ location: "cookie", name: "session", classification: "session-token", valueLength: secrets.cookie.length }),
      expect.objectContaining({ location: "header", name: "X-Tenant-Id", classification: "tenant-context", valueLength: secrets.tenant.length })
    ]));
    for (const attestation of attestations) {
      expect(attestation.correlationFingerprint).toMatch(/^hmac-sha256:[a-f0-9]{64}$/);
      expect(attestation.requestId).toMatch(/^[0-9a-f-]{36}$/);
      expect(attestation.statusCode).toBe(200);
      expect(attestation.responseHash).toMatch(/^[a-f0-9]{64}$/);
      expect(attestation.transportOutcome).toBe("transmitted");
      expect(attestation.reproductionSteps.length).toBeGreaterThan(0);
    }
    context.state.recordResponse(result);
    const exposed = JSON.stringify({ result, audit: context.state.getRequestAudit(), report: context.state.toReport(testPlan("quick")) });
    for (const secret of Object.values(secrets)) expect(exposed).not.toContain(secret);
    expect(exposed).not.toContain("server-session-secret");
  });

  it("keeps cached response analysis transient while every public clone remains scrubbed", async () => {
    const secret = "cached-analysis-secret";
    let requestCount = 0;
    const server = await testServer((request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain", "x-auth-token": secret });
      response.end(`${request.headers.authorization}|${secret}`);
    });
    const context = contextFor(`http://127.0.0.1:${server.port}/`);
    const request = {
      url: `http://127.0.0.1:${server.port}/cached`,
      method: "GET" as const,
      headers: { Authorization: `Bearer ${secret}` }
    };

    const first = await context.httpClient.send(request);
    const cached = await context.httpClient.send(request);

    expect(requestCount).toBe(1);
    expect(first.bodyPreview).not.toContain(secret);
    expect(cached.bodyPreview).not.toContain(secret);
    expect(first.headers["x-auth-token"]).toBe("<redacted>");
    expect(cached.headers["x-auth-token"]).toBe("<redacted>");
    expect(bodyPreviewForAnalysis(first)).toContain(secret);
    expect(bodyPreviewForAnalysis(cached)).toContain(secret);
    expect(headersForAnalysis(cached)["x-auth-token"]).toBe(secret);
    expect(JSON.stringify({ first, cached, audit: context.state.getRequestAudit() })).not.toContain(secret);
  });

  it("correlates the same value within one scan, including cache reuse, but not across scans", async () => {
    let requestCount = 0;
    const secret = "same-scan-correlation-secret";
    const server = await testServer((_request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
    });
    const firstContext = contextFor(`http://127.0.0.1:${server.port}/`);
    const secondContext = contextFor(`http://127.0.0.1:${server.port}/`);
    const request = {
      url: `http://127.0.0.1:${server.port}/same`,
      method: "GET" as const,
      headers: { Authorization: `Bearer ${secret}` }
    };

    const first = await firstContext.httpClient.send(request);
    const cached = await firstContext.httpClient.send(request);
    const separateScan = await secondContext.httpClient.send(request);

    expect(requestCount).toBe(2);
    const firstAttestation = first.valueAttestations?.[0];
    const cachedAttestation = cached.valueAttestations?.[0];
    const separateAttestation = separateScan.valueAttestations?.[0];
    expect(firstAttestation?.correlationFingerprint).toBe(cachedAttestation?.correlationFingerprint);
    expect(firstAttestation?.correlationFingerprint).not.toBe(separateAttestation?.correlationFingerprint);
    expect(firstAttestation?.transportOutcome).toBe("transmitted");
    expect(cachedAttestation?.transportOutcome).toBe("cache-reused");
    expect(firstAttestation?.requestId).not.toBe(cachedAttestation?.requestId);
    expect(JSON.stringify(firstContext.state.getRequestAudit())).not.toContain(secret);
    expect(JSON.stringify(secondContext.state.getRequestAudit())).not.toContain(secret);
  });

  it("does not reuse cached POST responses and records salted body fingerprints without raw IDs", async () => {
    let requestCount = 0;
    const server = await testServer((request, response) => {
      requestCount += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ requestCount }));
    });
    const body = '{"dryRun":true,"objectIds":["project-a-001","project-b-002"]}';
    const firstContext = contextFor(`http://127.0.0.1:${server.port}/`);
    const secondContext = contextFor(`http://127.0.0.1:${server.port}/`);

    const first = await firstContext.httpClient.send({ url: `http://127.0.0.1:${server.port}/bulk`, method: "POST", headers: { "content-type": "application/json" }, body });
    const second = await firstContext.httpClient.send({ url: `http://127.0.0.1:${server.port}/bulk`, method: "POST", headers: { "content-type": "application/json" }, body });
    await secondContext.httpClient.send({ url: `http://127.0.0.1:${server.port}/bulk`, method: "POST", headers: { "content-type": "application/json" }, body });

    expect(first.bodyPreview).toContain('"requestCount":1');
    expect(second.bodyPreview).toContain('"requestCount":2');
    expect(requestCount).toBe(3);
    expect(firstContext.state.getRequestAudit().map((entry) => entry.outcome)).toEqual(["sent", "sent"]);
    const firstHash = firstContext.state.getRequestAudit()[0]?.requestBodyHash;
    const secondScanHash = secondContext.state.getRequestAudit()[0]?.requestBodyHash;
    expect(firstHash).toBeTruthy();
    expect(secondScanHash).toBeTruthy();
    expect(firstHash).not.toBe(secondScanHash);
    expect(JSON.stringify(firstContext.state.getRequestAudit())).not.toContain("project-a-001");
    expect(JSON.stringify(firstContext.state.getRequestAudit())).not.toContain(body);
  });

  it("pins a hostname request to the RouteCairn-resolved address while preserving Host authority", async () => {
    let hostHeader = "";
    let requestCount = 0;
    const server = await testServer((request, response) => {
      requestCount += 1;
      hostHeader = String(request.headers.host ?? "");
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("pinned");
    });
    let resolverCalls = 0;
    const broker = brokerFor(`http://app.test:${server.port}/`, async (hostname) => {
      resolverCalls += 1;
      expect(hostname).toBe("app.test");
      return [{ address: "127.0.0.1", family: 4 }];
    });

    const response = await broker.send({ url: `http://app.test:${server.port}/safe`, method: "GET" });

    expect(response.statusCode).toBe(200);
    expect(response.bodyPreview).toBe("pinned");
    expect(hostHeader).toBe(`app.test:${server.port}`);
    expect(requestCount).toBe(1);
    expect(resolverCalls).toBe(1);
  });

  it("fails closed on mixed public and private DNS answers before transmission", async () => {
    let requestCount = 0;
    const server = await testServer((_request, response) => {
      requestCount += 1;
      response.writeHead(200).end("should-not-send");
    });
    const broker = brokerFor(`http://app.test:${server.port}/`, async () => [
      { address: "127.0.0.1", family: 4 },
      { address: "93.184.216.34", family: 4 }
    ]);

    const response = await broker.send({ url: `http://app.test:${server.port}/safe`, method: "GET" });

    expect(response.error?.name).toBe("DNS_MIXED_DESTINATION_CLASSES");
    expect(requestCount).toBe(0);
  });

  it("re-resolves redirect destinations and blocks newly prohibited answers", async () => {
    const server = await testServer((request, response) => {
      if (request.url === "/start") {
        response.writeHead(302, { location: "/final" });
        response.end();
        return;
      }
      response.writeHead(200).end("should-not-final");
    });
    let calls = 0;
    const broker = brokerFor(`http://app.test:${server.port}/`, async () => {
      calls += 1;
      return calls === 1 ? [{ address: "127.0.0.1", family: 4 }] : [{ address: "169.254.169.254", family: 4 }];
    }, 5);

    const response = await broker.send({ url: `http://app.test:${server.port}/start`, method: "GET" });

    expect(response.error?.name).toBe("DNS_PROHIBITED_ADDRESS");
    expect(calls).toBe(2);
  });

  it("re-resolves retry attempts and blocks a prohibited retry destination", async () => {
    const server = await testServer((_request, response) => {
      response.writeHead(500, { "content-type": "text/plain" });
      response.end("retry");
    });
    let calls = 0;
    const broker = brokerFor(`http://app.test:${server.port}/`, async () => {
      calls += 1;
      return calls === 1 ? [{ address: "127.0.0.1", family: 4 }] : [{ address: "169.254.169.254", family: 4 }];
    }, 5, 2);

    const response = await broker.send({ url: `http://app.test:${server.port}/retry`, method: "GET" });

    expect(response.error?.name).toBe("DNS_PROHIBITED_ADDRESS");
    expect(calls).toBe(2);
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
    allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"],
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

function brokerFor(target: string, dnsResolver: DnsResolver, maxRequests = 10, retryMaxAttempts = 1): RequestSafetyBroker {
  const scope = {
    ...exampleScope,
    sameOriginOnly: true,
    allowedDomains: ["app.test"],
    allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"],
    disallowedPaths: [],
    rateLimitPerSecond: 100,
    concurrency: 5
  };
  return new RequestSafetyBroker(
    {
      userAgent: "RouteCairn/Test",
      timeoutMs: 3000,
      bodyPreviewBytes: 1024,
      maxResponseBytes: 4096,
      rateLimitPerSecond: 100,
      concurrency: 5,
      maxRequests,
      dnsResolver,
      retry: {
        maxAttempts: retryMaxAttempts,
        baseDelayMs: 1,
        maxDelayMs: 1,
        retryStatusCodes: [500]
      }
    },
    new ScopeMatcher(target, scope),
    () => undefined
  );
}
