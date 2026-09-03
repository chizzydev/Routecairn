import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { TargetAuthorizationGuard, targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
import { exampleScope } from "../../src/config/defaults.js";

export function bountyInput(origin = "https://app.test") {
  return { schemaVersion: 1, mode: "BUG_BOUNTY_AUTHORIZED", targetOrigin: origin, proof: { reference: "program authorization fixture", sha256: "a".repeat(64) }, bugBounty: { program: "Disposable fixture", platform: "Internal test", scopeDocumentSha256: "b".repeat(64), inScope: [{ origin, pathPrefix: "/" }], outOfScope: [{ origin, pathPrefix: "/never" }], rules: ["Exact disposable cases only"], prohibitedActions: ["No real payments"], startsAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", maxRequests: 5, rateLimitPerSecond: 2, requests: [], reportMode: "BUG_BOUNTY_SAFE" } };
}

describe("bug-bounty target authorization", () => {
  it("defaults to no authentication, mutations, races or destructive requests", () => {
    const guard = new TargetAuthorizationGuard(targetAuthorizationSchema.parse(bountyInput()));
    expect(guard.check("https://app.test/api", "GET")).toBeUndefined();
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) expect(guard.check("https://app.test/api", method)).toBe("authorization-request-not-approved");
    for (const url of ["https://app.test/never/x", "https://app.test.evil.test/", "https://app.test:444/", "https://app.test/%252fnever"]) expect(guard.check(url, "GET")).toBeDefined();
  });
  it("shares exact budgets and rolling rate limits across all consumers and checks expiry on every call", () => {
    let now = Date.parse("2026-08-31T00:00:00.000Z");
    const guard = new TargetAuthorizationGuard(targetAuthorizationSchema.parse(bountyInput()), () => now);
    const reserve = () => guard.reserve("https://app.test/", "GET");
    expect(reserve()).toBeUndefined(); expect(reserve()).toBeUndefined(); expect(reserve()).toBe("authorization-rate-limit");
    now += 1000; expect(reserve()).toBeUndefined(); expect(reserve()).toBeUndefined(); now += 1000; expect(reserve()).toBeUndefined(); expect(reserve()).toBe("authorization-budget-exhausted");
    now = Date.parse("2099-01-01T00:00:00.000Z"); expect(reserve()).toBe("authorization-window-closed");
  });
  it("binds read-only POST permissions to body bytes, never to every operation at that route", () => {
    const input = bountyInput(); const body = '{"query":"{ me { id } }"}';
    const parsed = targetAuthorizationSchema.parse({ ...input, bugBounty: { ...input.bugBounty, requests: [{ origin: input.targetOrigin, path: "/graphql", method: "POST", effect: "READ", bodySha256: createHash("sha256").update(body).digest("hex") }] } });
    const guard = new TargetAuthorizationGuard(parsed);
    expect(guard.reserve("https://app.test/graphql", "POST", body)).toBeUndefined();
    expect(guard.reserve("https://app.test/graphql", "POST", "mutation { deleteAll }")).toBe("authorization-body-mismatch");
    expect(guard.reserve("https://app.test/graphql", "POST")).toBe("authorization-body-mismatch");
  });
  it("enforces the same ledger for browser traffic and rejects learned mutations and streams", () => {
    const guard = new TargetAuthorizationGuard(targetAuthorizationSchema.parse(bountyInput()));
    const scope = { ...exampleScope, allowedDomains: ["app.test"], allowedMethods: ["GET", "POST"] as const, disallowedPaths: [] };
    const create = () => { const broker = new RequestSafetyBroker({ userAgent: "fixture", timeoutMs: 1000, bodyPreviewBytes: 1024, maxResponseBytes: 1024, rateLimitPerSecond: 50, concurrency: 1, maxRequests: 100, retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1, retryStatusCodes: [] } }, new ScopeMatcher("https://app.test", scope, guard), () => {}); broker.setBrowserPolicyEventLimit(100); return broker; };
    const request = { url: "https://app.test/read", method: "GET", resourceType: "fetch", pageUrl: "https://app.test" };
    expect(create().evaluateBrowserRequest(request).allowed).toBe(true);
    expect(create().evaluateBrowserRequest(request).allowed).toBe(true);
    expect(create().evaluateBrowserRequest(request).reason).toBe("authorization-rate-limit");
    expect(create().evaluateBrowserLoginRequest({ ...request, method: "POST" }).allowed).toBe(false);
    expect(create().evaluateBrowserRequest({ ...request, resourceType: "websocket" }).allowed).toBe(false);
  });
  it("rejects ambiguous mode/permission combinations", () => {
    const input = bountyInput();
    expect(() => targetAuthorizationSchema.parse({ ...input, mode: "INTERNAL_STAGING" })).toThrow();
    expect(() => targetAuthorizationSchema.parse({ ...input, bugBounty: { ...input.bugBounty, mutationPermitted: true } })).toThrow();
    expect(() => targetAuthorizationSchema.parse({ ...input, bugBounty: { ...input.bugBounty, requests: [{ origin: input.targetOrigin, path: "/graphql", method: "POST", effect: "READ" }] } })).toThrow();
  });
});
