import { describe, expect, it } from "vitest";
import { scopeSchema } from "../../src/config/ConfigSchema.js";
import { assertRegisteredTargetScope } from "../../src/dashboard/execution/RegisteredTargetScope.js";

const approved = scopeSchema.parse({
  program: "Registered target approval",
  allowedDomains: ["api.example.test"],
  disallowedPaths: ["/admin", "/billing"],
  allowedMethods: ["GET", "HEAD", "OPTIONS", "PATCH"],
  rateLimitPerSecond: 2,
  concurrency: 2,
  maxDepth: 2,
  sameOriginOnly: true,
  includeSubdomains: false,
  respectRobotsTxt: true
});

describe("registered target scope binding", () => {
  it("accepts a narrower executable scope", () => {
    const requested = scopeSchema.parse({
      ...approved,
      disallowedPaths: ["/admin", "/billing", "/account/delete"],
      allowedMethods: ["GET", "HEAD"],
      rateLimitPerSecond: 1,
      concurrency: 1,
      maxDepth: 1
    });
    expect(() => assertRegisteredTargetScope(requested, approved, { rateLimitPerSecond: 1, concurrency: 1, maxDepth: 1 })).not.toThrow();
  });

  it("rejects every material expansion of the registered authorization boundary", () => {
    const cases = [
      scopeSchema.parse({ ...approved, allowedDomains: ["other.example.test"] }),
      scopeSchema.parse({ ...approved, allowedMethods: [...approved.allowedMethods, "DELETE"] }),
      scopeSchema.parse({ ...approved, disallowedPaths: ["/admin"] }),
      scopeSchema.parse({ ...approved, sameOriginOnly: false }),
      scopeSchema.parse({ ...approved, includeSubdomains: true }),
      scopeSchema.parse({ ...approved, respectRobotsTxt: false })
    ];
    for (const requested of cases) {
      expect(() => assertRegisteredTargetScope(requested, approved, { rateLimitPerSecond: requested.rateLimitPerSecond, concurrency: requested.concurrency, maxDepth: requested.maxDepth })).toThrow(/REGISTERED_TARGET_SCOPE_EXCEEDED/);
    }
    expect(() => assertRegisteredTargetScope(approved, approved, { rateLimitPerSecond: 3, concurrency: 2, maxDepth: 2 })).toThrow(/request rate/);
    expect(() => assertRegisteredTargetScope(approved, approved, { rateLimitPerSecond: 2, concurrency: 3, maxDepth: 2 })).toThrow(/concurrency/);
    expect(() => assertRegisteredTargetScope(approved, approved, { rateLimitPerSecond: 2, concurrency: 2, maxDepth: 3 })).toThrow(/crawl depth/);
  });

  it("does not treat a wildcard-only approval as approval for its root domain", () => {
    const wildcardApproval = scopeSchema.parse({ ...approved, allowedDomains: ["*.example.test"], includeSubdomains: true });
    const rootRequest = scopeSchema.parse({ ...approved, allowedDomains: ["example.test"], includeSubdomains: false });
    const childRequest = scopeSchema.parse({ ...approved, allowedDomains: ["api.example.test"], includeSubdomains: false });

    expect(() => assertRegisteredTargetScope(rootRequest, wildcardApproval, { rateLimitPerSecond: 2, concurrency: 2, maxDepth: 2 })).toThrow(/domains/);
    expect(() => assertRegisteredTargetScope(childRequest, wildcardApproval, { rateLimitPerSecond: 2, concurrency: 2, maxDepth: 2 })).not.toThrow();
  });
});
