import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { scopeSchema, transportConfigSchema } from "../../src/config/ConfigSchema.js";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
import { normalizeUrl } from "../../src/core/urls/UrlNormalizer.js";
import { TargetAuthorizationGuard, targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";

const runs = Number(process.env.ROUTECAIRN_PROPERTY_RUNS ?? 500);
const seed = Number(process.env.ROUTECAIRN_PROPERTY_SEED ?? 26_092_028);

describe("schema, parser, and authorization state properties", () => {
  it("normalizes an already normalized HTTP URL to the same value", () => {
    fc.assert(fc.property(
      fc.domain(),
      fc.array(fc.stringMatching(/^[a-z0-9_-]{1,12}$/), { maxLength: 6 }),
      fc.array(fc.tuple(fc.stringMatching(/^[a-z]{1,8}$/), fc.string({ maxLength: 20 })), { maxLength: 8 }),
      (domain, segments, query) => {
        const url = new URL(`https://${domain}/${segments.join("/")}`);
        for (const [key, value] of query) url.searchParams.append(key, value);
        const once = normalizeUrl(url.toString());
        expect(normalizeUrl(once)).toBe(once);
      }
    ), { numRuns: runs, seed });
  });

  it("keeps scope decisions closed under every generated external hostname", () => {
    const matcher = new ScopeMatcher("https://service.example.test", scopeSchema.parse({
      program: "property",
      allowedDomains: ["service.example.test"],
      disallowedPaths: ["/logout"],
      allowedMethods: ["GET"]
    }));
    fc.assert(fc.property(fc.domain(), fc.string({ maxLength: 80 }), (domain, value) => {
      fc.pre(domain.toLowerCase() !== "service.example.test" && !domain.toLowerCase().endsWith(".service.example.test"));
      expect(matcher.decide(`https://${domain}/?value=${encodeURIComponent(value)}`).allowed).toBe(false);
    }), { numRuns: runs, seed: seed + 1 });
  });

  it("accepts only transport timeout orderings that preserve the configured invariant", () => {
    fc.assert(fc.property(
      fc.integer({ min: 100, max: 120_000 }),
      fc.integer({ min: 100, max: 300_000 }),
      (keepAliveTimeoutMs, keepAliveMaxTimeoutMs) => {
        const parsed = transportConfigSchema.safeParse({ keepAliveTimeoutMs, keepAliveMaxTimeoutMs });
        expect(parsed.success).toBe(keepAliveMaxTimeoutMs >= keepAliveTimeoutMs);
      }
    ), { numRuns: runs, seed: seed + 2 });
  });

  it("never advances the authorization ledger for denied requests", () => {
    const input = targetAuthorizationSchema.parse({
      schemaVersion: 1,
      mode: "BUG_BOUNTY_AUTHORIZED",
      targetOrigin: "https://app.test",
      proof: { reference: "property fixture", sha256: "a".repeat(64) },
      bugBounty: {
        program: "Property fixture",
        platform: "Internal",
        scopeDocumentSha256: "b".repeat(64),
        inScope: [{ origin: "https://app.test", pathPrefix: "/allowed" }],
        outOfScope: [{ origin: "https://app.test", pathPrefix: "/allowed/private" }],
        rules: ["Read only"],
        prohibitedActions: ["No writes"],
        startsAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2099-01-01T00:00:00.000Z",
        maxRequests: 3,
        rateLimitPerSecond: 3,
        requests: [],
        reportMode: "BUG_BOUNTY_SAFE"
      }
    });
    fc.assert(fc.property(fc.array(fc.constantFrom("/outside", "/allowed/private", "/allowed/%2e%2e/private"), { maxLength: 30 }), (paths) => {
      const guard = new TargetAuthorizationGuard(input, () => Date.parse("2026-09-28T00:00:00.000Z"));
      for (const path of paths) expect(guard.reserve(`https://app.test${path}`, "GET")).toBeDefined();
      expect(guard.snapshot().transmittedRequests).toBe(0);
      expect(guard.reserve("https://app.test/allowed", "GET")).toBeUndefined();
      expect(guard.snapshot().transmittedRequests).toBe(1);
    }), { numRuns: runs, seed: seed + 3 });
  });
});
