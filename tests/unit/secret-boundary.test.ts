import { describe, expect, it } from "vitest";
import { classifyTransientSecret } from "../../src/modules/secretBoundary/SecretBoundaryClassifier.js";
import { extractTransientSecretCandidates } from "../../src/modules/secretBoundary/SecretBoundaryExtractor.js";
import { planSecretBoundary } from "../../src/modules/secretBoundary/SecretBoundaryPlanner.js";
import { PublicConfigAnalyzer } from "../../src/modules/jsIntelligence/PublicConfigAnalyzer.js";

describe("secret-boundary classification", () => {
  it("distinguishes Supabase anon, publishable, and service-role credentials by semantics", () => {
    const anon = classifyTransientSecret({ name: "NEXT_PUBLIC_SUPABASE_KEY", value: jwt({ role: "anon" }), surface: "JAVASCRIPT_BUNDLE", publicExposure: true });
    const publishable = classifyTransientSecret({ name: "SUPABASE_KEY", value: "sb_publishable_example12345", surface: "HTML", publicExposure: true });
    const service = classifyTransientSecret({ name: "NEXT_PUBLIC_SUPABASE_KEY", value: jwt({ role: "service_role" }), surface: "JAVASCRIPT_BUNDLE", publicExposure: true });
    expect(anon).toMatchObject({ materialClass: "SUPABASE_ANON_KEY", boundary: "CLIENT_SAFE", findingEligible: false, supabaseRole: "anon" });
    expect(publishable).toMatchObject({ materialClass: "SUPABASE_PUBLISHABLE_KEY", boundary: "CLIENT_SAFE", findingEligible: false });
    expect(service).toMatchObject({ materialClass: "SUPABASE_SERVICE_ROLE_KEY", boundary: "SERVER_ONLY", impact: "CRITICAL", findingEligible: true, clientSafeNameConflict: true, supabaseRole: "service_role" });
  });

  it("classifies storage according to script accessibility and cookie attributes", () => {
    const local = classifyTransientSecret({ name: "access_token", value: "session-value-private-123", surface: "BROWSER_LOCAL_STORAGE", publicExposure: false });
    const protectedCookie = classifyTransientSecret({ name: "session_id", value: "session-value-private-456", surface: "COOKIE", publicExposure: false, cookie: { httpOnly: true, secure: true, sameSite: "Lax" } });
    const transportExposedCookie = classifyTransientSecret({ name: "refresh_token", value: "session-value-private-654", surface: "COOKIE", publicExposure: false, cookie: { httpOnly: true, secure: false } });
    const exposedCookie = classifyTransientSecret({ name: "session_id", value: "session-value-private-789", surface: "COOKIE", publicExposure: false, cookie: { httpOnly: false, secure: true } });
    expect(local.outcome).toBe("CLIENT_STORAGE_RISK");
    expect(protectedCookie).toMatchObject({ outcome: "SECURE_COOKIE_STORAGE", findingEligible: false, impact: "NONE" });
    expect(transportExposedCookie).toMatchObject({ outcome: "COOKIE_TRANSPORT_RISK", findingEligible: true, impact: "MEDIUM" });
    expect(exposedCookie).toMatchObject({ outcome: "CLIENT_STORAGE_RISK", findingEligible: true, impact: "HIGH" });
  });

  it("classifies server credentials, public client keys, personal fields, and build metadata", () => {
    expect(classifyTransientSecret({ name: "DATABASE_URL", value: "postgres://user:password@db.internal/app", surface: "RUNTIME_CONFIGURATION", publicExposure: true }).materialClass).toBe("DATABASE_CREDENTIAL");
    expect(classifyTransientSecret({ name: "STRIPE_PUBLISHABLE_KEY", value: "pk_test_publishable123", surface: "HTML", publicExposure: true }).boundary).toBe("CLIENT_SAFE");
    expect(classifyTransientSecret({ name: "viewer.ssn", value: "123-45-6789", surface: "GRAPHQL_RESPONSE", publicExposure: true }).outcome).toBe("SENSITIVE_FIELD_EXPOSURE");
    expect(classifyTransientSecret({ name: "BUILD_ID", value: "build-991", surface: "BUILD_METADATA", publicExposure: true }).impact).toBe("INFORMATIONAL");
  });

  it("extracts bounded JSON, assignment, and direct-token candidates", () => {
    const candidates = extractTransientSecretCandidates('{"nested":{"refresh_token":"refresh-private-123"}}\nDATABASE_URL=postgres://u:p@db/x\nconst key="ghp_abcdefghijklmnopqrstuvwxyz123456";', 10);
    expect(candidates).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "refresh_token", value: "refresh-private-123" }),
      expect.objectContaining({ name: "DATABASE_URL" }),
      expect.objectContaining({ name: "detected.vendor_token" })
    ]));
  });

  it("redacts server-only values before JavaScript intelligence stores config previews", () => {
    const service = jwt({ role: "service_role" });
    const values = new PublicConfigAnalyzer().analyze(`NEXT_PUBLIC_SUPABASE_KEY = "${service}"; VITE_API_BASE = "https://api.example.test";`);
    expect(values).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "NEXT_PUBLIC_SUPABASE_KEY", valuePreview: "<redacted-sensitive-config>", classification: "redacted-sensitive-config", secretMaterialClass: "SUPABASE_SERVICE_ROLE_KEY" }),
      expect.objectContaining({ name: "VITE_API_BASE", valuePreview: "https://api.example.test", classification: "public-frontend-config" })
    ]));
    expect(JSON.stringify(values)).not.toContain(service);
  });
});

describe("secret-boundary planning", () => {
  it("resolves bounded read-only defaults", () => {
    expect(planSecretBoundary({})).toMatchObject({ enabled: true, maxObservedResponses: 250, maxAdditionalRequests: 12, maxSourceMaps: 4, maxTotalCandidates: 1000, inspectSourceMaps: true });
  });

  it("rejects root, query-bearing, and oversized probe definitions", () => {
    expect(() => planSecretBoundary({ secretBoundaryProbePaths: ["/"] })).toThrow(/root/i);
    expect(() => planSecretBoundary({ secretBoundaryProbePaths: ["/config?tenant=all"] })).toThrow(/query/i);
    expect(() => planSecretBoundary({ maxSecretBoundaryAdditionalRequests: 33 })).toThrow();
  });
});

function jwt(payload: Record<string, unknown>): string {
  return `${Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.signatureplaceholder`;
}
