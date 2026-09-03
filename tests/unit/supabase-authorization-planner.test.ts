import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { AppError } from "../../src/core/errors/AppError.js";
import { analyzeSupabaseCatalog } from "../../src/modules/supabaseAuthorization/SupabaseAuthorizationModule.js";
import { planSupabaseAuthorization, supabaseAuthorizationInputSchema } from "../../src/modules/supabaseAuthorization/SupabaseAuthorizationPlanner.js";

const target = "https://project.supabase.co/";
const scope = { ...exampleScope, allowedDomains: ["project.supabase.co"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "DELETE"] as const };

describe("Supabase authorization planner", () => {
  it("builds a frozen, scoped, env-reference-only plan", () => {
    const input = supabaseAuthorizationInputSchema.parse({
      projectUrl: target,
      anonKeyEnv: "ROUTECAIRN_TEST_ANON",
      cases: [{ id: "anon-read", surface: "TABLE", resource: "public.documents", operation: "SELECT", actor: "ANONYMOUS", expectedDecision: "DENY", method: "GET", url: "/rest/v1/documents?id=eq.private-id", identityAssertions: [{ path: "id", equals: "private-id" }] }]
    });
    const plan = planSupabaseAuthorization(input, { target, scope });

    expect(plan.projectOrigin).toBe("https://project.supabase.co");
    expect(plan.cases[0]?.identityAssertions[0]?.expectedValueHash).toMatch(/^[a-f0-9]{64}$/);
    expect(plan.cases[0]?.comparisonFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(plan.anonKeyEnv).toBe("ROUTECAIRN_TEST_ANON");
    expect(JSON.stringify(plan)).not.toContain("eyJ");
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.cases)).toBe(true);
  });

  it("binds expected decisions and identity proof values into the case fingerprint", () => {
    const manifest = { projectUrl: target, cases: [{ id: "read", surface: "TABLE", resource: "public.documents", operation: "SELECT", actor: "ANONYMOUS", expectedDecision: "DENY", method: "GET", url: "/rest/v1/documents", identityAssertions: [{ path: "id", equals: "private-a" }] }] };
    const before = planSupabaseAuthorization(supabaseAuthorizationInputSchema.parse(manifest), { target, scope }).cases[0]!.comparisonFingerprint;
    const decision: any = structuredClone(manifest); decision.cases[0].expectedDecision = "ALLOW";
    expect(planSupabaseAuthorization(supabaseAuthorizationInputSchema.parse(decision), { target, scope }).cases[0]!.comparisonFingerprint).not.toBe(before);
    const identity: any = structuredClone(manifest); identity.cases[0].identityAssertions[0].equals = "private-b";
    expect(planSupabaseAuthorization(supabaseAuthorizationInputSchema.parse(identity), { target, scope }).cases[0]!.comparisonFingerprint).not.toBe(before);
  });

  it("rejects embedded credential headers and uncontracted mutations", () => {
    const inlineSecret = supabaseAuthorizationInputSchema.parse({
      projectUrl: target,
      cases: [{ id: "bad", surface: "TABLE", resource: "public.documents", operation: "SELECT", actor: "ANONYMOUS", expectedDecision: "DENY", method: "GET", url: "/rest/v1/documents", headers: { apikey: "secret" } }]
    });
    expect(() => planSupabaseAuthorization(inlineSecret, { target, scope })).toThrowError(AppError);

    const noContract = supabaseAuthorizationInputSchema.parse({
      projectUrl: target,
      cases: [{ id: "write", surface: "TABLE", resource: "public.documents", operation: "UPDATE", actor: "ANONYMOUS", expectedDecision: "DENY", method: "PATCH", url: "/rest/v1/documents?id=eq.disposable" }]
    });
    expect(() => planSupabaseAuthorization(noContract, { target, scope })).toThrow(/mutationContractCaseId/);
  });

  it("classifies RLS, sensitive-column, storage, schema, relationship, and SECURITY DEFINER risks", () => {
    const input = supabaseAuthorizationInputSchema.parse({
      projectUrl: target,
      cases: [{ id: "read", surface: "TABLE", resource: "public.documents", operation: "SELECT", actor: "ANONYMOUS", expectedDecision: "DENY", method: "GET", url: "/rest/v1/documents" }],
      catalog: {
        exposedSchemas: ["public", "private"], expectedExposedSchemas: ["public"],
        tables: [{ schema: "public", name: "documents", exposed: true, rlsEnabled: false, grants: [{ role: "anon", operations: ["SELECT", "UPDATE"] }], columns: [{ name: "secret_token", sensitive: true, exposedTo: ["anon"] }] }],
        functions: [{ schema: "public", name: "admin_export", securityDefiner: true, executableBy: ["anon"], searchPath: ["public"], usesDynamicSql: true }],
        storageBuckets: [{ name: "private-files", public: false, ownershipEnforced: false }],
        relationships: [{ name: "documents_owner", from: "documents", to: "documents", exposed: true }]
      }
    });
    const plan = planSupabaseAuthorization(input, { target, scope });
    const categories = analyzeSupabaseCatalog(plan).map((item) => item.category);

    expect(categories).toEqual(expect.arrayContaining(["RLS_DISABLED_EXPOSED_TABLE", "ANON_WRITE_GRANT", "SENSITIVE_COLUMN_ANON_EXPOSURE", "STORAGE_OWNERSHIP_NOT_ENFORCED", "SECURITY_DEFINER_PUBLIC_EXECUTE", "SECURITY_DEFINER_UNSAFE_SEARCH_PATH", "SECURITY_DEFINER_DYNAMIC_SQL", "UNEXPECTED_EXPOSED_SCHEMA", "RELATIONSHIP_TRAVERSAL_RISK"]));
  });
});
