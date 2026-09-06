import { describe, expect, it } from "vitest";
import { dashboardScanCreateSchema } from "../../src/dashboard/contracts/DashboardSchemas.js";
import { advancedEngineIds, loadAdvancedEngineCatalog, validateAdvancedEngineInput } from "../../src/dashboard/contracts/AdvancedEngineSchemas.js";
import { dashboardRequiredAdvancedCapabilities, capabilityParityManifest, validateCapabilityParityManifest } from "../../src/dashboard/admin/CapabilityParityManifest.js";
import { resolveDashboardScanPlan, safeConfigurationSummary } from "../../src/dashboard/execution/ScanExecutionShared.js";
import { exactWorkflowRequests } from "../../src/dashboard/execution/ScanExecutionService.js";

describe("dashboard-native advanced engines", () => {
  it("ships a schema-valid, target-bound starter for every advanced builder", async () => {
    const catalog = await loadAdvancedEngineCatalog("https://app.example.test");
    expect(catalog.map((entry) => entry.id)).toEqual(advancedEngineIds);
    for (const entry of catalog) {
      const validation = validateAdvancedEngineInput(entry.id, entry.template);
      expect(validation.diagnostics, entry.id).toEqual([]);
      expect(validation.valid, entry.id).toBe(true);
      expect(JSON.stringify(entry.template)).not.toContain("https://app.example.com");
    }
  });

  it("accepts every dashboard starter through the scan-create contract without a server path", async () => {
    const target = "https://app.example.test";
    const catalog = await loadAdvancedEngineCatalog(target);
    for (const entry of catalog) {
      const value = entry.template as Record<string, unknown>;
      const inline = entry.id === "pre-handover-assault"
        ? { preHandover: value.orchestration, targetAuthorization: value.authorization }
        : { [entry.requestField]: value };
      const result = dashboardScanCreateSchema.safeParse({ ...publicStudioRequest(target), ...inline });
      expect(result.success, entry.id).toBe(true);
    }
  });

  it("plans inline Supabase authorization without a filesystem manifest and binds its safe contract digest", async () => {
    const target = "https://app.example.test";
    const request = dashboardScanCreateSchema.parse({
      ...publicStudioRequest(target),
      supabaseAuthorization: {
        schemaVersion: 1,
        projectUrl: target,
        cases: [{ id: "anonymous-documents-denied", surface: "TABLE", resource: "public.documents", operation: "SELECT", actor: "ANONYMOUS", expectedDecision: "DENY", boundary: "CROSS_USER", method: "GET", url: "/rest/v1/documents?id=eq.disposable-fixture", responseShape: "LIST", identityAssertions: [{ path: "id", equals: "disposable-fixture" }], forbiddenColumns: ["private_note"], requireVerifiedIdentity: false }]
      }
    });
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["supabase-authorization"]);
    expect(resolved.plan.supabaseAuthorization?.cases).toHaveLength(1);
    const safe = JSON.stringify(safeConfigurationSummary(request));
    expect(safe).toContain("contractDigest");
    expect(safe).not.toContain("disposable-fixture");
  });

  it("rejects mixed inline and legacy-file sources for the same executable contract", () => {
    const parsed = dashboardScanCreateSchema.safeParse({ ...publicStudioRequest("https://app.example.test"), supabaseAuthorization: { schemaVersion: 1, projectUrl: "https://app.example.test", cases: [] }, supabaseAuthorizationFile: "supabase.json" });
    expect(parsed.success).toBe(false);
    if (!parsed.success) expect(parsed.error.issues.some((issue) => issue.path.includes("supabaseAuthorization"))).toBe(true);
  });

  it("previews physical request capacity for learned automation, pre-handover setup, and signed URL follows", () => {
    expect(exactWorkflowRequests("authentication-lifecycle", { source: "BROWSER_LEARNED", maxRequests: 12, cases: [] })).toBe(12);
    expect(exactWorkflowRequests("pre-handover-assault", { objects: [{}, {}] })).toBe(5);
    expect(exactWorkflowRequests("supabase-authorization", { cases: [{ signedUrl: { followOnce: true } }, {}] })).toBe(3);
    expect(exactWorkflowRequests("assisted-review", { cases: [{}] })).toBe(0);
  });

  it("fails capability parity if any advanced engine loses its dashboard operation contract", () => {
    expect(validateCapabilityParityManifest()).toEqual([]);
    for (const id of dashboardRequiredAdvancedCapabilities) {
      const entry = capabilityParityManifest.find((candidate) => candidate.id === id);
      expect(entry?.status, id).toBe("FULL");
      expect(entry?.surfaces, id).toEqual(expect.arrayContaining(["API", "DASHBOARD"]));
      expect(entry?.dashboardOperation, id).toBeTruthy();
    }
    const weakened = capabilityParityManifest.map((entry) => entry.id === dashboardRequiredAdvancedCapabilities[0] ? { ...entry, surfaces: ["API"] as const } : entry);
    expect(validateCapabilityParityManifest(weakened)).not.toEqual([]);
  });
});

function publicStudioRequest(target: string) {
  return {
    target,
    profile: "quick",
    studio: {
      version: 1,
      scanName: "Advanced dashboard fixture",
      authorization: { category: "OWNED", confirmed: true },
      scope: { program: "Authorized fixture", allowedDomains: [new URL(target).hostname], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 3, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" },
      authentication: { mode: "public" },
      evidenceLevel: "minimal",
      outputs: { json: true, markdown: true, html: true },
      moduleSettings: {}, workflows: [], workflowSummary: []
    }
  };
}
