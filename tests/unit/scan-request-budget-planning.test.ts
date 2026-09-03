import { describe, expect, it } from "vitest";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { recoveryOnlyPlan } from "../../src/core/offensive/RecoveryRequestBudget.js";
import { dashboardScanCreateSchema } from "../../src/dashboard/contracts/DashboardSchemas.js";

describe("scan request budget planning", () => {
  it("resolves an exact ordinary scan-wide budget without inventing cleanup demand", () => {
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({
      requestedProfile: "quick",
      scope: exampleScope,
      config: defaultConfig,
      overrides: { maxRequests: 1, cleanupReservedRequests: 0 }
    });
    expect(plan.limits).toMatchObject({ maxRequests: 1, cleanupReservedRequests: 0 });
  });

  it("rejects a cleanup reserve larger than the total budget", () => {
    expect(() => new ScanPlanner(createDefaultPluginRegistry()).resolve({
      requestedProfile: "quick",
      scope: exampleScope,
      config: defaultConfig,
      overrides: { maxRequests: 4, cleanupReservedRequests: 5 }
    })).toThrow(/cleanupReservedRequests/);
  });

  it("accepts dashboard-first budget overrides and rejects an invalid split", () => {
    const base = {
      target: "https://app.example.test",
      profile: "quick",
      scopeFile: "scope.json",
      maxRequests: 120,
      cleanupReservedRequests: 25
    } as const;
    expect(dashboardScanCreateSchema.parse(base)).toMatchObject({ maxRequests: 120, cleanupReservedRequests: 25 });
    expect(() => dashboardScanCreateSchema.parse({ ...base, maxRequests: 10, cleanupReservedRequests: 11 })).toThrow(/Cleanup reserve/);
  });

  it("reserves future cleanup for browser-learned lifecycle cases before they are compiled", () => {
    const lifecycle = {
      schemaVersion: 1, enabled: true, source: "BROWSER_LEARNED", targetOrigin: "https://app.example.test",
      maxCases: 3, maxStepsPerCase: 8, maxRequests: 20, maxResponseBytes: 8192, cases: [], notes: [],
      automation: { categories: ["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION"] }
    } as any;
    const authProfile = { label: "member", safeAlias: "member", headers: {}, cookies: [], lifecycleSecrets: {}, notes: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] } } as any;
    const planner = new ScanPlanner(createDefaultPluginRegistry());
    const plan = planner.resolve({ requestedProfile: "quick", scope: exampleScope, config: defaultConfig, authProfile, authenticationLifecycle: lifecycle, overrides: { includeModules: ["authentication-lifecycle"] } });
    expect(plan.limits.cleanupReservedRequests).toBeGreaterThanOrEqual(3);
    expect(() => planner.resolve({ requestedProfile: "quick", scope: exampleScope, config: defaultConfig, authProfile, authenticationLifecycle: lifecycle, overrides: { includeModules: ["authentication-lifecycle"], cleanupReservedRequests: 2 } })).toThrow(/below the 3-request minimum/);
  });

  it("assigns a bounded recovery-only plan entirely to cleanup", () => {
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({
      requestedProfile: "quick",
      scope: exampleScope,
      config: defaultConfig
    });
    expect(recoveryOnlyPlan(plan, 12).limits).toMatchObject({
      maxRequests: 12,
      cleanupReservedRequests: 12,
      concurrency: 1,
      retry: { maxAttempts: 1 }
    });
  });
});
