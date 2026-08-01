import { describe, expect, it } from "vitest";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import type { ScanProfileName } from "../../src/config/ScanProfiles.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { moduleCatalog } from "../../src/core/planning/ModuleCatalog.js";
import { scanProfileDefinitions } from "../../src/core/planning/ProfileDefinitions.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import type { ModuleId, ScanProfileDefinition } from "../../src/core/planning/ScanPlan.js";
import { legacyModeCompatibility } from "../../src/cli/commands/scan.js";
import type { ScanMode } from "../../src/config/ConfigSchema.js";

const profiles: ScanProfileName[] = ["quick", "full", "authenticated", "monitor", "proof"];

describe("ScanPlanner", () => {
  it.each(profiles)("resolves %s with valid input", (profile) => {
    const plan = resolve(profile, profile === "authenticated" ? "single" : "none");

    expect(plan.profile).toBe(profile);
    expect(plan.modules.length).toBeGreaterThan(0);
    expect(plan.schemaVersion).toBe(1);
    expect(plan.output.includePlan).toBe(true);
  });

  it("produces meaningfully different plans for all five profiles", () => {
    const fingerprints = profiles.map((profile) => {
      const plan = resolve(profile, profile === "authenticated" ? "pair" : "none");
      return JSON.stringify({
        modules: plan.modules.map((modulePlan) => modulePlan.id),
        limits: plan.limits,
        evidence: plan.evidence,
        auth: plan.authentication.level,
        stableForDiff: plan.output.stableForDiff
      });
    });

    expect(new Set(fingerprints).size).toBe(profiles.length);
  });

  it("keeps quick and full distinct in modules and limits", () => {
    const quick = resolve("quick");
    const full = resolve("full");

    expect(quick.modules.map((modulePlan) => modulePlan.id)).not.toEqual(full.modules.map((modulePlan) => modulePlan.id));
    expect(quick.limits.maxRequests).toBeLessThan(full.limits.maxRequests);
    expect(quick.limits.concurrency).toBeLessThan(full.limits.concurrency);
    expect(full.modules.map((modulePlan) => modulePlan.id)).toContain("browser-crawler");
    expect(quick.modules.map((modulePlan) => modulePlan.id)).not.toContain("browser-crawler");
  });

  it("includes authenticated capabilities unavailable to unauthenticated profiles", () => {
    const authenticated = resolve("authenticated", "pair");
    const full = resolve("full");

    expect(authenticated.authentication.required).toBe(true);
    expect(authenticated.modules.map((modulePlan) => modulePlan.id)).toEqual(
      expect.arrayContaining(["authenticated-testing", "role-comparison", "state-aware-api"])
    );
    expect(full.modules.map((modulePlan) => modulePlan.id)).not.toContain("authenticated-testing");
    expect(full.modules.map((modulePlan) => modulePlan.id)).not.toContain("role-comparison");
  });

  it("fails before execution when authenticated profile lacks primary auth context", () => {
    expect(() => resolve("authenticated")).toThrow(/requires --auth/);
  });

  it("resolves authenticated with one valid account and excludes account-pair modules explicitly", () => {
    const plan = resolve("authenticated", "single");

    expect(plan.authentication).toMatchObject({ required: true, level: "single-profile", hasSingleProfile: true, hasAccountPair: false });
    expect(plan.modules.map((modulePlan) => modulePlan.id)).toContain("authenticated-testing");
    expect(plan.modules.map((modulePlan) => modulePlan.id)).not.toContain("role-comparison");
    expect(plan.skippedModules).toContainEqual({ id: "role-comparison", reason: "missing-account-pair" });
  });

  it("resolves authenticated with two accounts and includes account-pair modules", () => {
    const plan = resolve("authenticated", "pair");

    expect(plan.authentication).toMatchObject({ hasSingleProfile: true, hasAccountPair: true });
    expect(plan.modules.map((modulePlan) => modulePlan.id)).toContain("role-comparison");
  });

  it("fails when a two-account module is explicitly requested without account-pair context", () => {
    expect(() =>
      new ScanPlanner(createDefaultPluginRegistry()).resolve({
        requestedProfile: "authenticated",
        scope: exampleScope,
        config: defaultConfig,
        authProfile: { label: "auth", headers: { Cookie: "session=secret" }, cookies: [], notes: [] },
        overrides: { includeModules: ["baseline", "auth-surface", "authenticated-testing", "role-comparison"] }
      })
    ).toThrow(/requires account-pair/);
  });

  it("does not serialize authentication secrets into plans", () => {
    const plan = resolve("authenticated", "pair");
    const serialized = JSON.stringify(plan);

    expect(serialized).not.toContain("session=secret");
    expect(serialized).not.toContain("session=a");
    expect(serialized).not.toContain("session=b");
  });

  it("selects only monitoring-compatible modules for monitor", () => {
    const plan = resolve("monitor");
    const incompatible = plan.modules.filter((modulePlan) => !moduleCatalog[modulePlan.id].monitoringCompatible);

    expect(incompatible).toEqual([]);
    expect(plan.output.stableForDiff).toBe(true);
  });

  it("applies stronger evidence requirements for proof", () => {
    const proof = resolve("proof");
    const full = resolve("full");

    expect(proof.evidence.level).toBe("strong");
    expect(proof.evidence.requireReproducibleEvidence).toBe(true);
    expect(proof.evidence.retainProofBlocks).toBe(true);
    expect(full.evidence.level).toBe("normal");
  });

  it("rejects unknown profiles", () => {
    const planner = new ScanPlanner(createDefaultPluginRegistry());

    expect(() =>
      planner.resolve({
        requestedProfile: "reckless" as ScanProfileName,
        scope: exampleScope,
        config: defaultConfig
      })
    ).toThrow(/Unknown scan profile/);
  });

  it("rejects unknown modules", () => {
    const planner = plannerWithProfile({ enabledModules: ["not-real" as ModuleId] });

    expect(() => planner.resolve(input("quick"))).toThrow(/unknown module/);
  });

  it("rejects invalid limits", () => {
    const planner = plannerWithProfile({ limits: { maxRequests: -1 } });

    expect(() => planner.resolve(input("quick"))).toThrow(/Invalid scan limit/);
  });

  it("rejects missing dependencies", () => {
    const planner = plannerWithProfile({ enabledModules: ["api-probe"] });

    expect(() => planner.resolve(input("quick"))).toThrow(/required dependency/);
  });

  it("orders modules deterministically with dependencies before dependents", () => {
    const planA = resolve("proof");
    const planB = resolve("proof");
    const ids = planA.modules.map((modulePlan) => modulePlan.id);

    expect(ids).toEqual(planB.modules.map((modulePlan) => modulePlan.id));
    expect(ids.indexOf("state-aware-api")).toBeLessThan(ids.indexOf("proof-mode"));
    expect(ids.indexOf("api-mapper")).toBeLessThan(ids.indexOf("api-probe"));
  });

  it("does not mutate profile configuration between scans", () => {
    const before = JSON.stringify(scanProfileDefinitions.quick);
    const plan = resolve("quick");

    expect(() => {
      (plan.modules as { push: (value: unknown) => void }).push({ id: "mutated" });
    }).toThrow();
    expect(JSON.stringify(scanProfileDefinitions.quick)).toBe(before);
  });

  it("deep-freezes nested plan objects", () => {
    const plan = resolve("proof");

    expect(Object.isFrozen(plan.modules)).toBe(true);
    expect(Object.isFrozen(plan.modules[0]?.settings)).toBe(true);
    expect(Object.isFrozen(plan.limits.retry)).toBe(true);
    expect(Object.isFrozen(plan.metadata)).toBe(true);
    expect(() => {
      (plan.limits.retry as { maxAttempts: number }).maxAttempts = 99;
    }).toThrow();
    expect(() => {
      (plan.modules[0]?.settings as { maxEndpoints: number }).maxEndpoints = 99;
    }).toThrow();
    expect(() => {
      (plan.metadata as { resolvedProfile: string }).resolvedProfile = "mutated";
    }).toThrow();
  });

  it("records legacy mode translation at the compatibility boundary", () => {
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({
      requestedProfile: "full",
      scope: exampleScope,
      config: defaultConfig,
      legacyMode: "api",
      legacyModeTranslation: 'Legacy mode "api" translated to scan profile "full" at the CLI boundary.'
    });

    expect(plan.metadata.legacyMode).toBe("api");
    expect(plan.metadata.legacyModeTranslation).toContain("translated");
  });

  it("propagates per-profile limits to the execution plan", () => {
    const plan = resolve("quick");

    expect(plan.limits.maxRequests).toBe(80);
    expect(plan.limits.requestTimeoutMs).toBe(10000);
    expect(plan.limits.retry.maxAttempts).toBe(1);
  });

  it("applies module-specific overrides", () => {
    const plan = resolve("quick");
    const apiProbe = plan.modules.find((modulePlan) => modulePlan.id === "api-probe");
    const pathDiscovery = plan.modules.find((modulePlan) => modulePlan.id === "path-discovery");

    expect(apiProbe?.settings.maxEndpoints).toBe(12);
    expect(pathDiscovery?.settings.pathSources).toEqual(["wordlist:common", "wordlist:api"]);
  });

  it.each([
    ["quick", "quick", "equivalent", ["baseline", "tech-fingerprint", "js-intelligence", "path-discovery", "api-mapper", "api-probe", "auth-surface", "parameter-analysis", "vulnerability-workflows"]],
    ["full", "full", "equivalent", undefined],
    ["api", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "path-discovery", "api-mapper", "api-probe", "auth-surface", "parameter-analysis", "vulnerability-workflows"]],
    ["admin", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "path-discovery", "api-mapper", "auth-surface", "parameter-analysis", "vulnerability-workflows"]],
    ["backup", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "path-discovery", "exposure-review"]],
    ["headers", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "header-review"]],
    ["cookies", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "cookie-review"]],
    ["cors", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "cors-review"]],
    ["methods", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "method-review"]],
    ["js", "full", "narrower-than-full", ["baseline", "tech-fingerprint", "js-intelligence", "path-discovery", "api-mapper", "api-probe"]],
    [
      "browser",
      "full",
      "narrower-than-full",
      [
        "baseline",
        "tech-fingerprint",
        "browser-crawler",
        "js-intelligence",
        "api-mapper",
        "api-probe",
        "auth-surface",
        "nextjs-review",
        "parameter-analysis",
        "state-aware-api",
        "vulnerability-workflows",
        "proof-mode",
        "workflow-validation"
      ]
    ]
  ] as Array<[ScanMode, ScanProfileName, string, ModuleId[] | undefined]>)(
    "translates legacy %s to %s with %s behaviour",
    (legacyMode, profileName, _relationship, modules) => {
      const compatibility = legacyModeCompatibility(legacyMode);
      const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({
        requestedProfile: compatibility.profileName,
        scope: exampleScope,
        config: defaultConfig,
        overrides: {
          ...(compatibility.includeModules ? { includeModules: compatibility.includeModules } : {}),
          ...(compatibility.moduleSettings ? { moduleSettings: compatibility.moduleSettings } : {})
        },
        legacyMode,
        legacyModeTranslation: "test translation"
      });

      expect(compatibility.profileName).toBe(profileName);
      expect(plan.metadata.legacyMode).toBe(legacyMode);
      if (modules) expect(plan.modules.map((modulePlan) => modulePlan.id)).toEqual(modules);
    }
  );
});

describe("module catalog integrity", () => {
  it("contains valid dependencies, settings, auth declarations, and profile references", () => {
    const ids = new Set(Object.keys(moduleCatalog));
    expect(ids.size).toBe(Object.keys(moduleCatalog).length);

    for (const metadata of Object.values(moduleCatalog)) {
      expect(metadata.id).toBeTruthy();
      for (const dependency of [...metadata.dependencies, ...metadata.orderAfter]) {
        expect(ids.has(dependency)).toBe(true);
      }
      for (const setting of Object.keys(metadata.defaultSettings)) {
        expect(metadata.supportedSettings).toContain(setting);
      }
      if (metadata.capabilities.includes("auth-comparison")) expect(["single-profile", "account-pair"]).toContain(metadata.requiresAuthentication);
      if (metadata.capabilities.includes("role-comparison")) expect(metadata.requiresAuthentication).toBe("account-pair");
      if (metadata.capabilities.includes("object-pair")) expect(metadata.requiresAuthentication).toBe("account-pair");
    }

    for (const profile of Object.values(scanProfileDefinitions)) {
      for (const moduleId of [...profile.enabledModules, ...profile.disabledModules]) {
        expect(ids.has(moduleId)).toBe(true);
      }
    }
  });
});

function resolve(profile: ScanProfileName, auth: "none" | "single" | "pair" = "none") {
  return new ScanPlanner(createDefaultPluginRegistry()).resolve({
    requestedProfile: profile,
    scope: exampleScope,
    config: defaultConfig,
    ...(auth !== "none"
      ? {
          authProfile: { label: "auth", headers: { Cookie: "session=secret" }, cookies: [], notes: [] },
          ...(auth === "pair"
            ? {
          authProfileSet: {
            accountA: { label: "a", headers: { Cookie: "session=a" }, cookies: [], notes: [] },
            accountB: { label: "b", headers: { Cookie: "session=b" }, cookies: [], notes: [] }
          }
              }
            : {})
        }
      : {})
  });
}

function input(profile: ScanProfileName) {
  return { requestedProfile: profile, scope: exampleScope, config: defaultConfig };
}

function plannerWithProfile(overrides: Partial<ScanProfileDefinition>): ScanPlanner {
  return new ScanPlanner(createDefaultPluginRegistry(), {
    quick: {
      ...scanProfileDefinitions.quick,
      ...overrides,
      moduleSettings: overrides.moduleSettings ?? scanProfileDefinitions.quick.moduleSettings,
      limits: overrides.limits ?? scanProfileDefinitions.quick.limits,
      perModuleLimits: overrides.perModuleLimits ?? scanProfileDefinitions.quick.perModuleLimits
    }
  });
}
