import { describe, expect, it } from "vitest";
import { profileSummary, resolveScanProfile, scanProfiles } from "../../src/config/ScanProfiles.js";
import { scanProfileDefinitions } from "../../src/core/planning/ProfileDefinitions.js";

describe("scan profile definitions", () => {
  it("keeps authenticated as a primary-auth-required profile", () => {
    const profile = resolveScanProfile("authenticated");

    expect(profile.authentication.required).toBe(true);
    expect(profile.authentication.requireSingleProfile).toBe(true);
    expect(profile.authentication.requireAccountPair).toBe(false);
    expect(profile.enabledModules).toEqual(expect.arrayContaining(["authenticated-testing", "role-comparison", "state-aware-api"]));
  });

  it("keeps monitor low-noise and monitoring oriented", () => {
    expect(scanProfiles.monitor.authentication.level).toBe("none");
    expect(scanProfiles.monitor.output.stableForDiff).toBe(true);
    expect(scanProfiles.monitor.enabledModules).not.toContain("browser-crawler");
  });

  it("creates a defensive report summary copy", () => {
    const profile = resolveScanProfile("proof");
    const summary = profileSummary(profile);

    summary.modules.push("mutated");
    summary.reportFocus.push("mutated");

    expect(profile.enabledModules).not.toContain("mutated");
    expect(profile.reportFocus).not.toContain("mutated");
    expect(summary.limits.bodyPreviewBytes).toBe(16384);
  });

  it("has centralized definitions for every supported profile", () => {
    expect(Object.keys(scanProfileDefinitions).sort()).toEqual(["authenticated", "full", "monitor", "proof", "quick"]);
  });

  it("publishes exact bounded Next.js default and deep request ceilings", () => {
    const full = scanProfileDefinitions.full.moduleSettings["nextjs-review"]!;
    const proof = scanProfileDefinitions.proof.moduleSettings["nextjs-review"]!;
    expect((full.maxNextJsManifestRequests ?? 0) + (full.maxNextJsDataSurfaceRequests ?? 0) + (full.maxNextJsSourceMapRequests ?? 0) + (full.maxNextJsCacheDifferentialRequests ?? 0)).toBe(16);
    expect((proof.maxNextJsManifestRequests ?? 0) + (proof.maxNextJsDataSurfaceRequests ?? 0) + (proof.maxNextJsSourceMapRequests ?? 0) + (proof.maxNextJsCacheDifferentialRequests ?? 0)).toBe(38);
    expect(full.nextJsCacheReviewMode).toBe("PASSIVE_CACHE_REVIEW");
    expect(proof.nextJsCacheReviewMode).toBe("PASSIVE_CACHE_REVIEW");
  });

  it("rejects unsupported profiles", () => {
    expect(() => resolveScanProfile("reckless")).toThrow(/Unsupported scan profile/);
  });
});
