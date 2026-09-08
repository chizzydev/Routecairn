import { describe, expect, it } from "vitest";
import { capabilityParityManifest, dashboardRequiredOperationalCapabilities, validateCapabilityParityManifest } from "../../../src/dashboard/admin/CapabilityParityManifest.js";

describe("administration capability parity manifest", () => {
  it("contains no partial required workflows and fully documents intentional CLI-only work", () => {
    expect(validateCapabilityParityManifest()).toEqual([]);
    expect(capabilityParityManifest.some((entry) => (entry.status as string) === "PARTIAL")).toBe(false);
    for (const entry of capabilityParityManifest.filter((item) => item.status === "INTENTIONAL_CLI_ONLY")) {
      expect(entry.reason).toBeTruthy(); expect(entry.owner).toBeTruthy(); expect(entry.safety).toBeTruthy();
    }
    for (const id of dashboardRequiredOperationalCapabilities) {
      expect(capabilityParityManifest.find((entry) => entry.id === id)).toMatchObject({ status: "FULL", surfaces: expect.arrayContaining(["API", "DASHBOARD"]), dashboardOperation: "MANAGED_WORKSPACE" });
    }
    const withoutBrowserDiagnostics = capabilityParityManifest.filter((entry) => entry.id !== "browser.connection-boundary");
    expect(validateCapabilityParityManifest(withoutBrowserDiagnostics)).toContain("browser.connection-boundary is missing from capability parity.");
    const withoutAdaptiveWorkspace = capabilityParityManifest.filter((entry) => entry.id !== "adaptive-security.intelligence-and-drift");
    expect(validateCapabilityParityManifest(withoutAdaptiveWorkspace)).toContain("adaptive-security.intelligence-and-drift is missing from capability parity.");
    const withoutProviderAdapters = capabilityParityManifest.filter((entry) => entry.id !== "fixture-provider-adapters.versioned-execution");
    expect(validateCapabilityParityManifest(withoutProviderAdapters)).toContain("fixture-provider-adapters.versioned-execution is missing from capability parity.");
    const withoutContinuousAssurance = capabilityParityManifest.filter((entry) => entry.id !== "continuous-assurance.scheduling-and-evidence");
    expect(validateCapabilityParityManifest(withoutContinuousAssurance)).toContain("continuous-assurance.scheduling-and-evidence is missing from capability parity.");
  });
});
