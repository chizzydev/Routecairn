// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanStudio } from "../../apps/dashboard-ui/src/ScanStudio";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.localStorage.clear(); window.sessionStorage.clear(); });

describe("Scan Studio UI", () => {
  it("renders all ten required steps from capability-backed data", async () => {
    stubApi();
    render(<ScanStudio onLaunched={() => undefined} />);
    const navigation = await screen.findByRole("navigation", { name: "Scan Studio steps" });
    expect(within(navigation).getByRole("button", { name: /Target/ })).toBeTruthy();
    for (const label of ["Scope", "Profile & Modules", "Authentication", "Verified Identity", "Browser & Limits", "Evidence & Outputs", "Controlled Workflows", "Plan Review", "Launch"]) expect(screen.getByRole("button", { name: new RegExp(label) })).toBeTruthy();
  });

  it("exposes bounded Next.js Deep Review settings without raw JSON", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes("capabilities")) return response({ profiles: [{ name: "full", displayName: "Full", description: "Full review", modules: ["baseline", "tech-fingerprint", "nextjs-review"], limits: {}, browserUse: "bounded", authComparisonDepth: "none", proofMode: false, reportFocus: [] }], modules: [
        { id: "baseline", displayName: "Baseline", description: "Baseline", phase: "baseline", capabilities: ["baseline"], requiresAuthentication: "none", dependencies: [], cost: "low", supportedSettings: [] },
        { id: "tech-fingerprint", displayName: "Technology", description: "Technology", phase: "fingerprint", capabilities: ["fingerprint"], requiresAuthentication: "none", dependencies: ["baseline"], cost: "low", supportedSettings: [] },
        { id: "nextjs-review", displayName: "Next.js Deep Review", description: "Next.js deep review", phase: "analysis", capabilities: ["nextjs"], requiresAuthentication: "none", dependencies: ["tech-fingerprint"], cost: "medium", supportedSettings: ["maxNextJsManifestRequests"] }
      ], controlledWorkflows: [], evidenceLevels: [{ id: "normal", retention: "Bounded" }] });
      if (path.includes("projects")) return response({ projects: [] });
      if (path.includes("targets")) return response({ targets: [] });
      return response({ profiles: [] });
    }));
    render(<ScanStudio onLaunched={() => undefined} />);
    fireEvent.change(await screen.findByLabelText("Target base URL"), { target: { value: "https://app.example.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm I am authorized/));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    const domain = screen.getByLabelText("New allowed domains rule"); fireEvent.change(domain, { target: { value: "app.example.test" } }); fireEvent.click(screen.getAllByRole("button", { name: "Add" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("checkbox", { name: /Next\.js Deep Review/i }));
    expect(screen.getByRole("group", { name: "Next.js Deep Review settings" })).toBeTruthy();
    expect(screen.getByLabelText("Next.js cache review mode")).toBeTruthy();
    expect(screen.getByLabelText("Manifest requests")).toBeTruthy();
    expect(document.body.textContent).toContain("Server Actions");
  });

  it("blocks forward navigation and exposes accessible validation", async () => {
    stubApi();
    render(<ScanStudio onLaunched={() => undefined} />);
    const navigation = await screen.findByRole("navigation", { name: "Scan Studio steps" });
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("status").textContent).toMatch(/valid HTTP or HTTPS target/i);
    expect(within(navigation).getByRole("button", { name: /Target/ }).getAttribute("aria-current")).toBe("step");
  });

  it("explains why a future step cannot be opened and focuses the blocker", async () => {
    stubApi();
    render(<ScanStudio onLaunched={() => undefined} />);
    const navigation = await screen.findByRole("navigation", { name: "Scan Studio steps" });

    fireEvent.click(within(navigation).getByRole("button", { name: /Authentication/ }));

    expect(screen.getByRole("status").textContent).toMatch(
      /Complete Target before opening Authentication: Enter a valid HTTP or HTTPS target/i,
    );
    expect(within(navigation).getByRole("button", { name: /Target/ }).getAttribute("aria-current")).toBe("step");
    expect(document.activeElement).toBe(
      screen.getByRole("heading", { name: "Target" }),
    );
  });

  it("preserves target state across Back and Next navigation", async () => {
    stubApi();
    render(<ScanStudio onLaunched={() => undefined} />);
    fireEvent.change(await screen.findByLabelText("Target base URL"), { target: { value: "https://app.example.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm I am authorized/));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("heading", { name: "Scope" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect((screen.getByLabelText("Target base URL") as HTMLInputElement).value).toBe("https://app.example.test");
  });

  it("exposes authoritative total and cleanup-reserved request budgets", async () => {
    stubApi();
    render(<ScanStudio onLaunched={() => undefined} />);
    fireEvent.change(await screen.findByLabelText("Target base URL"), { target: { value: "https://app.example.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm I am authorized/));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    const domain = screen.getByLabelText("New allowed domains rule");
    fireEvent.change(domain, { target: { value: "app.example.test" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Add" })[0]!);
    for (let step = 0; step < 4; step += 1) fireEvent.click(screen.getByRole("button", { name: "Next" }));

    expect(screen.getByRole("heading", { name: "Browser & Limits" })).toBeTruthy();
    const total = screen.getByLabelText("Total scan request budget") as HTMLInputElement;
    const cleanupReserve = screen.getByLabelText("Cleanup requests reserved") as HTMLInputElement;
    expect(total.placeholder).toBe("80");
    expect(cleanupReserve.placeholder).toBe("Automatic");
    fireEvent.change(total, { target: { value: "120" } });
    fireEvent.change(cleanupReserve, { target: { value: "25" } });
    expect(total.value).toBe("120");
    expect(cleanupReserve.value).toBe("25");
    expect(screen.getByText(/enforced across every engine, retry, redirect, API broker/i)).toBeTruthy();
  });

  it("adds normalized scope rules and detects duplicates", async () => {
    stubApi();
    render(<ScanStudio onLaunched={() => undefined} />);
    fireEvent.change(await screen.findByLabelText("Target base URL"), { target: { value: "https://app.example.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm I am authorized/));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    const input = screen.getByLabelText("New allowed domains rule");
    fireEvent.change(input, { target: { value: "APP.EXAMPLE.TEST." } });
    fireEvent.click(screen.getAllByRole("button", { name: "Add" })[0]!);
    expect(screen.getByText("app.example.test")).toBeTruthy();
    fireEvent.change(input, { target: { value: "app.example.test" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Add" })[0]!);
    expect(screen.getByRole("alert").textContent).toContain("Duplicate rule");
  });

  it("clears ephemeral secret fields on session expiry", async () => {
    stubApi();
    render(<ScanStudio onLaunched={() => undefined} />);
    fireEvent.change(await screen.findByLabelText("Target base URL"), { target: { value: "https://app.example.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm I am authorized/));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.change(screen.getByLabelText("Authentication model"), { target: { value: "primary" } });
    const token = screen.getByLabelText(/Bearer token/);
    fireEvent.change(token, { target: { value: "memory-only-token" } });
    fireEvent(window, new Event("routecairn:session-expired"));
    expect((screen.getByLabelText(/Bearer token/) as HTMLInputElement).value).toBe("");
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("exposes one launch action and prevents duplicate queue requests", async () => {
    let queueRequests = 0;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes("/api/scans/plan-preview")) {
        return response({
          previewIdentity: "a".repeat(64),
          profile: "quick",
          modules: [{ id: "baseline", phase: "discovery", settings: {} }],
          limits: {},
          evidence: {},
          skippedModules: [],
          controlledWorkflowRequests: [],
          planSnapshot: {},
          warnings: [],
        });
      }
      if (path.endsWith("/api/scans")) {
        queueRequests += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return response({ scanId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
      }
      if (path.includes("capabilities")) {
        return response({
          profiles: [{ name: "quick", displayName: "Quick", description: "Fast safe feedback", modules: ["baseline"], limits: { maxRequests: 80 }, browserUse: "off", authComparisonDepth: "none", proofMode: false, reportFocus: [] }],
          modules: [{ id: "baseline", displayName: "Baseline", description: "Baseline response", phase: "discovery", capabilities: ["baseline"], requiresAuthentication: "none", dependencies: [], cost: "low", supportedSettings: [] }],
          controlledWorkflows: [],
          evidenceLevels: [{ id: "minimal", retention: "Metadata only" }],
        });
      }
      if (path.includes("projects")) return response({ projects: [] });
      if (path.includes("targets")) return response({ targets: [] });
      return response({ profiles: [] });
    }));

    render(<ScanStudio onLaunched={() => undefined} />);
    fireEvent.change(await screen.findByLabelText("Target base URL"), { target: { value: "https://app.example.test" } });
    fireEvent.click(screen.getByLabelText(/I confirm I am authorized/));
    for (let step = 0; step < 8; step += 1) fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: "Resolve Plan" }));
    expect(await screen.findByText(/Plan resolved by RouteCairn ScanPlanner/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Continue to Launch" }));

    expect(screen.queryByRole("button", { name: "Launch Scan" })).toBeNull();
    const launch = screen.getByRole("button", { name: "Confirm and Launch" });
    fireEvent.click(launch);
    fireEvent.click(launch);
    expect(queueRequests).toBe(1);
    expect((screen.getByRole("button", { name: "Launching..." }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("opens retest drafts with safe historical values and fresh credential requirements", async () => {
    stubApi();
    render(<ScanStudio initialDraft={{ context: { findingId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", sourceOccurrenceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", sourceScanId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", relevantModule: "baseline", purpose: "Retest of RC-FIND-aaaaaaaa" }, target: "https://app.example.test", profile: "quick", scope: { program: "Retest fixture", allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 1, concurrency: 1, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/0.1" }, selectedModules: ["baseline"], evidenceLevel: "normal", outputs: { json: true, markdown: true, html: true }, historicalAuthenticationMode: "primary", freshCredentialsRequired: true, savedCredentialReferences: [], warning: "Historical secrets were not restored." }} onLaunched={() => undefined} />);
    expect(await screen.findByText("Retest of RC-FIND-aaaaaaaa")).toBeTruthy();
    expect(screen.getByText(/Fresh credentials required/i)).toBeTruthy();
    expect((screen.getByLabelText("Target base URL") as HTMLInputElement).value).toBe("https://app.example.test");
    expect(document.body.textContent).not.toContain("historical-token");
  });

  it("opens an approved adaptive recommendation directly in its target-bound dashboard builder", async () => {
    const target = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", displayName: "Adaptive target", baseOrigin: "https://app.example.test", authorizationType: "OWNED", authorizationSummary: "Owned fixture", classification: "PRIVATE", scanCount: 1, openFindingCount: 0, tags: [], approvedScope: { program: "Adaptive fixture", allowedDomains: ["app.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET", "POST"], rateLimitPerSecond: 2, concurrency: 2, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" }, defaultAuthTemplate: {}, productionEnabled: false, archived: false, rowVersion: 1 } as any;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes("advanced-engines/catalog")) return response({ engines: [{ id: "business-invariant", displayName: "Business invariant testing", description: "Bounded invariant cases", moduleId: "business-invariant", requestField: "businessInvariant", safety: "Explicit cleanup required.", requiresApproval: true, template: { schemaVersion: 1, cases: [] } }] });
      if (path.includes("capabilities")) return response({ profiles: [{ name: "quick", displayName: "Quick", description: "Quick", modules: ["baseline"], limits: { maxRequests: 80 }, browserUse: "off", authComparisonDepth: "none", proofMode: false, reportFocus: [] }], modules: [{ id: "baseline", displayName: "Baseline", description: "Baseline", phase: "discovery", capabilities: [], requiresAuthentication: "none", dependencies: [], cost: "low", supportedSettings: [] }, { id: "business-invariant", displayName: "Business invariant", description: "Invariant", phase: "testing", capabilities: [], requiresAuthentication: "optional", dependencies: [], cost: "medium", supportedSettings: [] }], controlledWorkflows: [], evidenceLevels: [{ id: "strong", retention: "Strong" }] });
      if (path.includes("projects")) return response({ projects: [] }); if (path.includes("targets")) return response({ targets: [target] }); return response({ profiles: [] });
    }));
    render(<ScanStudio initialAdaptiveDraft={{ target, engineId: "business-invariant" }} onLaunched={() => undefined} />);
    expect(await screen.findByRole("heading", { name: "Controlled Workflows" })).toBeTruthy();
    expect(await screen.findByRole("heading", { name: "Business invariant testing" })).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Close" })).toBeTruthy();
    expect(document.body.textContent).toContain("https://app.example.test");
    expect(document.body.textContent).toContain("Scope1 domain rule");
  });

  it("materializes a reviewed provider adapter with its exact engine, actors, limits, and binding", async () => {
    const target = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", displayName: "Adapter target", baseOrigin: "https://app.example.test", authorizationType: "OWNED", authorizationSummary: "Owned fixture", classification: "PRIVATE", scanCount: 1, openFindingCount: 0, tags: [], approvedScope: { program: "Adapter fixture", allowedDomains: ["app.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET", "POST"], rateLimitPerSecond: 2, concurrency: 2, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" }, defaultAuthTemplate: {}, productionEnabled: false, archived: false, rowVersion: 1 } as any;
    let previewRequest: any;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.includes("scans/plan-preview")) { previewRequest = JSON.parse(String(init?.body)); return response({ previewIdentity: "f".repeat(64), profile: "full", modules: [], limits: {}, evidence: {}, skippedModules: [], controlledWorkflowRequests: [], planSnapshot: {}, credentialReadiness: { ready: true, checkedAt: new Date().toISOString(), requiredValidThrough: new Date().toISOString(), blockers: [], warnings: [], profiles: [] }, warnings: [] }); }
      if (path.includes("advanced-engines/catalog")) return response({ engines: [{ id: "business-invariant", displayName: "Business invariant testing", description: "Bounded invariant cases", moduleId: "business-invariant", requestField: "businessInvariant", safety: "Explicit cleanup required.", requiresApproval: true, template: { schemaVersion: 1, cases: [] } }] });
      if (path.includes("capabilities")) return response({ profiles: [{ name: "full", displayName: "Full", description: "Full", modules: [], limits: { maxRequests: 200 }, browserUse: "optional", authComparisonDepth: "optional", proofMode: false, reportFocus: [] }], modules: [{ id: "business-invariant", displayName: "Business invariant", description: "Invariant", phase: "testing", capabilities: [], requiresAuthentication: "optional", dependencies: [], cost: "medium", supportedSettings: [] }], controlledWorkflows: [], evidenceLevels: [{ id: "strong", retention: "Strong" }] });
      if (path.includes("projects")) return response({ projects: [] }); if (path.includes("targets")) return response({ targets: [target] }); return response({ profiles: [] });
    }));
    const engineConfiguration = { schemaVersion: 1, cases: [{ id: "adapter-case", label: "Adapter exact case" }] };
    render(<ScanStudio initialAdapterDraft={{ target, engineId: "business-invariant", engineConfiguration, authentication: { mode: "public" }, binding: { profileId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", versionId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", adapterDigest: "d".repeat(64) }, limits: { maxRequests: 73, cleanupReservedRequests: 11, rateLimitPerSecond: 1, concurrency: 1, evidenceLevel: "strong" } }} onLaunched={() => undefined} />);
    expect(await screen.findByRole("heading", { name: "Business invariant testing" })).toBeTruthy();
    expect(await screen.findByDisplayValue("Adapter exact case")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Preview complete plan" }));
    await waitFor(() => expect(previewRequest).toBeTruthy());
    expect(previewRequest).toMatchObject({ targetId: target.id, profile: "full", maxRequests: 73, cleanupReservedRequests: 11, providerAdapterBinding: { adapterDigest: "d".repeat(64) }, businessInvariant: engineConfiguration, studio: { authentication: { mode: "public" }, scope: { rateLimitPerSecond: 1, concurrency: 1 } } });
  });
});

function stubApi() { vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => { const path = String(input); const body = path.includes("capabilities") ? { profiles: [{ name: "quick", displayName: "Quick", description: "Fast safe feedback", modules: ["baseline"], limits: { maxRequests: 80 }, browserUse: "off", authComparisonDepth: "none", proofMode: false, reportFocus: [] }], modules: [{ id: "baseline", displayName: "Baseline", description: "Baseline response", phase: "discovery", capabilities: ["baseline"], requiresAuthentication: "none", dependencies: [], cost: "low", supportedSettings: [] }], controlledWorkflows: [], evidenceLevels: [{ id: "minimal", retention: "Metadata only" }] } : path.includes("projects") ? { projects: [] } : path.includes("targets") ? { targets: [] } : { profiles: [] }; return { ok: true, status: 200, json: async () => body } as Response; })); }

function response(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as Response;
}
