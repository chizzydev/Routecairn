// @vitest-environment jsdom
import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdaptiveSecurityWorkspace } from "./AdaptiveSecurityWorkspace";

afterEach(() => vi.unstubAllGlobals());

describe("AdaptiveSecurityWorkspace read-only automation", () => {
  it("opens a materialized evidence-bound case in Scan Studio without an approval step", async () => {
    const target = { id: "11111111-1111-4111-8111-111111111111", displayName: "Fixture", baseOrigin: "https://app.test", authorizationType: "OWNED", authorizationSummary: "Owned", classification: "PRIVATE", scanCount: 1, openFindingCount: 0, tags: [], approvedScope: {}, defaultAuthTemplate: {}, productionEnabled: false, archived: false, rowVersion: 1 };
    const binding = { recommendationId: "22222222-2222-4222-8222-222222222222", sourceFingerprint: "a".repeat(64), executionFingerprint: "b".repeat(64), compilerVersion: 1 as const };
    const configuration = { schemaVersion: 1, actors: [{ id: "anonymous", authSlot: "anonymous" }], routes: [], checks: [] };
    const state = { targetId: target.id, policy: { requiredLanes: ["PUBLIC_BASELINE"], requireEvidenceForNotApplicable: true, detectRemovedSurfaces: true }, coverage: { complete: false, required: 1, gaps: 1, lanes: [{ kind: "PUBLIC_BASELINE", state: "MISSING" }] }, snapshots: [], drifts: [], recommendations: [{ id: binding.recommendationId, category: "API_READ_ONLY_REGRESSION", engineId: "api-graphql-authorization", laneKind: "API_GRAPHQL_AUTHORIZATION", status: "PROPOSED", mutationHypothesis: false, operatorApprovalRequired: false, sourceFingerprint: binding.sourceFingerprint, draft: { executable: true, automation: { state: "READY_READ_ONLY" } }, requiredBindings: [], executionCandidates: [] }] };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      const body = path === "/api/targets" ? { targets: [target] }
        : path.startsWith("/api/scans") ? { scans: [] }
        : path.endsWith("/materialize") ? { materialized: { targetId: target.id, engineId: "api-graphql-authorization", engineConfiguration: configuration, binding, limits: { maxRequests: 10, cleanupReservedRequests: 0, evidenceLevel: "strong" }, automation: { state: "READY_READ_ONLY" } } }
        : { adaptiveSecurity: state };
      return { ok: true, status: 200, json: async () => body } as Response;
    }));
    const open = vi.fn();
    render(<AdaptiveSecurityWorkspace onOpenBuilder={open} canApprove={false} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Open compiled case" }));
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ target, engineId: "api-graphql-authorization", engineConfiguration: configuration, binding, limits: { maxRequests: 10, cleanupReservedRequests: 0, evidenceLevel: "strong" } }));
    expect(screen.queryByRole("button", { name: "Approve proposal" })).toBeNull();
  });
});
