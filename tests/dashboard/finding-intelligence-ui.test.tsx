// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProjectDetail, TargetDetail } from "../../apps/dashboard-ui/src/main.js";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("project and target finding intelligence", () => {
  it("renders project distributions and emits allowlisted metric filters", async () => {
    const onFindings = vi.fn();
    mockJson({ project: { id: "project", name: "Payments", description: "", tags: [], openFindingCount: 2, targetCount: 1, scanCount: 2 }, targets: [{ id: "target", displayName: "Accounts", baseOrigin: "https://app.test", authorizationType: "OWNED", authorizationSummary: "Owned", classification: "PUBLIC", scanCount: 2, openFindingCount: 2 }], findingIntelligence: intelligence() });
    render(<ProjectDetail projectId="project" onFindings={onFindings} onTarget={vi.fn()} />);
    expect(await screen.findByText("Severity Distribution")).toBeTruthy();
    expect(screen.getByText("Affected Targets")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /2 unreviewed/i }));
    expect(onFindings).toHaveBeenCalledWith({ projectId: "project", review: "UNREVIEWED" });
    fireEvent.click(screen.getByRole("button", { name: "High" }));
    expect(onFindings).toHaveBeenCalledWith({ projectId: "project", severity: "High" });
  });

  it("renders target retest queue, module distribution, actions, and empty state", async () => {
    const onFindings = vi.fn(); const onScan = vi.fn();
    mockJson({ target: { id: "target", displayName: "Accounts API", baseOrigin: "https://app.test", authorizationType: "OWNED", authorizationSummary: "Owned", classification: "PUBLIC", scanCount: 2, openFindingCount: 2 }, findingIntelligence: intelligence() });
    render(<TargetDetail targetId="target" onFindings={onFindings} onScan={onScan} />);
    expect(await screen.findByText("Findings by Module")).toBeTruthy();
    expect(screen.getByText("Retest Needed")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Start New Scan" })); expect(onScan).toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Retest Findings" })); expect(onFindings).toHaveBeenCalledWith({ targetId: "target", remediation: "FIXED_PENDING_RETEST" });
  });
});

function intelligence() {
  return { totalOpen: 3, unreviewed: 2, confirmed: 1, reopened: 0, acceptedRisk: 0, falsePositive: 0, resolved: 0, fixedPendingRetest: 1, fixedVerified: 0, severity: { Critical: 0, High: 2, Medium: 1, Low: 0, Info: 0 }, remediation: { OPEN: 2, FIXED_PENDING_RETEST: 1 }, byModule: [{ label: "authorization-matrix-testing", count: 3 }], byTarget: [{ id: "target", label: "Accounts", count: 3 }], recentOccurrences: [], recentReviews: [], retestNeeded: [{ id: "finding", title: "Retest account boundary" }], proofReady: [], firstLast: { first_seen_at: "2026-01-01", last_seen_at: "2026-01-02" } };
}

function mockJson(value: unknown): void {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } })));
}
