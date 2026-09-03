// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AssistedReviewPanel } from "../../apps/dashboard-ui/src/AssistedReviewPanel";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

function response(state = "BLOCKED") {
  return { scanId: "scan", gate: { state, blockers: state === "BLOCKED" ? ["HUMAN_REVIEW_PENDING", "CLEANUP_UNRESOLVED"] : [] }, report: { title: "Explicit security review", coverageMatrix: { AUTHORIZATION: { selected: true, required: true, outcomes: { PROVEN: 1, INCONCLUSIVE: 2, NOT_ASSESSED: 3, BLOCKED: 4 }, cleanupFailures: 1 } }, timeline: [], remediationRoadmap: [] }, queue: [], publications: [] };
}

describe("assisted review dashboard", () => {
  it("shows pre-handover critical coverage and fix regression readiness", async () => {
    const value = response();
    const preHandover = { revision: "release-123", environment: "STAGING", objectCount: 2, invariantCount: 1, raceCount: 1, sequence: ["business-invariant", "controlled-race"], criticalCoverage: [{ passed: true }, { passed: false }], regressions: [{ passed: false }] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ ...value, report: { ...value.report, targetMode: "PRE_HANDOVER_ASSAULT", preHandover } }), { status: 200 })));
    render(<AssistedReviewPanel scanId="scan" onReviewFindings={() => {}} />);
    await screen.findByText("Pre-Handover Readiness");
    expect(screen.getByText(/1\/2 critical cases passed; 0\/1 regressions verified/)).toBeTruthy();
    expect(screen.getByText(/release-123/)).toBeTruthy();
  });
  it("shows separate coverage states, keeps publish disabled, and opens the human-review lane", async () => {
    const onReviewFindings = vi.fn();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(response()), { status: 200, headers: { "content-type": "application/json" } })));
    render(<AssistedReviewPanel scanId="scan" onReviewFindings={onReviewFindings} />);
    await screen.findByText("Explicit security review");
    expect((screen.getByRole("button", { name: "Publish Human-reviewed Customer Report" }) as HTMLButtonElement).disabled).toBe(true);
    for (const name of ["Proven", "Inconclusive", "Not assessed", "Blocked", "Cleanup unresolved"]) expect(screen.getByRole("columnheader", { name })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Review Findings and Evidence" }));
    expect(onReviewFindings).toHaveBeenCalledOnce();
  });

  it("surfaces a changed server gate instead of pretending publication succeeded", async () => {
    vi.stubGlobal("fetch", vi.fn(async (_url: string, options?: RequestInit) => new Response(JSON.stringify(options?.method === "POST" ? { error: "Review changed; refresh required." } : response("READY")), { status: options?.method === "POST" ? 409 : 200, headers: { "content-type": "application/json" } })));
    render(<AssistedReviewPanel scanId="scan" onReviewFindings={() => {}} />);
    await screen.findByText("Explicit security review");
    fireEvent.click(screen.getByRole("button", { name: "Publish Human-reviewed Customer Report" }));
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain("Review changed"));
    expect(screen.queryByRole("link", { name: /Customer report/ })).toBeNull();
  });
});
