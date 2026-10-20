// @vitest-environment jsdom
import React from "react";
import { it, expect, vi } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";
import { ObservedStateRegression, ObservedStateAttention, ObservedStateAssessment } from "./ObservedStateRegression";
import { apiGet } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
it("keeps unconfigured observations untested and withholds owner review controls", async () => {
  vi.mocked(apiGet).mockImplementation(async (path) =>
    path.endsWith("/policies")
      ? { policies: [] }
      : path.endsWith("/attention")
        ? { alerts: [], policiesConfigured: 0 }
        : { revisions: [] }
  );
  try {
    render(<ObservedStateRegression canManage={false} />);
    fireEvent.click(screen.getByText("Observed-State Regression & Continuous Assurance"));
    await waitFor(() => expect(screen.getByText(/UNTESTED — no reviewed/)).toBeTruthy());
    expect(screen.getByRole("button", { name: "Preview observed-state policy" }).closest("fieldset")!.disabled).toBe(
      true
    );
    expect(screen.getByText(/State-changing execution remains HOLD/)).toBeTruthy();
  } finally {
    cleanup();
  }
});
it("shows permission or read errors as unavailable rather than empty healthy alerts", async () => {
  vi.mocked(apiGet).mockRejectedValue(new Error("403"));
  try {
    render(<ObservedStateAttention eager />);
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain("No healthy result is inferred"));
    expect(screen.queryByText(/No pending observed-state alerts/)).toBeNull();
  } finally {
    cleanup();
  }
});
it("labels denied observations and inconclusive revisions without asserting transition authorization", () => {
  const value = {
    id: "assessment",
    policyId: "policy",
    policyDigest: "digest",
    outcome: "INCONCLUSIVE",
    reasons: ["REVISION_CHANGED_REVIEW_REQUIRED"],
    baselineSource: { sourceScanId: "before" },
    currentSource: null,
    comparisonId: null,
    cells: [
      {
        checkId: "route-observe-a",
        actorId: "account-a",
        routeId: "route",
        expectedDecision: "DENY",
        observedDecision: "DENIED",
        outcome: "INCONCLUSIVE",
        stateAssessment: "NOT_OBSERVED_DUE_TO_DENIAL",
        reasons: ["REVISION_CHANGED_REVIEW_REQUIRED"],
        expectedMarkers: [],
        observedMarkers: []
      }
    ]
  } as unknown as Parameters<typeof ObservedStateAssessment>[0]["value"];
  try {
    render(<ObservedStateAssessment value={value} />);
    expect(screen.getByRole("heading").textContent).toContain("INCONCLUSIVE");
    expect(screen.getByText(/State-change authorization: NOT_TESTED/)).toBeTruthy();
    expect(screen.getByText(/NOT_OBSERVED_DUE_TO_DENIAL/)).toBeTruthy();
    expect(screen.getByText(/later scan: UNTESTED/)).toBeTruthy();
  } finally {
    cleanup();
  }
});

it("treats a malformed attention payload as unavailable without crashing the operator workspace", async () => {
  vi.mocked(apiGet).mockResolvedValue({ alerts: null, policiesConfigured: 2 });
  try {
    render(<ObservedStateAttention {...{ eager: true }} />);
    await waitFor(() => expect(screen.getByText(/Observed-state evidence unavailable/)).toBeTruthy());
    expect(screen.queryByText(/No pending observed-state alerts/)).toBeNull();
  } finally {
    cleanup();
  }
});

it("withholds policy approval controls when the server denies review even though scan execution is allowed", async () => {
  vi.mocked(apiGet).mockImplementation(async (path) =>
    path.endsWith("/policies")
      ? { policies: [], canReviewPolicies: false }
      : path.endsWith("/attention")
        ? { alerts: [], policiesConfigured: 0 }
        : { revisions: [] }
  );
  try {
    render(<ObservedStateRegression canManage={true} />);
    (await import("@testing-library/react")).fireEvent.click(
      screen.getByText("Observed-State Regression & Continuous Assurance")
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Preview observed-state policy" }).closest("fieldset")!.disabled).toBe(
        true
      )
    );
  } finally {
    cleanup();
  }
});
