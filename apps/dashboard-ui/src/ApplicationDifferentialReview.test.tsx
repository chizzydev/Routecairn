// @vitest-environment jsdom
import React from "react";
import { it, expect, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { ApplicationDifferentialReview } from "./ApplicationDifferentialReview";
import type { ApplicationHypothesisService } from "../../../src/dashboard/execution/ApplicationHypothesisService";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
const base = {
  proposalId: "proposal",
  source: { mapRevisionId: "map" },
  candidates: [
    { routeId: "source", candidateId: "a", kind: "OBJECT", evidence: [], missingControls: [] },
    { routeId: "operation", candidateId: "b", kind: "FUNCTION", evidence: [], missingControls: [] }
  ]
} as unknown as ReturnType<ApplicationHypothesisService["generate"]>;
it("does not grant proposal or proof authority to read-only users", () => {
  try {
    render(
      <ApplicationDifferentialReview proposal={base} canExecute={false} onProposal={vi.fn()} onMatrix={vi.fn()} />
    );
    expect(screen.getByRole("button", { name: "Draft reviewed differential workflow" }).hasAttribute("disabled")).toBe(
      true
    );
    expect(screen.getByText(/Mutation execution remains HOLD/)).toBeTruthy();
    expect(screen.queryByText("Authorize and run selected matrix")).toBeNull();
  } finally {
    cleanup();
  }
});
it("keeps missing-state workflows visibly abstained despite checked human confirmation", () => {
  try {
    const proposal = {
      ...base,
      flow: {
        flowId: "flow",
        version: "v1",
        steps: [],
        eligibility: "ABSTAIN",
        missingControls: ["TYPED_STATE_CONTROL_REQUIRED"],
        maximumSharedRequests: 40,
        maximumModuleRequests: 8
      }
    } as unknown as typeof base;
    render(
      <ApplicationDifferentialReview proposal={proposal} canExecute={true} onProposal={vi.fn()} onMatrix={vi.fn()} />
    );
    fireEvent.change(screen.getByLabelText("Flow relationship explanation"), {
      target: { value: "Owner-declared fixture relationship" }
    });
    for (const input of screen.getAllByRole("checkbox")) fireEvent.click(input);
    expect(
      screen.getByRole("button", { name: "Review flow into existing proof matrix" }).hasAttribute("disabled")
    ).toBe(true);
    expect(screen.getByText("TYPED_STATE_CONTROL_REQUIRED")).toBeTruthy();
  } finally {
    cleanup();
  }
});
