// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@testing-library/react";
import { ApplicationSecurityHypotheses } from "./ApplicationSecurityHypotheses";
import { apiGet, apiMutation } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("does not reinterpret whitespace as a numeric policy in single-hypothesis review", async () => {
  vi.mocked(apiGet).mockResolvedValue([]);
  vi.mocked(apiMutation).mockResolvedValue({
    proposalId: "p",
    digest: "a".repeat(64),
    source: { mapRevisionId: "m" },
    candidates: [
      {
        candidateId: "c",
        routeId: "record",
        url: "http://127.0.0.1/record/42",
        group: "record",
        kind: "OBJECT",
        identityPath: "id",
        eligibility: "EVIDENCE_READY_FOR_POLICY_REVIEW",
        priority: 1,
        missingControls: [],
        irCaseIds: [],
        nativeCheckIds: [],
        counterevidence: [],
        evidence: [{ actorId: "primary", markers: [{ path: "id", scalarType: "number" }] }]
      }
    ]
  });
  render(<ApplicationSecurityHypotheses mapId="m" canExecute onMatrix={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Generate grounded hypotheses" }));
  await screen.findByRole("button", { name: "Inspect hypothesis record" });
  fireEvent.click(screen.getByRole("button", { name: "Inspect hypothesis record" }));
  fireEvent.change(screen.getByLabelText("Expected hypothesis object marker"), { target: { value: "   " } });
  fireEvent.change(screen.getByLabelText("Hypothesis policy rationale"), {
    target: { value: "Explicit owner review of this resource" }
  });
  for (const a of ["account-a", "account-b", "anonymous"])
    fireEvent.change(screen.getByLabelText("Hypothesis policy " + a), { target: { value: "DENY" } });
  fireEvent.click(screen.getByRole("checkbox", { name: /I explicitly confirm ownership/ }));
  fireEvent.click(screen.getByRole("checkbox", { name: /I declare the expected policy/ }));
  vi.mocked(apiMutation).mockClear();
  fireEvent.click(screen.getByRole("button", { name: "Record policy and review bounded matrix" }));
  await waitFor(() => expect(apiMutation).not.toHaveBeenCalled());
  expect((await screen.findByRole("alert")).textContent).toContain("explicit finite decimal");
});
