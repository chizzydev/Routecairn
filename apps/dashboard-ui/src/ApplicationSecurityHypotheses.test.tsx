// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { ApplicationSecurityHypotheses } from "./ApplicationSecurityHypotheses";
import { apiGet, apiMutation } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("does not grant read-only users proposal or proof authority", () => {
  render(<ApplicationSecurityHypotheses mapId="map" canExecute={false} onMatrix={() => {}} />);
  expect((screen.getByRole("button", { name: "Generate grounded hypotheses" }) as HTMLButtonElement).disabled).toBe(
    true
  );
  expect(apiMutation).not.toHaveBeenCalled();
});
it("displays UNKNOWN controls and provides no eligible proof from abstention", async () => {
  vi.mocked(apiGet).mockResolvedValue([]);
  vi.mocked(apiMutation).mockResolvedValue({
    proposalId: "proposal",
    digest: "a".repeat(64),
    algorithm: "v1",
    source: { targetId: "target", mapRevisionId: "map", sourceScanId: null, sourceHash: null },
    candidates: [
      {
        candidateId: "candidate",
        routeId: "record",
        url: "http://127.0.0.1/record/42",
        group: "/record/:id",
        eligibility: "ABSTAIN",
        priority: 0,
        priorityBasis: "MISSING_CONTROL",
        missingControls: ["SOURCE_NOT_COMPLETE"],
        irCaseIds: [],
        vulnerabilityConclusion: "NOT_ASSESSED",
        evidence: [],
        counterevidence: []
      }
    ]
  });
  render(<ApplicationSecurityHypotheses mapId="map" canExecute onMatrix={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Generate grounded hypotheses" }));
  await screen.findByText(/ABSTAIN/);
  fireEvent.click(screen.getByRole("button", { name: "Inspect hypothesis record" }));
  expect(
    (screen.getByRole("button", { name: "Record policy and review bounded matrix" }) as HTMLButtonElement).disabled
  ).toBe(true);
  expect(screen.getByText(/Policy and ownership are unknown/)).toBeTruthy();
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
