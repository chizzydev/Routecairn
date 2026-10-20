// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@testing-library/react";
import { AssessmentJourney } from "./AssessmentJourney";
import { apiGet } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("inspects only after an explicit action and rejects late readiness from another actor context", async () => {
  let resolve!: (value: unknown) => void;
  vi.mocked(apiGet).mockReturnValue(
    new Promise((r) => {
      resolve = r;
    })
  );
  const credentials = { primary: "p", account_a: "a", account_b: "b" },
    v = render(<AssessmentJourney targetId="first" credentials={credentials} />);
  expect(apiGet).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Inspect assessment readiness" }));
  expect(apiGet).toHaveBeenCalledTimes(1);
  v.rerender(<AssessmentJourney targetId="second" credentials={credentials} />);
  resolve({
    steps: [{ id: "scope", status: "OLD_CONTEXT", next: "wrong" }],
    observation: { nativeActorRoutePairs: 4, expectedPairs: 4, missing: [] },
    ownerInputContract: { scope: "old" }
  });
  await waitFor(() => expect(screen.queryByText(/OLD_CONTEXT/)).toBeNull());
});
it("shows actionable declaration, native coverage and independent-input limits without creating authority", async () => {
  vi.mocked(apiGet).mockResolvedValue({
    steps: [{ id: "actors", status: "ACTION_REQUIRED", next: "Save three explicit actor contracts" }],
    observation: { nativeActorRoutePairs: 0, expectedPairs: 12, missing: ["FRESH_NATIVE_IDENTITY_REQUIRED"] },
    ownerInputContract: { scope: "Only explicit loopback GET scope" },
    independentEvaluation: "BLOCKED_PENDING_SEPARATE_EVALUATOR"
  });
  render(<AssessmentJourney targetId="t" credentials={{ primary: "", account_a: "", account_b: "" }} />);
  fireEvent.click(screen.getByRole("button", { name: "Inspect assessment readiness" }));
  await screen.findByText("Save three explicit actor contracts");
  expect(screen.getByRole("status").textContent).toContain("0/12");
  expect(screen.getByText(/Independent evaluation:/).textContent).toContain("BLOCKED_PENDING_SEPARATE_EVALUATOR");
});
