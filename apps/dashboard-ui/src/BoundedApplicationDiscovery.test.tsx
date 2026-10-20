// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import { BoundedApplicationDiscovery } from "./BoundedApplicationDiscovery";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const proposal = {
  proposalId: "proposal",
  digest: "a".repeat(64),
  source: { sourceHash: "b".repeat(64) },
  round: 1,
  requestCeiling: 12,
  coverage: { observedRoutes: 1, complete: false },
  candidates: [
    {
      candidateId: "c".repeat(64),
      path: "/hub/record/17",
      url: "http://127.0.0.1:9000/hub/record/17",
      provenance: [{}]
    }
  ],
  excluded: [{ reason: "ORIGIN_MISMATCH", count: 1 }],
  missingControls: ["UNKNOWN_SOURCE_CONTROL"]
};
it("requires scope review, displays incomplete evidence and returns only selected source-bound routes without execution", async () => {
  vi.mocked(apiMutation).mockResolvedValue(proposal);
  const onSelect = vi.fn();
  render(<BoundedApplicationDiscovery mapRevisionId="map" canExecute onSelect={onSelect} />);
  const button = screen.getByRole("button", { name: "Review discovery suggestions" });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByLabelText(/I reviewed this local scope/));
  fireEvent.click(button);
  await screen.findByText(/1 scoped suggestions/);
  expect(apiMutation).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByText("Exclusions and missing controls"));
  expect(screen.getByText("UNKNOWN_SOURCE_CONTROL")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Discovered object identity field"), { target: { value: "asset.ref" } });
  fireEvent.click(screen.getByLabelText("Select discovered /hub/record/17"));
  fireEvent.click(screen.getByRole("button", { name: "Use selected routes in mapping review" }));
  expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ proposalId: "proposal", digest: proposal.digest }), [
    expect.objectContaining({ url: proposal.candidates[0]!.url, identityPath: "asset.ref", method: "GET" })
  ]);
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
it("does not expose a discovery action to read-only operators", () => {
  render(<BoundedApplicationDiscovery mapRevisionId="map" canExecute={false} onSelect={vi.fn()} />);
  fireEvent.click(screen.getByLabelText(/I reviewed this local scope/));
  expect((screen.getByRole("button", { name: "Review discovery suggestions" }) as HTMLButtonElement).disabled).toBe(
    true
  );
  expect(apiMutation).not.toHaveBeenCalled();
});
it("renders genuine API failure without dispatch or a fabricated successful result", async () => {
  vi.mocked(apiMutation).mockRejectedValue(Error("WORKBENCH_DISCOVERY_SCOPE_REQUIRED"));
  render(<BoundedApplicationDiscovery mapRevisionId="map" canExecute onSelect={vi.fn()} />);
  fireEvent.click(screen.getByLabelText(/I reviewed this local scope/));
  fireEvent.click(screen.getByRole("button", { name: "Review discovery suggestions" }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("SCOPE_REQUIRED"));
  expect(screen.queryByText(/scoped suggestions/)).toBeNull();
});
