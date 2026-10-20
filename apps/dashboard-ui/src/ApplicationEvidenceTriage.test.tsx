// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, act } from "@testing-library/react";
import { ApplicationEvidenceTriage } from "./ApplicationEvidenceTriage";
import { apiGet, apiMutation } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const evidence = {
  digest: "a".repeat(64),
  nextAction: "REVIEW_POLICY_THEN_SEPARATELY_AUTHORIZE_PROOF",
  freshness: "CURRENT",
  source: { sourceScanId: "owned-scan", sourceHash: "hash" },
  policyAuthority: "OWNER_DECLARATION",
  questions: [],
  proofs: [],
  comparisons: [],
  notes: []
};
it("shows explicit untested and missing remediation evidence without making any target or mutation request", async () => {
  vi.mocked(apiGet).mockResolvedValue(evidence);
  render(<ApplicationEvidenceTriage proposalId="one" canExecute={false} />);
  expect(apiGet).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Refresh linked assessment evidence" }));
  await screen.findByText(/This assessment is UNTESTED/);
  expect(screen.getByText(/Resolution is NOT TESTED/)).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: "Record evidence-bound triage note" }) as HTMLButtonElement).disabled
  ).toBe(true);
  expect(apiMutation).not.toHaveBeenCalled();
});
it("discards stale evidence after the selected proposal changes and permits a fresh independent load", async () => {
  let old!: (v: unknown) => void;
  vi.mocked(apiGet)
    .mockImplementationOnce(
      () =>
        new Promise((r) => {
          old = r;
        })
    )
    .mockResolvedValue({ ...evidence, source: { ...evidence.source, sourceScanId: "fresh-scan" } });
  const view = render(<ApplicationEvidenceTriage proposalId="old" canExecute />);
  fireEvent.click(screen.getByRole("button", { name: "Refresh linked assessment evidence" }));
  view.rerender(<ApplicationEvidenceTriage proposalId="new" canExecute />);
  await act(async () => {
    old({ ...evidence, source: { ...evidence.source, sourceScanId: "old-scan" } });
  });
  expect(screen.queryByText(/old-scan/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Refresh linked assessment evidence" }));
  await screen.findByText(/fresh-scan/);
  expect(apiGet).toHaveBeenLastCalledWith("/api/authorization-workbench/mapping/hypotheses/new/triage");
});
it("retains uncertain note acknowledgement without automatic retry or scanner outcome changes", async () => {
  vi.mocked(apiGet).mockResolvedValue(evidence);
  vi.mocked(apiMutation).mockRejectedValue(Error("response lost"));
  render(<ApplicationEvidenceTriage proposalId="one" canExecute />);
  fireEvent.click(screen.getByRole("button", { name: "Refresh linked assessment evidence" }));
  await screen.findByText(/This assessment is UNTESTED/);
  fireEvent.change(screen.getByLabelText("Triage rationale"), {
    target: { value: "Owner context requires explicit review of the exact source evidence." }
  });
  fireEvent.click(screen.getByLabelText(/I reviewed this exact evidence/));
  fireEvent.click(screen.getByRole("button", { name: "Record evidence-bound triage note" }));
  await screen.findByRole("alert");
  expect(screen.getByRole("alert").textContent).toContain("do not infer rollback");
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
