// @vitest-environment jsdom
import React from "react";
import { afterEach, describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { RecoveryCenter } from "./RecoveryCenter";
import type { RecoveryCenterSnapshot } from "../../../src/dashboard/contracts/RecoveryCenterContracts";
const api = vi.hoisted(() => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
vi.mock("./api", () => api);
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const snapshot = (review = true): RecoveryCenterSnapshot => ({
  schemaVersion: 1,
  organizationId: "fixture",
  automaticReplay: false,
  dispatchState: "QUARANTINED",
  issues: [
    {
      kind: "CUSTODY",
      subjectId: "fixture-worker",
      state: "UNKNOWN_RETAINED",
      snapshotDigest: "a".repeat(64),
      title: "Worker custody needs review",
      explanation: "Native descendant custody is not proven.",
      evidence: [{ label: "Job", value: "fixture-job" }],
      blockedActions: ["Dispatch remains blocked."],
      humanReviewRequired: true,
      actions: { review, recompute: false, cleanup: false }
    }
  ],
  inventoryWarnings: [],
  hasMore: false,
  page: 1,
  pageSize: 25
});
describe("operator uncertainty UI authority and failure states", () => {
  it("never offers review or recovery to a read-only operator", async () => {
    api.apiGet.mockResolvedValue(snapshot(false));
    render(<RecoveryCenter />);
    await screen.findByText("Worker custody needs review");
    expect(screen.queryByRole("button", { name: "Acknowledge review" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Open authorized cleanup recovery" })).toBeNull();
    expect(api.apiMutation).not.toHaveBeenCalled();
  });
  it("binds confirmation to evidence and retains blockers after review", async () => {
    api.apiGet.mockResolvedValue(snapshot());
    api.apiMutation.mockResolvedValue({ uncertaintyResolved: false });
    render(<RecoveryCenter />);
    const b = await screen.findByRole("button", { name: "Acknowledge review" });
    expect((b as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(b);
    await screen.findByText("Review recorded. Uncertainty and safety blockers remain in force.");
    expect(api.apiMutation).toHaveBeenCalledWith(
      "/api/recovery-center/reviews",
      "POST",
      expect.objectContaining({ subjectId: "fixture-worker", snapshotDigest: "a".repeat(64), decision: "ACKNOWLEDGED" })
    );
    await screen.findByText("Dispatch remains blocked.");
  });
  it("removes stale actions after a rejected or unacknowledged mutation", async () => {
    api.apiGet.mockResolvedValue(snapshot());
    api.apiMutation.mockRejectedValue(Error("409"));
    render(<RecoveryCenter />);
    const b = await screen.findByRole("button", { name: "Acknowledge review" });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(b);
    await screen.findByRole("alert");
    expect(screen.queryByRole("button", { name: "Acknowledge review" })).toBeNull();
  });
  it("treats unavailable inventory as unknown, not a clean state", async () => {
    api.apiGet.mockRejectedValue(Error("offline"));
    render(<RecoveryCenter />);
    await screen.findByRole("alert");
    expect(screen.queryByText(/No items/)).toBeNull();
    expect(api.apiMutation).not.toHaveBeenCalled();
  });
  it("resets consent when source digest changes", async () => {
    api.apiGet.mockResolvedValue(snapshot());
    render(<RecoveryCenter />);
    const b = await screen.findByRole("button", { name: "Acknowledge review" });
    fireEvent.click(screen.getByRole("checkbox"));
    expect((b as HTMLButtonElement).disabled).toBe(false);
    const next = snapshot();
    next.issues[0]!.snapshotDigest = "b".repeat(64);
    api.apiGet.mockResolvedValue(next);
    fireEvent.click(screen.getByRole("button", { name: "Refresh evidence" }));
    await screen.findByText("b".repeat(64));
    expect((screen.getByRole("button", { name: "Acknowledge review" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("requires a fresh exact-target profile and explicit consent for controlled cleanup", async () => {
    const view = snapshot(),
      approval = "approval:00000000-0000-4000-8000-000000000001",
      target = "00000000-0000-4000-8000-000000000002",
      profile = "00000000-0000-4000-8000-000000000003";
    view.issues[0] = {
      ...view.issues[0]!,
      kind: "CLEANUP",
      subjectId: approval,
      title: "Controlled cleanup",
      evidence: [{ label: "Target", value: target }],
      actions: { review: false, recompute: false, cleanup: true }
    };
    api.apiGet.mockImplementation(async (path: string) =>
      path === "/api/credential-profiles"
        ? {
            profiles: [
              { id: profile, name: "Fresh owner", targetId: target, enabled: true },
              { id: "wrong", name: "Wrong target", targetId: "another", enabled: true },
              { id: "disabled", name: "Disabled profile", targetId: target, enabled: false }
            ]
          }
        : view
    );
    api.apiMutation.mockResolvedValue({ status: "REQUESTED" });
    render(<RecoveryCenter />);
    fireEvent.click(await screen.findByRole("button", { name: "Open authorized cleanup recovery" }));
    const select = await screen.findByRole("combobox", { name: "Fresh target-bound credential" });
    await screen.findByRole("option", { name: "Fresh owner" });
    expect(screen.queryByRole("option", { name: "Wrong target" })).toBeNull();
    expect(screen.queryByRole("option", { name: "Disabled profile" })).toBeNull();
    const button = screen.getByRole("button", { name: "Request bound cleanup" });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(select, { target: { value: profile } });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(button);
    await screen.findByText(
      "Bound cleanup requested. Monitor the approval and recovery evidence; restoration is not yet verified."
    );
    expect(api.apiMutation).toHaveBeenCalledWith("/api/recovery-center/controlled-cleanup", "POST", {
      subjectId: approval,
      snapshotDigest: "a".repeat(64),
      credentialProfileId: profile,
      confirmation: "I_AUTHORIZE_BOUND_CONTROLLED_CLEANUP_ONLY"
    });
  });
});
