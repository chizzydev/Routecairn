// @vitest-environment jsdom
import React from "react";
import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { CleanupAttemptHistory } from "./CleanupAttemptHistory";
const mocks = vi.hoisted(() => ({ apiGet: vi.fn() }));
vi.mock("./api", () => mocks);
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
describe("immutable cleanup attempt operator history", () => {
  it("shows distinct result receipt and independent restoration without offering replay", async () => {
    mocks.apiGet.mockResolvedValue({
      attemptId: "fixture",
      phase: "RESTORATION_VERIFIED",
      jobId: "job",
      immutableBindingDigest: "a".repeat(64),
      automaticReplay: false,
      authorizationReusable: false,
      history: [
        { sequence: 1, kind: "REQUESTED", at: "2026-01-01", hash: "a".repeat(64), previousHash: "b".repeat(64) },
        { sequence: 2, kind: "RESULT_RECEIVED", at: "2026-01-01", hash: "b".repeat(64), previousHash: "a".repeat(64) },
        {
          sequence: 3,
          kind: "RESTORATION_VERIFIED",
          at: "2026-01-01",
          hash: "c".repeat(64),
          previousHash: "b".repeat(64)
        }
      ]
    });
    render(<CleanupAttemptHistory attemptId="fixture" snapshotDigest={"a".repeat(64)} />);
    fireEvent.click(screen.getByRole("button", { name: "Inspect immutable attempt history" }));
    await screen.findByText("2. RESULT_RECEIVED");
    expect(screen.getByText("3. RESTORATION_VERIFIED")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /retry|replay|clear/i })).toBeNull();
  });
  it("clears stale outcome evidence when refreshed history is unavailable", async () => {
    mocks.apiGet.mockRejectedValue(Error("Integrity failure"));
    render(<CleanupAttemptHistory attemptId="fixture" snapshotDigest={"a".repeat(64)} />);
    fireEvent.click(screen.getByRole("button"));
    await screen.findByRole("alert");
    expect(screen.queryByText(/Current attempt:/)).toBeNull();
  });
  it("refuses a history response that grants authorization reuse", async () => {
    mocks.apiGet.mockResolvedValue({
      attemptId: "fixture",
      phase: "PASSED",
      automaticReplay: false,
      authorizationReusable: true,
      history: []
    });
    render(<CleanupAttemptHistory attemptId="fixture" snapshotDigest={"a".repeat(64)} />);
    fireEvent.click(screen.getByRole("button"));
    await screen.findByRole("alert");
    expect(screen.queryByText(/PASSED/)).toBeNull();
  });
});
