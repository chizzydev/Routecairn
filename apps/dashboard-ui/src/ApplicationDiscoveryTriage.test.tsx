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
const p = {
  proposalId: "p",
  digest: "a".repeat(64),
  expiresAt: "2000-01-01T00:00:00Z",
  source: { sourceHash: "b".repeat(64), contextDigest: "c".repeat(64), sourceScanId: "native-scan" },
  round: 1,
  requestCeiling: 12,
  coverage: { observedRoutes: 1, complete: false },
  candidates: [
    {
      candidateId: "d".repeat(64),
      path: "/desk/tickets/52",
      url: "http://127.0.0.1:9000/desk/tickets/52",
      provenance: [
        {
          routeId: "seed",
          actorId: "account-b",
          checkId: "seed-observe-account-b",
          responseFingerprint: "e".repeat(64),
          evidenceFingerprint: "f".repeat(64)
        }
      ]
    }
  ],
  excluded: [{ reason: "HTML_BASE_AMBIGUITY", count: 1 }],
  missingControls: ["INCOMPLETE_SOURCE"]
};
it("shows stale source-bound reviews and expected I/O while refusing selection without new review", async () => {
  vi.mocked(apiMutation).mockResolvedValue(p);
  render(<BoundedApplicationDiscovery mapRevisionId="map" canExecute onSelect={vi.fn()} />);
  fireEvent.click(screen.getByLabelText(/I reviewed this local scope/));
  fireEvent.click(screen.getByRole("button", { name: "Review discovery suggestions" }));
  await screen.findByText(/STALE REVIEW/);
  fireEvent.click(screen.getByLabelText("Select discovered /desk/tickets/52"));
  await waitFor(() =>
    expect(
      (screen.getByRole("button", { name: "Use selected routes in mapping review" }) as HTMLButtonElement).disabled
    ).toBe(true)
  );
  expect(screen.getByText(/Selected observation cost: at most 8/)).toBeTruthy();
  expect(screen.getByText("actor/credential binding SHA256", { exact: false })).toBeTruthy();
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
it("invalidates old candidates on source revision change without fetching or following links", async () => {
  vi.mocked(apiMutation).mockResolvedValue({ ...p, expiresAt: "2099-01-01T00:00:00Z" });
  const v = render(<BoundedApplicationDiscovery mapRevisionId="map1" canExecute onSelect={vi.fn()} />);
  fireEvent.click(screen.getByLabelText(/I reviewed this local scope/));
  fireEvent.click(screen.getByRole("button", { name: "Review discovery suggestions" }));
  await screen.findByText(/1 scoped suggestions/);
  v.rerender(<BoundedApplicationDiscovery mapRevisionId="map2" canExecute onSelect={vi.fn()} />);
  await waitFor(() => expect(screen.queryByText(/1 scoped suggestions/)).toBeNull());
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
