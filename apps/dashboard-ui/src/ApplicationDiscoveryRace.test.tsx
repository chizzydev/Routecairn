// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, act, waitFor, cleanup } from "@testing-library/react";
import { BoundedApplicationDiscovery } from "./BoundedApplicationDiscovery";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("discards an in-flight prior-source review after the operator changes source revision", async () => {
  let release!: (v: unknown) => void;
  const pending = new Promise((r) => {
    release = r;
  });
  vi.mocked(apiMutation).mockReturnValue(pending);
  const view = render(<BoundedApplicationDiscovery mapRevisionId="sourceA" canExecute onSelect={vi.fn()} />);
  fireEvent.click(screen.getByLabelText(/I reviewed this local scope/));
  fireEvent.click(screen.getByRole("button", { name: "Review discovery suggestions" }));
  view.rerender(<BoundedApplicationDiscovery mapRevisionId="sourceB" canExecute onSelect={vi.fn()} />);
  await act(async () =>
    release({
      proposalId: "prior-source-proposal",
      digest: "a".repeat(64),
      expiresAt: "2099-01-01T00:00:00Z",
      source: { sourceHash: "b".repeat(64) },
      round: 1,
      requestCeiling: 12,
      coverage: { observedRoutes: 1, complete: true },
      candidates: [
        {
          candidateId: "c".repeat(64),
          path: "/old-source/record",
          url: "http://127.0.0.1:9000/old-source/record",
          provenance: []
        }
      ],
      excluded: [],
      missingControls: []
    })
  );
  await waitFor(() => expect(screen.queryByText(/1 scoped suggestions/)).toBeNull());
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
