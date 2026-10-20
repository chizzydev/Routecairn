// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@testing-library/react";
import { GuidedApplicationMapping } from "./GuidedApplicationMapping";
import { apiGet, apiMutation } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("does not silently turn whitespace into a numeric owner policy or submit it for review", async () => {
  const input = {
    targetId: "owned",
    credentials: { primary: "p", account_a: "a", account_b: "b" },
    routes: [
      {
        id: "object",
        kind: "OBJECT",
        method: "GET",
        url: "http://127.0.0.1:9999/object/42",
        pathTemplate: "/object/:id",
        identityPath: "id"
      }
    ]
  };
  vi.mocked(apiGet).mockImplementation(async (path) =>
    path.endsWith("/mapping")
      ? { targets: [], credentials: [], acquisitions: [{ id: "retained", version: 1 }] }
      : {
          revisionId: "retained",
          status: "COMPLETED",
          digest: "a".repeat(64),
          input,
          actors: [
            { id: "primary", alias: "Primary" },
            { id: "anonymous", alias: "Anonymous" }
          ],
          observations: [
            {
              routeId: "object",
              cells: [
                {
                  actorId: "primary",
                  alias: "Primary",
                  identityVerified: true,
                  nativeOutcome: "PASS",
                  nativeDecision: "ALLOWED",
                  observedMarkers: [{ path: "id", scalarType: "number", valueFingerprint: "b".repeat(64) }]
                }
              ]
            }
          ],
          proofBudget: { totalRequestCeiling: 8 },
          transportIntents: []
        }
  );
  vi.mocked(apiMutation).mockResolvedValue({});
  render(<GuidedApplicationMapping canExecute onMatrix={() => {}} />);
  await screen.findByRole("option", { name: /retained/ });
  fireEvent.change(screen.getByLabelText("Retained application map"), { target: { value: "retained" } });
  await screen.findByText("Observation status: COMPLETED");
  fireEvent.change(screen.getByLabelText("object expected identity"), { target: { value: "   " } });
  fireEvent.change(screen.getByLabelText("object policy primary"), { target: { value: "ALLOW" } });
  fireEvent.change(screen.getByLabelText("object policy anonymous"), { target: { value: "DENY" } });
  fireEvent.click(screen.getByRole("checkbox", { name: /I confirm these are declared policy/ }));
  fireEvent.click(screen.getByRole("button", { name: "Build reviewed authorization matrix" }));
  await waitFor(() => expect(apiMutation).not.toHaveBeenCalled());
  expect((await screen.findByRole("alert")).textContent).toContain("explicit finite decimal");
});
