// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, act } from "@testing-library/react";
import { BusinessRelationshipPanel } from "./BusinessRelationshipPanel";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const p = {
  proposalId: "p",
  source: { mapRevisionId: "map" },
  candidates: ["source", "consumer"].map((routeId) => ({
    routeId,
    identityPath: "record.id",
    tenantPath: "record.tenant",
    evidence: [{ markers: ["record.id", "record.tenant", "record.parent", "record.version"].map((path) => ({ path })) }]
  }))
} as never;
it("drafts exact observed relationships without authorizing native requests or extracting policy", async () => {
  vi.mocked(apiMutation).mockResolvedValue({ proposalId: "next" });
  const next = vi.fn();
  render(<BusinessRelationshipPanel proposal={p} canExecute onProposal={next} />);
  fireEvent.change(screen.getByLabelText("Relationship 1 reference"), { target: { value: "record.parent" } });
  fireEvent.click(screen.getByRole("button", { name: "Build evidence-bound relationship questions" }));
  await act(async () => {});
  expect(apiMutation).toHaveBeenCalledWith(
    "/api/authorization-workbench/mapping/hypotheses",
    "POST",
    expect.objectContaining({
      workflow: expect.objectContaining({
        relationships: [
          expect.objectContaining({ producer: "source", consumer: "consumer", reference: "record.parent" })
        ]
      })
    })
  );
  expect(next).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/never ownership/)).toBeTruthy();
});
it("keeps read-only users from generating relationships and rejects late unmounted responses", async () => {
  const next = vi.fn(),
    view = render(<BusinessRelationshipPanel proposal={p} canExecute={false} onProposal={next} />);
  expect(
    (screen.getByRole("button", { name: "Build evidence-bound relationship questions" }) as HTMLButtonElement).disabled
  ).toBe(true);
  view.rerender(<BusinessRelationshipPanel proposal={p} canExecute onProposal={next} />);
  let resolve!: (v: unknown) => void;
  vi.mocked(apiMutation).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      })
  );
  fireEvent.click(screen.getByRole("button", { name: "Build evidence-bound relationship questions" }));
  view.unmount();
  await act(async () => {
    resolve({ proposalId: "late" });
  });
  expect(next).not.toHaveBeenCalled();
});
