// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { AuthorizationWorkbench } from "./AuthorizationWorkbench";
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
it("keeps read-only operators from importing or starting authorization checks", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => ({ scans: [], credentials: [], revisions: [] }) }))
  );
  render(<AuthorizationWorkbench canExecute={false} onScan={() => {}} onComparison={() => {}} />);
  await screen.findByText(/Read-only access/);
  expect((screen.getByLabelText("Import authorization expectations") as HTMLInputElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: "Create versioned matrix" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.queryByRole("button", { name: "Authorize and run selected matrix" })).toBeNull();
});
it("shows unavailable observations as an error instead of a clean assessment", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw Error("Observation inventory unavailable");
    })
  );
  render(<AuthorizationWorkbench canExecute onScan={() => {}} onComparison={() => {}} />);
  expect((await screen.findByRole("alert")).textContent).toContain("Observation inventory unavailable");
  expect(screen.queryByText(/All selected contracts matched/)).toBeNull();
});

it("keeps a retained unknown dispatch visibly uncertain and disables another execution", async () => {
  const id = "11111111-1111-4111-8111-111111111111";
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => ({
      ok: true,
      json: async () =>
        url.endsWith(id)
          ? {
              revisionId: id,
              digest: "a".repeat(64),
              classification: "READY_READ_ONLY",
              input: { targetId: id, sourceScanId: id, credentials: {}, expectations: [] },
              matrix: [],
              blockers: [],
              proofBudget: { totalRequestCeiling: 40, checks: 0, identityRequests: 0, maxResponseBytes: 8192 },
              request: {},
              provenance: {
                securityCases: { cases: [] },
                authorizationReview: { questions: [] },
                observations: { observations: [] }
              },
              result: { revisionId: id, version: 1, status: "UNKNOWN", verifiedPass: false }
            }
          : { scans: [], credentials: [], revisions: [{ id, version: 1 }] }
    }))
  );
  render(<AuthorizationWorkbench canExecute onScan={() => {}} onComparison={() => {}} />);
  await screen.findByRole("option", { name: new RegExp(id) });
  fireEvent.change(screen.getByLabelText("Retained workbench revision"), { target: { value: id } });
  await screen.findByText(/Execution outcome: UNKNOWN/);
  expect(
    (screen.getByRole("button", { name: "Authorize and run selected matrix" }) as HTMLButtonElement).disabled
  ).toBe(true);
  expect(screen.getByText(/This is not a verified clean/)).toBeTruthy();
});
