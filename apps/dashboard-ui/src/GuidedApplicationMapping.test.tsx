// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { GuidedApplicationMapping } from "./GuidedApplicationMapping";
import { apiGet, apiMutation } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const options = {
  targets: [{ id: "owned", displayName: "Owned app", baseOrigin: "http://127.0.0.1:9999" }],
  credentials: [
    ...(["primary", "account_a", "account_b"] as const).map((slot) => ({
      id: slot,
      targetId: "owned",
      alias: slot,
      identity: { principalId: slot, tenantId: slot === "account_b" ? "tenant-b" : "tenant-a", role: "member" }
    })),
    { id: "foreign", targetId: "other", alias: "foreign", identity: {} }
  ],
  acquisitions: [{ id: "retained", version: 1 }]
};
const revision = (status: string) => ({
  revisionId: "retained",
  status,
  digest: "a".repeat(64),
  input: {
    targetId: "owned",
    credentials: { primary: "primary", account_a: "account_a", account_b: "account_b" },
    routes: [
      {
        id: "object",
        kind: "OBJECT",
        url: "http://127.0.0.1:9999/object/42",
        pathTemplate: "/object/:id",
        method: "GET",
        identityPath: "id"
      }
    ]
  },
  actors: [
    { id: "primary", alias: "Primary" },
    { id: "anonymous", alias: "Anonymous" }
  ],
  observations:
    status === "COMPLETED"
      ? [
          {
            routeId: "object",
            template: "/object/:id",
            cells: [
              {
                actorId: "primary",
                alias: "Primary",
                role: "member",
                nativeDecision: "ALLOWED",
                nativeOutcome: "PASS",
                statusCode: 200,
                identityVerified: true,
                observedMarkers: [{ path: "id", valueFingerprint: "b".repeat(64), scalarType: "number" }]
              }
            ]
          }
        ]
      : [],
  proofBudget: { totalRequestCeiling: 40, checks: 4, maxResponseBytes: 8192 },
  transportIntents: [
    { purpose: "object-observe-primary", actorId: "primary", method: "GET", url: "http://127.0.0.1:9999/object/42" }
  ]
});
it("exposes read-only history without granting observation authority", async () => {
  vi.mocked(apiGet).mockResolvedValue(options);
  render(<GuidedApplicationMapping canExecute={false} onMatrix={() => {}} />);
  await screen.findByRole("option", { name: /Owned app/ });
  expect(screen.getByLabelText("Owned loopback target").closest("fieldset")?.disabled).toBe(true);
  expect(screen.getByText(/Read-only mapping access/)).toBeTruthy();
  expect(apiMutation).not.toHaveBeenCalled();
});
it("invalidates the preview and explicit consent when a route changes and excludes foreign credentials", async () => {
  vi.mocked(apiGet).mockResolvedValue(options);
  vi.mocked(apiMutation).mockResolvedValue(revision("REVIEW_REQUIRED"));
  render(<GuidedApplicationMapping canExecute onMatrix={() => {}} />);
  await screen.findByRole("option", { name: /Owned app/ });
  fireEvent.change(screen.getByLabelText("Owned loopback target"), { target: { value: "owned" } });
  expect(screen.queryByRole("option", { name: /foreign/ })).toBeNull();
  for (const slot of ["primary", "account_a", "account_b"])
    fireEvent.change(screen.getByLabelText(slot + " saved credential"), { target: { value: slot } });
  fireEvent.click(screen.getByRole("checkbox", { name: /I confirm these disposable/ }));
  fireEvent.change(screen.getByLabelText("Route 1 exact URL"), {
    target: { value: "http://127.0.0.1:9999/object/42" }
  });
  fireEvent.change(screen.getByLabelText("Route 1 template"), { target: { value: "/object/:id" } });
  fireEvent.click(screen.getByRole("checkbox", { name: /I confirm the exact listed GET/ }));
  fireEvent.click(screen.getByRole("button", { name: "Review observation requests" }));
  await screen.findByText("Observation status: REVIEW_REQUIRED");
  fireEvent.click(screen.getByRole("checkbox", { name: /I approve only/ }));
  fireEvent.change(screen.getByLabelText("Route 1 exact URL"), {
    target: { value: "http://127.0.0.1:9999/object/43" }
  });
  expect(screen.queryByRole("button", { name: "Authorize native observations" })).toBeNull();
  expect((screen.getByRole("checkbox", { name: /I confirm the exact listed GET/ }) as HTMLInputElement).checked).toBe(
    false
  );
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
it("retains UNKNOWN visibly and offers no observation replay", async () => {
  vi.mocked(apiGet).mockImplementation(async (path) => (path.endsWith("/mapping") ? options : revision("UNKNOWN")));
  render(<GuidedApplicationMapping canExecute onMatrix={() => {}} />);
  await screen.findByRole("option", { name: /retained/ });
  fireEvent.change(screen.getByLabelText("Retained application map"), { target: { value: "retained" } });
  await screen.findByText("Observation status: UNKNOWN");
  expect((screen.getByRole("button", { name: "Authorize native observations" }) as HTMLButtonElement).disabled).toBe(
    true
  );
  expect(screen.getByText(/Dispatch custody is uncertain/)).toBeTruthy();
  expect(apiMutation).not.toHaveBeenCalled();
});
it("uses the observed scalar type when binding numeric identities without interpreting response access as policy", async () => {
  vi.mocked(apiGet).mockImplementation(async (path) => (path.endsWith("/mapping") ? options : revision("COMPLETED")));
  vi.mocked(apiMutation).mockResolvedValue({});
  render(<GuidedApplicationMapping canExecute onMatrix={() => {}} />);
  await screen.findByRole("option", { name: /retained/ });
  fireEvent.change(screen.getByLabelText("Retained application map"), { target: { value: "retained" } });
  await screen.findByText("Observation status: COMPLETED");
  expect((screen.getByLabelText("object policy primary") as HTMLSelectElement).value).toBe("UNKNOWN");
  fireEvent.change(screen.getByLabelText("object expected identity"), { target: { value: "42" } });
  fireEvent.change(screen.getByLabelText("object policy primary"), { target: { value: "ALLOW" } });
  fireEvent.change(screen.getByLabelText("object policy anonymous"), { target: { value: "DENY" } });
  fireEvent.click(screen.getByRole("checkbox", { name: /I confirm these are declared policy/ }));
  fireEvent.click(screen.getByRole("button", { name: "Build reviewed authorization matrix" }));
  await waitFor(() => expect(apiMutation).toHaveBeenCalled());
  expect(vi.mocked(apiMutation).mock.calls[0]?.[2]).toMatchObject({
    expectations: [
      {
        kind: "OBJECT_AUTHORIZATION",
        identity: { path: "id", expectedValue: 42 },
        decisions: { primary: "ALLOW", anonymous: "DENY" }
      }
    ],
    policyConfirmed: true
  });
});
