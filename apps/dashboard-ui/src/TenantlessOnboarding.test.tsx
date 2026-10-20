// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@testing-library/react";
import { ApplicationOnboarding } from "./ApplicationOnboarding";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("saves explicit principal-role declarations without any fabricated tenant field and with separate consent", async () => {
  vi.mocked(apiMutation).mockResolvedValue({
    targetId: "generated-target",
    credentials: {},
    executionAuthority: "NONE"
  });
  render(<ApplicationOnboarding onSaved={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("Application identity model"), { target: { value: "PRINCIPAL_ROLE" } });
  expect(screen.queryByLabelText("primary tenant")).toBeNull();
  expect(screen.queryByLabelText("Onboarding tenantField")).toBeNull();
  for (const [label, value] of [
    ["Application name", "Generated tenantless app"],
    ["Owned application origin", "http://127.0.0.1:9000"],
    ["Owner authorization explanation", "Owner authorizes only separately reviewed generated GET routes"],
    ["Initial permitted GET path", "/object"]
  ] as const)
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  for (const [i, slot] of ["primary", "account_a", "account_b"].entries())
    for (const [key, value] of [
      ["principal", "generated-person-" + i],
      ["role", i === 0 ? "admin" : "user"],
      ["expiresAt", "2099-01-01T00:00:00Z"],
      ["authorizationHeader", "Bearer generated-ui-" + slot]
    ])
      fireEvent.change(screen.getByLabelText(slot + " " + key), { target: { value } });
  expect(apiMutation).not.toHaveBeenCalled();
  fireEvent.click(screen.getByLabelText(/I own this local application/));
  fireEvent.click(screen.getByRole("button", { name: "Save declarations without sending requests" }));
  await waitFor(() => expect(apiMutation).toHaveBeenCalledTimes(1));
  const payload = vi.mocked(apiMutation).mock.calls[0]![2] as {
    identityModel: string;
    tenantField?: string;
    objectTenantField?: string;
    actors: Record<string, { tenant?: string }>;
  };
  expect(payload.identityModel).toBe("PRINCIPAL_ROLE");
  expect(payload).not.toHaveProperty("tenantField");
  expect(payload).not.toHaveProperty("objectTenantField");
  expect(Object.values(payload.actors).every((a) => !Object.hasOwn(a, "tenant"))).toBe(true);
});
it("changing the identity model invalidates existing confirmation without issuing a request", () => {
  render(<ApplicationOnboarding onSaved={vi.fn()} />);
  const consent = screen.getByLabelText(/I own this local application/) as HTMLInputElement;
  fireEvent.click(consent);
  expect(consent.checked).toBe(true);
  fireEvent.change(screen.getByLabelText("Application identity model"), { target: { value: "PRINCIPAL_ROLE" } });
  expect(consent.checked).toBe(false);
  expect((screen.getByRole("button") as HTMLButtonElement).disabled).toBe(true);
  expect(apiMutation).not.toHaveBeenCalled();
});
