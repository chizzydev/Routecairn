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
it("separates declaration save from all native execution and clears entered secrets after success", async () => {
  const saved = vi.fn();
  vi.mocked(apiMutation).mockResolvedValue({ targetId: "target", credentials: {}, executionAuthority: "NONE" });
  render(<ApplicationOnboarding onSaved={saved} />);
  const b = screen.getByRole("button", { name: "Save declarations without sending requests" });
  expect((b as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("primary authorizationHeader"), {
    target: { value: "Bearer disposable-secret" }
  });
  fireEvent.click(screen.getByLabelText(/I own this local application/));
  fireEvent.click(b);
  await waitFor(() => expect(saved).toHaveBeenCalledTimes(1));
  expect(apiMutation).toHaveBeenCalledTimes(1);
  expect((screen.getByLabelText("primary authorizationHeader") as HTMLInputElement).value).toBe("");
  expect(screen.getByRole("status").textContent).toContain("unverified");
});
it("reports refused setup without leaking backend diagnostics or pretending success", async () => {
  vi.mocked(apiMutation).mockRejectedValue(Error("private-token-diagnostic"));
  render(<ApplicationOnboarding onSaved={vi.fn()} />);
  fireEvent.click(screen.getByLabelText(/I own this local application/));
  fireEvent.click(screen.getByRole("button"));
  await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
  expect(screen.queryByText(/private-token-diagnostic/)).toBeNull();
  expect(screen.queryByRole("status")).toBeNull();
});
