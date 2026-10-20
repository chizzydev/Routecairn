// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, act, waitFor } from "@testing-library/react";
import { ApplicationOnboarding } from "./ApplicationOnboarding";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("never selects an obsolete onboarding response after a draft edit; reports possible committed declarations", async () => {
  let resolve!: (v: unknown) => void;
  vi.mocked(apiMutation).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      })
  );
  const saved = vi.fn();
  render(<ApplicationOnboarding onSaved={saved} />);
  fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "Earlier draft" } });
  fireEvent.change(screen.getByLabelText("primary authorizationHeader"), { target: { value: "Bearer owned-old" } });
  fireEvent.click(screen.getByLabelText(/I own this local application/));
  fireEvent.click(screen.getByRole("button", { name: "Save declarations without sending requests" }));
  fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "Newer draft" } });
  await act(async () => {
    resolve({ targetId: "old-target", credentials: {}, executionAuthority: "NONE" });
  });
  expect(saved).not.toHaveBeenCalled();
  expect((screen.getByLabelText("Application name") as HTMLInputElement).value).toBe("Newer draft");
  expect((screen.getByLabelText("primary authorizationHeader") as HTMLInputElement).value).toBe("");
  expect(screen.getByRole("alert").textContent).toContain("may have saved");
  expect(apiMutation).toHaveBeenCalledTimes(1);
});
it("discards success after unmount without notifying the mapping parent", async () => {
  let resolve!: (v: unknown) => void;
  vi.mocked(apiMutation).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      })
  );
  const saved = vi.fn(),
    view = render(<ApplicationOnboarding onSaved={saved} />);
  fireEvent.click(screen.getByLabelText(/I own this local application/));
  fireEvent.click(screen.getByRole("button", { name: "Save declarations without sending requests" }));
  view.unmount();
  await act(async () => {
    resolve({ targetId: "old-target" });
  });
  expect(saved).not.toHaveBeenCalled();
});

it("never calls a lost save response a rollback or retries it; clears credentials and requires inventory review", async () => {
  vi.mocked(apiMutation).mockRejectedValue(new TypeError("private-network-diagnostic"));
  const saved = vi.fn();
  render(<ApplicationOnboarding onSaved={saved} />);
  fireEvent.change(screen.getByLabelText("primary authorizationHeader"), {
    target: { value: "Bearer disposable-only" }
  });
  fireEvent.click(screen.getByLabelText(/I own this local application/));
  fireEvent.click(screen.getByRole("button", { name: "Save declarations without sending requests" }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("could not be confirmed"));
  expect(screen.getByRole("alert").textContent).toContain("may have saved");
  expect(screen.getByRole("alert").textContent).not.toContain("private-network-diagnostic");
  expect((screen.getByLabelText("primary authorizationHeader") as HTMLInputElement).value).toBe("");
  expect(saved).not.toHaveBeenCalled();
  expect(apiMutation).toHaveBeenCalledTimes(1);
  expect(
    (screen.getByRole("button", { name: "Save declarations without sending requests" }) as HTMLButtonElement).disabled
  ).toBe(true);
});
