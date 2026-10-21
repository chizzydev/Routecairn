// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, act, cleanup } from "@testing-library/react";
import { FlexibleAuthentication } from "./FlexibleAuthentication";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it.each(["draft", "target", "unmount"] as const)(
  "refuses stale actor capability review after %s change",
  async (change) => {
    let release!: (v: unknown) => void;
    vi.mocked(apiMutation).mockImplementation(
      () =>
        new Promise((r) => {
          release = r;
        })
    );
    const accepted = vi.fn(),
      invalidated = vi.fn(),
      props = { targetId: "owned-target-a", credentials: [], onChange: accepted, onInvalidated: invalidated },
      view = render(<FlexibleAuthentication {...props} />);
    fireEvent.click(screen.getByLabelText(/I approve the exact GET path/));
    fireEvent.click(screen.getByRole("button", { name: "Review available checks" }));
    if (change === "draft")
      fireEvent.change(screen.getByLabelText("Exact reviewed read-only path"), { target: { value: "/new-path" } });
    else if (change === "target") view.rerender(<FlexibleAuthentication {...props} targetId="owned-target-b" />);
    else view.unmount();
    await act(async () =>
      release({ registry: { registryId: "obsolete" }, capabilities: { actors: [], workflows: [] } })
    );
    expect(accepted).not.toHaveBeenCalled();
    expect(apiMutation).toHaveBeenCalledTimes(1);
  }
);
it("public review needs no accounts and caps extra actors at eight without identity fields", () => {
  render(
    <FlexibleAuthentication targetId="owned-target" credentials={[]} onChange={vi.fn()} onInvalidated={vi.fn()} />
  );
  fireEvent.click(screen.getByLabelText(/I approve the exact GET path/));
  expect((screen.getByRole("button", { name: "Review available checks" }) as HTMLButtonElement).disabled).toBe(false);
  expect(screen.queryByLabelText(/principal/i)).toBeNull();
  for (let i = 0; i < 8; i++) fireEvent.click(screen.getByRole("button", { name: "Add account" }));
  expect((screen.getByRole("button", { name: "Add account" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getAllByRole("group")).toHaveLength(8);
  expect((screen.getByRole("button", { name: "Review available checks" }) as HTMLButtonElement).disabled).toBe(true);
});
