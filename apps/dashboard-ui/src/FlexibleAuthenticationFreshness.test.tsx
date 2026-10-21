// @vitest-environment jsdom
import React from "react";
import { expect, it, vi, afterEach } from "vitest";
import { render, screen, fireEvent, act, cleanup } from "@testing-library/react";
import { FlexibleAuthentication } from "./FlexibleAuthentication";
import type { CredentialSummary } from "./CredentialLifecycle";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("invalidates pending and accepted previews when vault credential metadata changes", async () => {
  let release!: (v: unknown) => void;
  vi.mocked(apiMutation).mockImplementation(
    () =>
      new Promise((r) => {
        release = r;
      })
  );
  const accepted = vi.fn(),
    invalidated = vi.fn();
  const credential = {
    id: "credential-a",
    targetId: "target",
    enabled: true,
    safeAlias: "Owned account",
    secretVersion: 1,
    health: { classification: "UNVERIFIED" }
  } as CredentialSummary;
  const props = { targetId: "target", credentials: [credential], onChange: accepted, onInvalidated: invalidated };
  const view = render(<FlexibleAuthentication {...props} />);
  fireEvent.click(screen.getByLabelText(/I approve the exact GET path/));
  fireEvent.click(screen.getByRole("button", { name: "Review available checks" }));
  view.rerender(<FlexibleAuthentication {...props} credentials={[{ ...credential, secretVersion: 2 }]} />);
  await act(async () => release({ registry: { registryId: "obsolete" }, capabilities: { actors: [], workflows: [] } }));
  expect(accepted).not.toHaveBeenCalled();
  expect(screen.queryByText(/Registry obsolete/)).toBeNull();
});
it("removes an already accepted preparation when credential authority metadata changes", async () => {
  vi.mocked(apiMutation).mockResolvedValue({
    registry: { registryId: "accepted-review" },
    capabilities: { actors: [], workflows: [] }
  } as never);
  const credential = {
    id: "saved",
    targetId: "owned",
    enabled: true,
    secretVersion: 1,
    safeIdentitySummary: {}
  } as CredentialSummary;
  const accepted = vi.fn(),
    invalidated = vi.fn(),
    props = { targetId: "owned", credentials: [credential], onChange: accepted, onInvalidated: invalidated };
  const view = render(<FlexibleAuthentication {...props} />);
  fireEvent.click(screen.getByLabelText(/I approve the exact GET path/));
  await act(async () => fireEvent.click(screen.getByRole("button", { name: "Review available checks" })));
  expect(accepted).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/Registry accepted-review/)).toBeTruthy();
  const before = invalidated.mock.calls.length;
  view.rerender(
    <FlexibleAuthentication {...props} credentials={[{ ...credential, enabled: false, secretVersion: 2 }]} />
  );
  expect(screen.queryByText(/Registry accepted-review/)).toBeNull();
  expect(invalidated.mock.calls.length).toBeGreaterThan(before);
});
