// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, act, cleanup } from "@testing-library/react";
import { OwnedApplicationIntake } from "./OwnedApplicationIntake";
import { apiGet, apiMutation } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const props = {
  target: "owned",
  credentials: { primary: "p", account_a: "a", account_b: "b" },
  disabled: false,
  onApply: vi.fn()
};
it("requires explicit offline consent, never applies an unconfirmed import, and exposes uncertain acknowledgement without replay", async () => {
  vi.mocked(apiMutation).mockRejectedValue(Error("lost ack"));
  render(<OwnedApplicationIntake {...props} />);
  expect(
    (screen.getByRole("button", { name: "Validate and retain offline intake" }) as HTMLButtonElement).disabled
  ).toBe(true);
  fireEvent.change(screen.getByLabelText("Minimized owner evidence JSON"), { target: { value: "{}" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Validate and retain offline intake" }));
  await screen.findByRole("alert");
  expect(apiMutation).toHaveBeenCalledTimes(1);
  expect(props.onApply).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: /Apply reviewed/ })).toBeNull();
});
it("discards a retained response when the pasted artifact changes before acknowledgement", async () => {
  let resolve!: (value: unknown) => void;
  vi.mocked(apiMutation).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      })
  );
  render(<OwnedApplicationIntake {...props} />);
  fireEvent.change(screen.getByLabelText("Minimized owner evidence JSON"), { target: { value: "{}" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Validate and retain offline intake" }));
  await act(async () => {
    await Promise.resolve();
  });
  fireEvent.change(screen.getByLabelText("Minimized owner evidence JSON"), { target: { value: '{"changed":true}' } });
  await act(async () => resolve({ revisionId: "old", draft: {}, requestsSent: 0, missing: [] }));
  expect(screen.queryByText(/Offline intake retained/)).toBeNull();
});

it("recovers a retained receipt by explicit GET after a lost save acknowledgement, without repeating the POST", async () => {
  const id = "11111111-1111-4111-8111-111111111111";
  vi.mocked(apiMutation).mockRejectedValue(Error("lost after commit"));
  vi.mocked(apiGet)
    .mockResolvedValueOnce({
      records: [{ revisionId: id, createdAt: "2026-10-20T00:00:00Z", artifactSha256: "pinned" }],
      total: 1,
      truncated: false
    })
    .mockResolvedValueOnce({
      revisionId: id,
      digest: "pinned",
      requestsSent: 0,
      identityStatus: "DECLARED_NOT_NATIVE_VERIFIED",
      provenance: "OWNER_LOCAL_APPLICATION",
      missing: [],
      freshness: "CURRENT",
      draft: { targetId: props.target, credentials: props.credentials, routes: [] }
    });
  render(<OwnedApplicationIntake {...props} />);
  fireEvent.change(screen.getByLabelText("Minimized owner evidence JSON"), { target: { value: "{}" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Validate and retain offline intake" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Inspect retained offline intakes" }));
  await screen.findByLabelText("Retained intake receipt");
  fireEvent.change(screen.getByLabelText("Retained intake receipt"), { target: { value: id } });
  fireEvent.click(screen.getByRole("button", { name: "Open retained intake without replay" }));
  await screen.findByText(/Offline intake retained/);
  fireEvent.click(screen.getByRole("button", { name: "Apply reviewed intake routes without execution" }));
  expect(apiMutation).toHaveBeenCalledTimes(1);
  expect(apiGet).toHaveBeenCalledTimes(2);
  expect(props.onApply).toHaveBeenCalledTimes(1);
});
it("keeps stale retained receipts readable but refuses to apply their old authority", async () => {
  vi.mocked(apiGet).mockResolvedValue({
    revisionId: "11111111-1111-4111-8111-111111111111",
    digest: "stale",
    requestsSent: 0,
    identityStatus: "DECLARED_NOT_NATIVE_VERIFIED",
    provenance: "OWNER_LOCAL_APPLICATION",
    missing: [],
    freshness: "STALE",
    draft: { targetId: props.target, credentials: props.credentials, routes: [] }
  });
  render(<OwnedApplicationIntake {...props} />);
  fireEvent.change(screen.getByLabelText("Exact retained intake ID"), {
    target: { value: "11111111-1111-4111-8111-111111111111" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Open retained intake without replay" }));
  await screen.findByText(/context STALE/);
  expect(
    (screen.getByRole("button", { name: "Apply reviewed intake routes without execution" }) as HTMLButtonElement)
      .disabled
  ).toBe(true);
  expect(apiMutation).not.toHaveBeenCalled();
});

it("discards a late receipt GET after the exact selected receipt ID changes", async () => {
  let resolve!: (value: unknown) => void;
  vi.mocked(apiGet).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      })
  );
  render(<OwnedApplicationIntake {...props} />);
  fireEvent.change(screen.getByLabelText("Exact retained intake ID"), {
    target: { value: "11111111-1111-4111-8111-111111111111" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Open retained intake without replay" }));
  fireEvent.change(screen.getByLabelText("Exact retained intake ID"), {
    target: { value: "22222222-2222-4222-8222-222222222222" }
  });
  await act(async () =>
    resolve({
      revisionId: "11111111-1111-4111-8111-111111111111",
      digest: "old",
      requestsSent: 0,
      identityStatus: "DECLARED_NOT_NATIVE_VERIFIED",
      provenance: "OWNER_LOCAL_APPLICATION",
      missing: [],
      freshness: "CURRENT",
      draft: { targetId: props.target, credentials: props.credentials, routes: [] }
    })
  );
  expect(screen.queryByText(/Offline intake retained/)).toBeNull();
  expect(props.onApply).not.toHaveBeenCalled();
});
