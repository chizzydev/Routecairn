// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, act, cleanup } from "@testing-library/react";
import { AnalystHandoff } from "./AnalystHandoff";
import { apiGet } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("exposes bounded history, snapshot continuation and nonquiet empty/error states without implicit I/O", async () => {
  vi.mocked(apiGet)
    .mockResolvedValueOnce({
      matching: 24,
      total: 124,
      offset: 0,
      snapshot: "pinned",
      entries: [{ id: "old-unknown", state: "UNKNOWN", detail: { status: "UNKNOWN" } }],
      nextCursor: "next"
    })
    .mockRejectedValueOnce(Error("changed"));
  render(<AnalystHandoff proposalId="owned" />);
  expect(apiGet).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Search retained history" }));
  await screen.findByText(/24 matching of 124/);
  expect(screen.getByText(/old-unknown/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Next history page" }));
  await screen.findByRole("alert");
  expect(screen.queryByText(/old-unknown/)).toBeNull();
  expect(apiGet).toHaveBeenLastCalledWith(expect.stringContaining("cursor=next"));
});
it("discards responses after changing proposal, and refuses to portray an unavailable handoff as success", async () => {
  let resolve!: (value: unknown) => void;
  vi.mocked(apiGet)
    .mockImplementationOnce(
      () =>
        new Promise((r) => {
          resolve = r;
        })
    )
    .mockRejectedValue(Error("unavailable"));
  const v = render(<AnalystHandoff proposalId="one" />);
  fireEvent.click(screen.getByRole("button", { name: "Search retained history" }));
  v.rerender(<AnalystHandoff proposalId="two" />);
  await act(async () =>
    resolve({
      matching: 1,
      total: 1,
      offset: 0,
      snapshot: "old",
      entries: [{ id: "stale-private", state: "UNKNOWN", detail: {} }]
    })
  );
  expect(screen.queryByText(/stale-private/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Prepare redacted analyst handoff" }));
  await screen.findByRole("alert");
  expect(screen.queryByRole("button", { name: "Download redacted analyst packet" })).toBeNull();
});

it("searches comparison failures explicitly instead of silently relying on the bounded proof summary", async () => {
  vi.mocked(apiGet).mockResolvedValue({
    matching: 1,
    total: 104,
    offset: 0,
    snapshot: "case",
    entries: [{ id: "old-comparison", state: "FAILED", detail: { status: "FAILED", coverageComplete: false } }],
    nextCursor: null
  });
  render(<AnalystHandoff proposalId="owned" />);
  fireEvent.change(screen.getByLabelText("History type"), { target: { value: "comparisons" } });
  fireEvent.change(screen.getByLabelText("History search"), { target: { value: "FAILED" } });
  fireEvent.click(screen.getByRole("button", { name: "Search retained history" }));
  await screen.findByText(/old-comparison/);
  expect(apiGet).toHaveBeenLastCalledWith(expect.stringContaining("kind=comparisons&query=FAILED"));
});
