// @vitest-environment jsdom
import React from "react";
import { it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { ApplicationMapComparison } from "./ApplicationMapComparison";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiGet: vi.fn(), apiMutation: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("requires an explicit baseline and shows incomplete map comparisons as UNKNOWN without proof authority", async () => {
  vi.mocked(apiMutation).mockResolvedValue({
    comparisonId: "comparison",
    digest: "a".repeat(64),
    status: "UNKNOWN",
    baseline: { sourceHash: null },
    current: { sourceHash: null },
    routes: []
  });
  render(<ApplicationMapComparison maps={[{ id: "old", version: 1 }]} saved={[]} currentId="new" />);
  expect((screen.getByRole("button", { name: "Compare observed maps" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("Baseline application map"), { target: { value: "old" } });
  fireEvent.click(screen.getByRole("button", { name: "Compare observed maps" }));
  await screen.findByText("Map comparison: UNKNOWN · comparison");
  expect(apiMutation).toHaveBeenCalledWith("/api/authorization-workbench/mapping/comparisons", "POST", {
    baselineRevisionId: "old",
    currentRevisionId: "new"
  });
  expect(screen.getByText("No policy or vulnerability conclusion is inferred.")).toBeTruthy();
  expect(screen.queryByText(/Authorize native/)).toBeNull();
});
