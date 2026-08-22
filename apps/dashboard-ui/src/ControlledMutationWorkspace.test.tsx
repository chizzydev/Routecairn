// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./main";

describe("controlled mutation workspace", () => {
  it("opens the owner approval workspace and loads registered targets", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.includes("/api/auth/session") ? { principal: { login: "owner", role: "OWNER" } } : url.includes("/api/targets") ? { targets: [{ id: "target-1", displayName: "Staging target", baseOrigin: "https://example.test" }] } : { scans: { total: 0, queued: 0, running: 0, completed: 0, failed: 0, interrupted: 0 }, findings: { open: 0, unreviewed: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, resolved: 0, reopened: 0 }, recentScans: [] };
      return { ok: true, status: 200, json: async () => body } as Response;
    }));
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Mutation Approval" }));
    expect(await screen.findByText("Controlled Mutation Workspace")).toBeTruthy();
    expect(screen.getByText(/Staging target/)).toBeTruthy();
    vi.unstubAllGlobals();
  });
});
