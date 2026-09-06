// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./main";

describe("production mutation workspace", () => {
  it("opens the production safety gate and only lists production-enabled targets", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.includes("/api/auth/session") ? { principal: { login: "owner", role: "OWNER" } } : url.includes("/api/targets") ? { targets: [{ id: "target-1", displayName: "Production app", baseOrigin: "https://app.example.com", productionEnabled: true }, { id: "target-2", displayName: "Lab app", baseOrigin: "https://lab.example.com", productionEnabled: false }] } : url.includes("/api/credential-profiles") ? { profiles: [{ id: "profile-1", safeAlias: "low-privileged actor", enabled: true }] } : { scans: { total: 0, queued: 0, running: 0, completed: 0, failed: 0, interrupted: 0 }, findings: { open: 0, unreviewed: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, resolved: 0, reopened: 0 }, recentScans: [] };
      return { ok: true, status: 200, json: async () => body } as Response;
    }));
    const user = userEvent.setup(); render(<App />);
    await user.click(await screen.findByRole("button", { name: "Production Mutation" }));
    expect(await screen.findByText("Production Controlled Mutation")).toBeTruthy();
    expect(screen.getByText("Production safety gate")).toBeTruthy();
    expect(screen.getByText("Production-enabled targets")).toBeTruthy();
    expect(screen.getByText("Enabled actor profiles")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Guided builder" }).className).toContain("selected");
    expect(screen.queryByLabelText("Production case JSON")).toBeNull();
    expect(screen.getByRole("group", { name: "1. Target and actor" })).toBeTruthy();
    expect(screen.getByRole("group", { name: "10. Approval window" })).toBeTruthy();
    expect(await screen.findByRole("option", { name: /Production app/ })).toBeTruthy();
    expect(screen.queryByRole("option", { name: /Lab app/ })).toBeNull();
    vi.unstubAllGlobals();
  });
});
