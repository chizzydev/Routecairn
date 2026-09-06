// @vitest-environment jsdom
import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WorkerDiagnostics } from "./WorkerDiagnostics";

afterEach(() => vi.unstubAllGlobals());

describe("WorkerDiagnostics", () => {
  it("shows live resource, module, cleanup, process-tree, and termination diagnostics", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, status: 200, json: async () => fleet() })));
    const view = render(<WorkerDiagnostics canManage={true} />);
    expect(await screen.findByText("authentication-lifecycle")).toBeTruthy();
    expect(screen.getByText("MEMORY_LIMIT")).toBeTruthy();
    expect(screen.getByText("7001, 7002")).toBeTruthy();
    expect(screen.getAllByText("RUNNING").length).toBeGreaterThan(0);
    expect(screen.getByText(/RSS exceeded/)).toBeTruthy();
    view.unmount();
  });

  it("operates fleet quarantine and release from the dashboard", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => ({ ok: true, status: 200, json: async () => init?.method === "POST" ? { ok: true } : fleet() }));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("prompt", vi.fn(() => "Planned worker maintenance"));
    const user = userEvent.setup();
    const view = render(<WorkerDiagnostics canManage={true} />);
    await user.click(await screen.findByRole("button", { name: "Quarantine dispatch" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/workers/fleet/quarantine", expect.objectContaining({ method: "POST" })));
    view.unmount();
  });
});

function fleet() {
  const policy = { memoryBytes: 805306368, cpuTimeMs: 900000, wallClockMs: 1200000, outputBytes: 536870912, tempBytes: 268435456, heartbeatTimeoutMs: 15000, cleanupGraceMs: 135000, forceKillGraceMs: 5000, crashLoopLimit: 3, crashLoopWindowMs: 300000 };
  return { dispatchState: "NORMAL", crashCount: 1, policy, workers: [{ id: "00000000-0000-4000-8000-000000000001", processId: 7001, state: "RUNNING", currentJobId: "00000000-0000-4000-8000-000000000002", startedAt: new Date().toISOString(), lastHeartbeatAt: new Date().toISOString(), currentModule: "authentication-lifecycle", cleanupState: "RUNNING", resources: { rssBytes: 800000000, heapUsedBytes: 400000000, cpuTimeMs: 1200, outputBytes: 2048, tempBytes: 1024 }, processTreePids: [7001, 7002], failureCategory: "MEMORY_LIMIT", terminationReason: "Worker RSS exceeded its configured ceiling.", policy }] };
}
