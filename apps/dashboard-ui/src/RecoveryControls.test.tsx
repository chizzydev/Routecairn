// @vitest-environment jsdom
import React from "react";
import { afterEach, describe, it, expect, vi } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { WorkerDiagnostics } from "./WorkerDiagnostics";
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
describe("custody uncertainty operator controls", () => {
  it("does not offer fleet release when durable custody remains unknown", async () => {
    const policy = {
      memoryBytes: 100,
      cpuTimeMs: 100,
      wallClockMs: 100,
      outputBytes: 100,
      tempBytes: 100,
      heartbeatTimeoutMs: 100,
      cleanupGraceMs: 135000,
      forceKillGraceMs: 5000,
      crashLoopLimit: 3,
      crashLoopWindowMs: 100
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({
          dispatchState: "QUARANTINED",
          custodyQuarantine: true,
          resources: [{ resource_id: "owned-resource", state: "UNKNOWN_RETAINED" }],
          retentionFailures: [],
          workers: [],
          policy
        })
      }))
    );
    render(<WorkerDiagnostics canManage={true} />);
    const button = await screen.findByRole("button", { name: "Release dispatch" });
    await screen.findByText("QUARANTINED");
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });
});
