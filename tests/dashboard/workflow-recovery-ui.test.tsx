// @vitest-environment jsdom
import React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WorkflowRecoveryPanel } from "../../apps/dashboard-ui/src/WorkflowRecoveryPanel";
import { setCsrfToken } from "../../apps/dashboard-ui/src/api";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe("dashboard workflow recovery", () => {
  it("keeps the dashboard usable when the inventory response is malformed", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })));
    render(<WorkflowRecoveryPanel />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByRole("region", { name: "Workflow cleanup recovery" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Run cleanup recovery" })).toBeNull();
  });
  it("requires approval again when polling discovers a replacement checkpoint", async () => {
    let tick: (() => void) | undefined; let digest = "a".repeat(64);
    const originalInterval = window.setInterval.bind(window);
    vi.spyOn(window, "setInterval").mockImplementation((callback, delay) => { if (delay === 3000) { tick = callback as () => void; return 123; } return originalInterval(callback, delay); });
    vi.stubGlobal("fetch", vi.fn(async (url: string) => new Response(JSON.stringify(url.includes("credential-profiles") ? { profiles: [] } : url === "/api/targets" ? { targets: [{ id: "target", displayName: "Target", baseOrigin: "http://127.0.0.1" }] } : { cases: [{ caseId: "case", stage: "CLEANUP_FAILED", recoveryKind: "WORKFLOW", workflow: "authenticationLifecycle", checkpointDigest: digest, targetOrigin: "http://127.0.0.1", actorSlots: [] }], jobs: [] }), { status: 200 })));
    render(<WorkflowRecoveryPanel />);
    await screen.findByRole("option", { name: /authenticationLifecycle/ });
    fireEvent.change(screen.getByLabelText("Unresolved workflow"), { target: { value: "case" } });
    fireEvent.change(screen.getByLabelText("Registered target"), { target: { value: "target" } });
    fireEvent.click(screen.getByRole("checkbox"));
    expect((screen.getByRole("button") as HTMLButtonElement).disabled).toBe(false);
    digest = "b".repeat(64);
    await act(async () => { tick?.(); });
    await waitFor(() => expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false));
    expect((screen.getByRole("button") as HTMLButtonElement).disabled).toBe(true);
  });
  it("requires an exact obligation, matching target, fresh profile and explicit cleanup approval", async () => {
    const writes: unknown[] = []; setCsrfToken("test-csrf");
    vi.stubGlobal("fetch", vi.fn(async (url: string, options?: RequestInit) => {
      const body = options?.method === "POST" ? (writes.push(JSON.parse(String(options.body))), { jobId: "job-1" }) : url.includes("credential-profiles") ? { profiles: [{ id: "credential-a", name: "Fresh actor", enabled: true }] } : url === "/api/targets" ? { targets: [{ id: "target-a", displayName: "Disposable target", baseOrigin: "http://127.0.0.1:8080" }, { id: "wrong", displayName: "Wrong target", baseOrigin: "https://out-of-scope.test" }] } : { cases: [{ caseId: "auth-lifecycle-case", workflow: "authenticationLifecycle", targetOrigin: "http://127.0.0.1:8080", stage: "CLEANUP_FAILED", recoveryKind: "WORKFLOW", checkpointDigest: "a".repeat(64), actorSlots: ["primary"] }], jobs: [] };
      return new Response(JSON.stringify(body), { status: 200 });
    }));
    render(<WorkflowRecoveryPanel />);
    await screen.findByRole("option", { name: /authenticationLifecycle/ });
    fireEvent.change(screen.getByLabelText("Unresolved workflow"), { target: { value: "auth-lifecycle-case" } });
    expect(screen.queryByRole("option", { name: "Wrong target" })).toBeNull();
    const button = screen.getByRole("button", { name: "Run cleanup recovery" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Registered target"), { target: { value: "target-a" } });
    fireEvent.change(screen.getByLabelText("Fresh primary credential"), { target: { value: "credential-a" } });
    expect(button.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(button);
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).toEqual({ caseId: "auth-lifecycle-case", checkpointDigest: "a".repeat(64), targetId: "target-a", credentialProfileId: "credential-a", confirmation: "I_AUTHORIZE_STORED_CLEANUP_ONLY" });
    await screen.findByRole("status");
    expect(button.disabled).toBe(true);
  });
});
