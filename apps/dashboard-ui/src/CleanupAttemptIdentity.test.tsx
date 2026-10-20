// @vitest-environment jsdom
import { webcrypto } from "node:crypto";
import { describe, it, expect, vi, afterEach } from "vitest";
import { apiMutation, setCsrfToken, setActiveOrganizationId } from "./api";
afterEach(() => {
  sessionStorage.clear();
  vi.unstubAllGlobals();
});
describe("stable explicit cleanup request identity", () => {
  it("retains the same submission identity across an unavailable acknowledgement", async () => {
    vi.stubGlobal("crypto", webcrypto);
    setCsrfToken("fixture-only");
    setActiveOrganizationId("org-fixture");
    const calls: Record<string, unknown>[] = [],
      fetch = vi.fn(async (_url: string, init: RequestInit) => {
        calls.push(JSON.parse(String(init.body)));
        if (calls.length === 1) throw Error("lost acknowledgement");
        return { ok: true, status: 202, json: async () => ({ alreadyRecorded: true }) };
      });
    vi.stubGlobal("fetch", fetch);
    const body = {
      caseId: "fixture",
      targetId: "target",
      checkpointDigest: "a".repeat(64),
      confirmation: "I_AUTHORIZE_STORED_CLEANUP_ONLY"
    };
    await expect(apiMutation("/api/workflow-mutations/recovery", "POST", body)).rejects.toThrow();
    await apiMutation("/api/workflow-mutations/recovery", "POST", body);
    expect(calls[0]!.requestId).toBe(calls[1]!.requestId);
    expect(String(calls[0]!.requestId)).toMatch(/^[a-f0-9-]{36}$/);
    expect(Object.keys(sessionStorage).some((k) => k.includes("fixture-only"))).toBe(false);
  });
});
