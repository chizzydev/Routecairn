// @vitest-environment jsdom
import React from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App, ProofPacks } from "./main";
import { apiMutation, setCsrfToken } from "./api";

describe("RouteCairn dashboard UI", () => {
  it("renders the navigation shell after session check", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        return {
          ok: true,
          json: async () => (url.includes("/api/overview") ? { scans: { total: 0, queued: 0, running: 0, completed: 0, failed: 0, interrupted: 0 }, findings: { open: 0, unreviewed: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, resolved: 0, reopened: 0 }, recentScans: [] } : url.includes("/api/scans") ? { scans: [] } : {})
        };
      })
    );
    const rendered = render(<App />);
    expect(await screen.findByRole("button", { name: "Scans" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "New Scan" })).toBeTruthy();
    rendered.unmount();
    vi.unstubAllGlobals();
  });

  it("renders a persistent emergency alert for unresolved controlled-mutation cleanup", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.includes("/api/auth/session")
        ? { principal: { login: "owner", role: "OWNER" } }
        : url.includes("/api/workflow-mutations/status") ? { cases: [], jobs: [] }
        : url.includes("/api/targets") ? { targets: [] }
        : url.includes("/api/credential-profiles") ? { profiles: [] }
        : url.includes("/api/offensive/status")
          ? {
              globalMutationActive: true,
              cleanupRequired: 1,
              modes: { CONTROLLED_MUTATION: "AVAILABLE" },
              cases: [{ journalId: "journal-1", caseId: "role-mutation-017", stage: "CLEANUP_FAILED", outcome: "CLEANUP_FAILED", timestamp: "2026-08-22T00:00:00.000Z", targetOrigin: "https://example.test", recoveryBundleAvailable: true, warning: "UNRESOLVED CLEANUP — RouteCairn cannot prove the original target state was restored." }]
            }
          : { scans: { total: 0, queued: 0, running: 0, completed: 0, failed: 0, interrupted: 0 }, findings: { open: 0, unreviewed: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, resolved: 0, reopened: 0 }, recentScans: [] };
      return { ok: true, status: 200, json: async () => body } as Response;
    }));
    const user = userEvent.setup();
    const rendered = render(<App />);
    await user.click(await screen.findByRole("button", { name: "Offensive Safety" }));

    expect((await screen.findByRole("alert")).textContent).toContain("UNRESOLVED CLEANUP — TARGET STATE MAY STILL BE MODIFIED");
    expect(screen.getByText("role-mutation-017")).toBeTruthy();
    expect(screen.getAllByText("AVAILABLE").length).toBeGreaterThan(0);
    expect(screen.getByText("BLOCKED")).toBeTruthy();
    rendered.unmount();
    vi.unstubAllGlobals();
  });

  it("labels compact scan cards without separating headers from values", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const body = url.includes("/api/overview")
          ? {
              scans: { total: 1, queued: 0, running: 0, completed: 1, failed: 0, interrupted: 0 },
              findings: { open: 0, unreviewed: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, resolved: 0, reopened: 0 },
              recentScans: [{
                id: "scan-1", shortId: "scan-1", status: "COMPLETED", target: "Northstar Accounts",
                profile: "authenticated", evidenceLevel: "normal", createdAt: "2026-08-19T06:42:43.043Z",
                progressPercent: 100, plannedModuleCount: 1, completedModuleCount: 1, failedModuleCount: 0,
                findingCount: 0
              }]
            }
          : url.includes("/api/auth/session") ? { principal: { login: "owner", role: "OWNER" } } : {};
        return { ok: true, json: async () => body };
      })
    );

    const rendered = render(<App />);
    const scan = await screen.findByRole("button", { name: "Northstar Accounts" });
    expect(scan.closest("[data-label]")?.getAttribute("data-label")).toBe("Scan");
    expect(rendered.container.querySelector('.scan-row [data-label="Status"]')).toBeTruthy();
    expect(rendered.container.querySelector('.scan-row [data-label="Actions"]')).toBeTruthy();
    rendered.unmount();
    vi.unstubAllGlobals();
  });

  it("restores the session-scoped CSRF token for mutations after a refresh", async () => {
    setCsrfToken("");
    window.sessionStorage.setItem("routecairn.dashboard.csrf", "refresh-safe-csrf-token");
    const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ saved: true }) }));
    vi.stubGlobal("fetch", fetchMock);

    await apiMutation("/api/finding-views", "POST", { name: "Manual QA Columns" });

    const request = (fetchMock.mock.calls as unknown as Array<[RequestInfo | URL, RequestInit | undefined]>)[0];
    expect(request?.[1]?.headers).toMatchObject({ "x-csrf-token": "refresh-safe-csrf-token" });
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("reissues CSRF protection for an authenticated direct navigation", async () => {
    setCsrfToken("");
    window.sessionStorage.clear();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = url === "/api/auth/csrf"
        ? { csrfToken: "direct-navigation-csrf" }
        : url === "/api/auth/session"
          ? { principal: { login: "owner", role: "OWNER" } }
          : url === "/api/overview"
            ? { scans: { total: 0, queued: 0, running: 0, completed: 0, failed: 0, interrupted: 0 }, findings: { open: 0, unreviewed: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, resolved: 0, reopened: 0 }, recentScans: [] }
            : { saved: true };
      return { ok: true, status: 200, json: async () => body } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    const rendered = render(<App />);
    await screen.findByRole("button", { name: "Projects" });
    await apiMutation("/api/finding-views", "POST", { name: "Direct navigation" });

    const mutation = (fetchMock.mock.calls as unknown as Array<[RequestInfo | URL, RequestInit | undefined]>).find(([url]) => String(url) === "/api/finding-views");
    expect(mutation?.[1]?.headers).toMatchObject({ "x-csrf-token": "direct-navigation-csrf" });
    rendered.unmount();
    vi.unstubAllGlobals();
  });

  it("exchanges a bootstrap token supplied by same-page hash navigation", async () => {
    history.replaceState(null, "", "/");
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      return {
        ok: true,
        json: async () => url.includes("/api/session/bootstrap")
          ? { csrfToken: "hash-navigation-csrf" }
          : url.includes("/api/auth/session")
            ? { principal: { login: "owner", role: "OWNER" } }
            : { scans: { total: 0, queued: 0, running: 0, completed: 0, failed: 0, interrupted: 0 }, findings: { open: 0, unreviewed: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, resolved: 0, reopened: 0 }, recentScans: [] }
      };
    });
    vi.stubGlobal("fetch", fetchMock);
    const rendered = render(<App />);
    await screen.findByRole("button", { name: "Findings" });

    window.location.hash = "bootstrap=same-page-token";
    window.dispatchEvent(new HashChangeEvent("hashchange"));

    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url) === "/api/session/bootstrap")).toBe(true));
    await waitFor(() => expect(window.location.hash).toBe(""));
    rendered.unmount();
    vi.unstubAllGlobals();
  });

  it("generates a proof pack with a safe default title and selected confirmed finding", async () => {
    const findingId = "11111111-1111-4111-8111-111111111111";
    const requests: Array<{ url: string; method: string; body?: unknown }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requests.push({ url, method, ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
      const body = url.startsWith("/api/findings")
        ? { findings: [{ id: findingId, title: "Confirmed authorization issue", severity: "High", endpoint: "https://example.test/account" }] }
        : url === "/api/proof-packs" && method === "POST"
          ? { proofPackId: "22222222-2222-4222-8222-222222222222" }
          : { proofPacks: [] };
      return { ok: true, status: method === "POST" ? 201 : 200, json: async () => body };
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    const rendered = render(<ProofPacks />);

    await user.click(await screen.findByRole("checkbox", { name: /Confirmed authorization issue/ }));
    await user.click(screen.getByRole("button", { name: "Generate Proof Pack" }));

    expect(await screen.findByText(/Generated proof pack 22222222/)).toBeTruthy();
    const createRequest = requests.find((request) => request.url === "/api/proof-packs" && request.method === "POST");
    expect(createRequest?.body).toEqual({ title: "Confirmed findings proof pack", findingIds: [findingId] });
    rendered.unmount();
    vi.unstubAllGlobals();
  });

  it("blocks proof-pack generation when the required title is blank", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => ({
      ok: true,
      status: 200,
      json: async () => String(input).startsWith("/api/findings")
        ? { findings: [{ id: "11111111-1111-4111-8111-111111111111", title: "Confirmed authorization issue", severity: "High", endpoint: "https://example.test/account" }] }
        : { proofPacks: [] }
    }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    const rendered = render(<ProofPacks />);

    const title = screen.getByRole("textbox", { name: /Title/ });
    await user.clear(title);
    await user.click(await screen.findByRole("checkbox", { name: /Confirmed authorization issue/ }));
    await user.click(screen.getByRole("button", { name: "Generate Proof Pack" }));

    expect((fetchMock.mock.calls as unknown as Array<[RequestInfo | URL, RequestInit | undefined]>).filter(([url, init]) => String(url) === "/api/proof-packs" && init?.method === "POST")).toHaveLength(0);
    rendered.unmount();
    vi.unstubAllGlobals();
  });
});
