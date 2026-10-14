// @vitest-environment jsdom
import React from "react";
import { fork } from "node:child_process";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { render, screen, cleanup, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./main";
import { TrustedDiscoveryWorkspace } from "./TrustedDiscoveryWorkspace";
import { TrustedDiscoveryStatus, discoveryErrorCopy, type DiscoveryExecutionEvidence } from "./TrustedDiscoveryStatus";
import { DashboardApiError, setActiveOrganizationId, setCsrfToken } from "./api";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); setActiveOrganizationId(""); setCsrfToken(""); });
it("C01 makes Trusted Discovery discoverable without client owner authority", async () => {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => ({ ok: true, status: 200, json: async () => String(input).includes("/api/overview") ? { scans: {}, findings: {}, recentScans: [] } : {} })));
  render(<App />);
  expect(await screen.findByRole("button", { name: "Trusted Discovery" })).toBeTruthy();
});

const org = "11111111-1111-4111-8111-111111111111", target = "22222222-2222-4222-8222-222222222222", scan = "33333333-3333-4333-8333-333333333333", candidate = "a".repeat(64);
const confirmation = "I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET";
const status = { availability: "PREVIEW_ONLY", execution: "UNAVAILABLE", targets: [{ id: target, label: `Local target ${target.slice(0, 8)}` }], scans: [{ id: scan, targetId: target, label: `Completed scan ${scan.slice(0, 8)}` }], truncated: false };
const candidates = { scanId: scan, targetId: target, executionAuthority: "NONE", truncated: false, candidates: [{ candidateId: candidate, label: "Anonymous GET candidate 1", method: "GET", executionAuthority: "NONE" }] };
const facts = { status: "NOT_EXECUTED", attempted: 0, initiated: 0, observed: 0, executionAuthority: "NONE" };
const makeReview = (expiresAt = new Date(Date.now() + 59_000).toISOString()) => ({ reviewId: "r".repeat(43), scanId: scan, candidateId: candidate, targetId: target, routeLabel: "/api/health", method: "GET", effect: "NON_MUTATING", reviewDigest: "d".repeat(64), expiresAt });
const response = (body: unknown, code = 200) => ({ ok: code >= 200 && code < 300, status: code, json: async () => body }) as Response;
function transport(overrides: Partial<Record<string, () => Promise<Response>>> = {}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const path = String(input);
    if (overrides[path]) return overrides[path]!();
    if (path.endsWith("/status")) return response(status);
    if (path.includes("/candidates/")) return response(candidates);
    if (path.endsWith("/review")) return response({ ...facts, review: makeReview() });
    if (path.endsWith("/pre-consent")) { expect(JSON.parse(String(options?.body))).toMatchObject({ confirmation, candidateId: candidate, routeLabel: "/api/health" }); return response({ ...facts, code: "PRECONSENT_RECORDED" }); }
    throw Error("NO_EXECUTION_TRANSPORT");
  });
  vi.stubGlobal("fetch", fetchMock); setActiveOrganizationId(org); setCsrfToken("fixture-csrf");
  return fetchMock;
}
async function choose(user = userEvent.setup()) {
  await user.selectOptions(await screen.findByLabelText("Registered local target"), target);
  await user.selectOptions(screen.getByLabelText("Completed dashboard scan"), scan);
  await waitFor(() => expect((screen.getByLabelText("Retained candidate") as HTMLSelectElement).disabled).toBe(false));
  await user.selectOptions(screen.getByLabelText("Retained candidate"), candidate);
  return user;
}
async function reviewed(user = userEvent.setup()) {
  await choose(user); await user.click(screen.getByRole("button", { name: "Review selected candidate" }));
  await screen.findByRole("heading", { name: "Reviewed candidate" }); return user;
}
it("C04/C05 keyboard review and exact pre-consent submit once and retain no temporary identity", async () => {
  const fetchMock = transport(); const storage = vi.spyOn(Storage.prototype, "setItem");
  render(<TrustedDiscoveryWorkspace organizationId={org} />); const user = await reviewed();
  expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Reviewed candidate" }));
  expect(screen.getByText("/api/health")).toBeTruthy(); expect(screen.getByText("Non-mutating")).toBeTruthy();
  const button = screen.getByRole("button", { name: "Record pre-consent (does not execute)" }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  await user.type(screen.getByLabelText("Type the exact confirmation phrase"), confirmation + " "); expect(button.disabled).toBe(true);
  await user.clear(screen.getByLabelText("Type the exact confirmation phrase")); await user.type(screen.getByLabelText("Type the exact confirmation phrase"), confirmation);
  await user.tab(); expect(document.activeElement).toBe(button); await user.keyboard("{Enter}");
  expect(await screen.findByText("Pre-consent recorded — NOT EXECUTED. No HTTP GET was sent.")).toBeTruthy();
  expect(screen.queryByRole("heading", { name: "Reviewed candidate" })).toBeNull();
  expect(fetchMock.mock.calls.filter(([path]) => String(path).endsWith("/pre-consent"))).toHaveLength(1);
  expect(fetchMock.mock.calls.some(([path]) => String(path).includes("execute"))).toBe(false);
  expect(storage).not.toHaveBeenCalled(); expect(location.hash).not.toContain("review");
  expect(document.activeElement?.textContent).toBe("Pre-consent recorded — NOT EXECUTED. No HTTP GET was sent.");
});
it.each([401, 403, 404, 409, 503])("C01/C08 server denial%d wins over client owner state and raw error text", async (code) => {
  transport({ "/api/trusted-discovery/status": async () => response({ error: "SQLITE secret path C:/Users/HP/private", code: "RAW_SOCKET" }, code) });
  render(<TrustedDiscoveryWorkspace organizationId={org} />);
  const alert = await screen.findByRole("alert"); expect(alert.textContent).not.toMatch(/SQLITE|RAW_SOCKET|private/); expect(document.activeElement).toBe(alert);
  expect(screen.queryByLabelText("Registered local target")).toBeNull(); expect((screen.getByRole("button", { name: "Execute (unavailable)" }) as HTMLButtonElement).disabled).toBe(true);
});
it("C06 review expiry removes identity and typed confirmation at the absolute deadline", async () => {
  transport(); render(<TrustedDiscoveryWorkspace organizationId={org} />); await reviewed();
  const start = Date.now(); vi.spyOn(Date, "now").mockImplementation(() => start + 61_000);
  await waitFor(() => expect(screen.queryByRole("heading", { name: "Reviewed candidate" })).toBeNull(), { timeout: 2000 });
  expect(screen.getByRole("alert").textContent).toContain("Review expired"); expect(screen.queryByLabelText("Type the exact confirmation phrase")).toBeNull();
});
it.each(["routecairn:session-expired", "popstate", "hashchange", "offline", "online", "pagehide", "pageshow"])("C06 discards temporary review on %s without another POST", async (event) => {
  const fetchMock = transport(); render(<TrustedDiscoveryWorkspace organizationId={org} />); await reviewed();
  act(() => window.dispatchEvent(new Event(event)));
  expect(screen.queryByRole("heading", { name: "Reviewed candidate" })).toBeNull(); expect(screen.queryByLabelText("Registered local target")).toBeNull();
  expect(fetchMock.mock.calls.filter(([, options]) => options?.method === "POST")).toHaveLength(1);
});
it("C06 unmount/org change rejects an old async review response", async () => {
  let resolve!: (r: Response) => void;
  const fetchMock = transport({ "/api/trusted-discovery/review": () => new Promise<Response>((done) => { resolve = done; }) });
  const mounted = render(<TrustedDiscoveryWorkspace organizationId={org} />); const user = await choose(); await user.click(screen.getByRole("button", { name: "Review selected candidate" }));
  setActiveOrganizationId("44444444-4444-4444-8444-444444444444"); mounted.rerender(<TrustedDiscoveryWorkspace organizationId="44444444-4444-4444-8444-444444444444" />);
  await act(async () => resolve(response({ ...facts, review: makeReview() })));
  expect(screen.queryByRole("heading", { name: "Reviewed candidate" })).toBeNull(); expect(fetchMock.mock.calls.filter(([path]) => String(path).endsWith("/review"))).toHaveLength(1);
  mounted.unmount();
});
it("C06/C07 interrupted double-click confirmation is UNKNOWN and cannot auto retry", async () => {
  let resolve!: (r: Response) => void;
  const fetchMock = transport({ "/api/trusted-discovery/pre-consent": () => new Promise<Response>((done) => { resolve = done; }) });
  render(<TrustedDiscoveryWorkspace organizationId={org} />); const user = await reviewed(); await user.type(screen.getByLabelText("Type the exact confirmation phrase"), confirmation);
  await user.dblClick(screen.getByRole("button", { name: "Record pre-consent (does not execute)" }));
  await user.click(screen.getByRole("button", { name: "Discard displayed review" }));
  expect(screen.getByRole("alert").textContent).toContain("outcome UNKNOWN");
  await act(async () => resolve(response({ ...facts, code: "PRECONSENT_RECORDED" })));
  expect(screen.queryByText("Pre-consent recorded — NOT EXECUTED. No HTTP GET was sent.")).toBeNull();
  expect(fetchMock.mock.calls.filter(([path]) => String(path).endsWith("/pre-consent"))).toHaveLength(1);
});
it("C07 lost confirmation response remains unknown without invented no-operation result", async () => {
  const fetchMock = transport({ "/api/trusted-discovery/pre-consent": async () => { throw Error("socket secret"); } });
  render(<TrustedDiscoveryWorkspace organizationId={org} />); const user = await reviewed(); await user.type(screen.getByLabelText("Type the exact confirmation phrase"), confirmation); await user.click(screen.getByRole("button", { name: "Record pre-consent (does not execute)" }));
  expect((await screen.findByRole("alert")).textContent).toContain("UNKNOWN"); expect(screen.queryByRole("heading", { name: "Reviewed candidate" })).toBeNull(); expect(fetchMock.mock.calls.filter(([path]) => String(path).endsWith("/pre-consent"))).toHaveLength(1);
});
it("C03/C09 empty safe metadata and malformed server fields never enable review", async () => {
  transport({ "/api/trusted-discovery/status": async () => response({ ...status, targets: [], scans: [] }) });
  const mounted = render(<TrustedDiscoveryWorkspace organizationId={org} />); expect(await screen.findByText("No registered authorized local targets are available in this organization.")).toBeTruthy(); mounted.unmount();
  transport({ "/api/trusted-discovery/status": async () => response({ ...status, targets: [{ id: target, label: "https://secret.example/?token=secret" }] }) });
  render(<TrustedDiscoveryWorkspace organizationId={org} />); expect((await screen.findByRole("alert")).textContent).toContain("UNKNOWN"); expect(screen.queryByLabelText("Registered local target")).toBeNull();
});
it.each([
  [{ attempted: 1, initiated: 0, responseObserved: 0 }, "Attempted — zero wire initiation"],
  [{ attempted: 1, initiated: 1, responseObserved: 0 }, "Native request initiated — inconclusive"],
  [{ attempted: 1, initiated: 1, responseObserved: 1 }, "Response observed"],
  [{ attempted: 1, initiated: 1, responseObserved: 1, cleanup: "FAILED" }, "Cleanup FAILED — unavailable"],
  [{ attempted: 1, initiated: 1, responseObserved: 1, outcomePersistence: "UNKNOWN" }, "Custody UNKNOWN — unavailable"],
  [{ attempted: 0, initiated: 1, responseObserved: 1 }, "Custody UNKNOWN — unavailable"]
])("C08 test-only typed result adapter preserves native fact distinctions %j", async (facts, title) => {
  async function testOnlyAdapter(): Promise<DiscoveryExecutionEvidence> { return { assessment: "NOT_ASSESSED", outcomePersistence: "COMMITTED", cleanup: "CONFIRMED", ...facts } as DiscoveryExecutionEvidence; }
  render(<TrustedDiscoveryStatus evidence={await testOnlyAdapter()} />);
  expect(screen.getByRole("heading", { name: title })).toBeTruthy(); expect(screen.getByText("Assessment: not assessed. These facts are not a security finding.")).toBeTruthy(); expect(screen.queryByRole("button", { name: /retry|resend/i })).toBeNull();
});
it("C08 denial map never uses arbitrary server exception strings", () => {
  expect(discoveryErrorCopy(new DashboardApiError("untrusted <script> secrets", "UNKNOWN", [], undefined, 503))).toContain("operator investigation");
  expect(discoveryErrorCopy(new Error("raw secrets"))).not.toContain("raw secrets");
});
it("C06 target change discards exact reviewed identity and confirmation", async () => {
  const fetchMock = transport(); render(<TrustedDiscoveryWorkspace organizationId={org} />); const user = await reviewed();
  await user.type(screen.getByLabelText("Type the exact confirmation phrase"), "partial confirmation");
  await user.selectOptions(screen.getByLabelText("Registered local target"), "");
  expect(screen.queryByRole("heading", { name: "Reviewed candidate" })).toBeNull(); expect(screen.queryByLabelText("Type the exact confirmation phrase")).toBeNull();
  expect(fetchMock.mock.calls.filter(([, options]) => options?.method === "POST")).toHaveLength(1);
});
it("C08 missing cleanup remains unavailable despite a committed response fact", () => {
  render(<TrustedDiscoveryStatus evidence={{ attempted: 1, initiated: 1, responseObserved: 1, assessment: "NOT_ASSESSED", outcomePersistence: "COMMITTED" }} />);
  expect(screen.getByRole("heading", { name: "Cleanup UNKNOWN — unavailable" })).toBeTruthy(); expect(screen.getByRole("alert")).toBeTruthy();
});
it("C09 narrow, reduced-motion and contrast declarations preserve readable keyboard controls", () => {
  const css = readFileSync("apps/dashboard-ui/src/styles.css", "utf8");
  expect(css).toContain(".trusted-discovery-workspace :focus-visible"); expect(css).toContain("outline: 3px solid #174a8b");
  expect(css).toContain("@media (max-width: 640px)"); expect(css).toContain(".trusted-discovery-facts { grid-template-columns: minmax(0, 1fr)"); expect(css).toContain("prefers-reduced-motion: reduce");
  const lum = (hex: string) => hex.match(/[a-f0-9]{2}/g)!.map((c) => parseInt(c, 16) / 255).map((c) => c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4).reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i]!, 0);
  for (const [fg, bg] of [["465367", "e6ebf1"], ["7b1717", "fff2f2"], ["17202a", "ffffff"]]) expect((lum(bg!) + .05) / (lum(fg!) + .05)).toBeGreaterThanOrEqual(4.5);
});
it("C04/C05 real native dashboard review through UI utilities produces zero actual target GET", async () => {
  const child = fork(resolve("tests/dashboard/trusted-discovery-stage-c.fixture.ts"), { execArgv: ["--import", "tsx"], stdio: ["ignore", "inherit", "inherit", "ipc"] });
  interface FixtureView { url: string; org: string; target: string; scan: string; candidate: string; cookie: string; csrf: string; origin: string }
  let ended = false;
  const exited = new Promise<number | null>((done) => child.once("exit", (code) => { ended = true; done(code); }));
  const result = new Promise<{ receipts: number; preconsents: number }>((done) => child.on("message", (value) => { if (value && typeof value === "object" && "receipts" in value) done(value as { receipts: number; preconsents: number }); }));
  try {
    const f = await new Promise<FixtureView>((done, reject) => { child.once("error", reject); child.once("exit", () => reject(Error("NATIVE_FIXTURE_STARTUP_FAILED"))); child.on("message", (value) => { if (value && typeof value === "object" && "url" in value) done(value as FixtureView); }); });
    const nativeFetch = globalThis.fetch;
    setActiveOrganizationId(f.org); setCsrfToken(f.csrf);
    const wire = vi.fn((input: RequestInfo | URL, options: RequestInit = {}) => nativeFetch(f.url + String(input), { ...options, headers: { ...options.headers, cookie: f.cookie, origin: f.origin } }));
    vi.stubGlobal("fetch", wire); const mounted = render(<TrustedDiscoveryWorkspace organizationId={f.org} />); const user = userEvent.setup();
    await user.selectOptions(await screen.findByLabelText("Registered local target"), f.target); await user.selectOptions(screen.getByLabelText("Completed dashboard scan"), f.scan);
    await waitFor(() => expect((screen.getByLabelText("Retained candidate") as HTMLSelectElement).disabled).toBe(false));
    await user.selectOptions(screen.getByLabelText("Retained candidate"), f.candidate); await user.click(screen.getByRole("button", { name: "Review selected candidate" }));
    await screen.findByRole("heading", { name: "Reviewed candidate" }); await user.type(screen.getByLabelText("Type the exact confirmation phrase"), confirmation); await user.click(screen.getByRole("button", { name: "Record pre-consent (does not execute)" }));
    await screen.findByText("Pre-consent recorded — NOT EXECUTED. No HTTP GET was sent.");
    expect(wire.mock.calls.filter(([path]) => String(path).endsWith("/pre-consent"))).toHaveLength(1); mounted.unmount();
    child.send("close"); expect(await result).toEqual({ receipts: 0, preconsents: 1 }); expect(await exited).toBe(0);
  } finally { cleanup(); if (!ended && child.connected) child.send("close"); await exited; }
});
