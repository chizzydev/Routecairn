// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingsCommandCenter } from "../../apps/dashboard-ui/src/FindingsCommandCenter";

const finding = {
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", title: "Hostile <img src=x onerror=alert(1)>",
  module: "authorization-matrix-testing", category: "Authorization", endpoint: "https://app.test/api/orders/:id?token=<redacted>",
  method: "GET", severity: "High", effectiveSeverity: "High", confidence: "High",
  reviewStatus: "UNREVIEWED", remediationStatus: "OPEN", firstSeenAt: "2026-01-01T00:00:00.000Z",
  lastSeenAt: "2026-01-02T00:00:00.000Z", occurrenceCount: 2, retestStatus: "NOT_RETESTED",
  proofReadiness: "MISSING_REVIEW", newOccurrenceKind: "NEW_OCCURRENCE", rowVersion: 1,
  projectName: "Payments", targetName: "Accounts API"
};

const detail = {
  finding,
  description: "Needs manual verification.",
  occurrences: [{ id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", scan_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", created_at: "2026-01-02T00:00:00.000Z", severity: "High", confidence: "High", evidence_summary: "GET safe endpoint", safe_endpoint: finding.endpoint, safe_actor_relationship: "Account B", safe_tenant_or_role_boundary: "role:user", safe_state_boundary: "active", description: "Denied expected; allowed observed", limitations: "Needs manual verification.", reproduction_steps: "Repeat the exact controlled GET." }],
  occurrenceDifferences: [],
  evidence: [{ id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", finding_occurrence_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", evidence_type: "HTTP", evidence_level: "normal", safe_summary: "Escaped <script>alert(1)</script>", safe_structured_data_json: JSON.stringify({ status: 200, authorization: "<redacted>" }) }],
  reviews: [], remediationHistory: [], notes: [], retests: [], duplicates: [], related: []
};

describe("Findings Command Center UI", () => {
  let requests: Array<{ url: string; method: string; body?: unknown }>;

  beforeEach(() => {
    requests = [];
    vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requests.push({ url, method, ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
      if (url === `/api/findings/${finding.id}`) return response(detail);
      if (url.endsWith("/retest-candidates")) return response({ scans: [] });
      if (url === "/api/finding-assignees") return response({ users: [] });
      if (url === "/api/finding-views" && method === "POST") return response({ viewId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }, 201);
      if (url === "/api/finding-views") return response({ views: [] });
      if (url.includes("/api/findings/queue") || url.startsWith("/api/findings?")) return response({ findings: [finding], page: 1, pageSize: 25, total: 1, totalPages: 1 });
      if (url.includes("/review")) return response({ finding: { ...finding, reviewStatus: "CONFIRMED", rowVersion: 2 } });
      if (url === "/api/findings/bulk-review") return response({ succeeded: [finding.id], failed: [] });
      return response({ ok: true });
    }));
  });

  afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("renders a dense server-backed table and composes filters and queue mode", async () => {
    render(<FindingsCommandCenter />);
    expect(await screen.findByRole("table")).toBeTruthy();
    expect(screen.getByText("Payments")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "High" } });
    await waitFor(() => expect(requests.some((item) => item.url.includes("severity=High"))).toBe(true));
    fireEvent.click(screen.getByRole("tab", { name: "Review Queue" }));
    await waitFor(() => expect(requests.some((item) => item.url.includes("/api/findings/queue?mode=UNREVIEWED"))).toBe(true));
  });

  it("renders hostile evidence inertly and keeps review shortcuts disabled while typing", async () => {
    render(<FindingsCommandCenter />);
    fireEvent.click(await screen.findByRole("button", { name: finding.title }));
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
    expect(await screen.findByText(/Escaped <script>/)).toBeTruthy();
    expect(document.querySelector("script")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    const reason = screen.getByLabelText("Safe reason");
    fireEvent.keyDown(reason, { key: "c" });
    expect(requests.filter((item) => item.url.endsWith("/review"))).toHaveLength(0);
  });

  it("performs bounded bulk review with explicit confirmation and row versions", async () => {
    render(<FindingsCommandCenter />);
    const table = await screen.findByRole("table");
    fireEvent.click(within(table).getByLabelText(`Select ${finding.title}`));
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "CONFIRMED" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply to Selection" }));
    await waitFor(() => expect(requests.some((item) => item.url === "/api/findings/bulk-review" && item.method === "POST")).toBe(true));
    const mutation = requests.find((item) => item.url === "/api/findings/bulk-review")!;
    expect(mutation.body).toMatchObject({ findingIds: [finding.id], newStatus: "CONFIRMED", versions: { [finding.id]: 1 } });
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("1 selected finding"));
  });

  it("reorders visible columns with accessible controls", async () => {
    render(<FindingsCommandCenter />);
    await screen.findByRole("table");
    fireEvent.click(screen.getByText("Columns"));
    const moveTitleEarlier = screen.getByRole("button", { name: "Move Title earlier" });
    fireEvent.click(moveTitleEarlier);
    const headers = within(screen.getByRole("table")).getAllByRole("columnheader").map((item) => item.textContent);
    expect(headers.indexOf("Title")).toBeLessThan(headers.indexOf("Remediation"));
    fireEvent.click(screen.getByRole("button", { name: "Hide Confidence column" }));
    expect(within(screen.getByRole("table")).queryByText("Confidence")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Add Confidence" }));
    expect(within(screen.getByRole("table")).getByText("Confidence")).toBeTruthy();
  });

  it("saves the visible filter model using the canonical persisted-view contract", async () => {
    render(<FindingsCommandCenter />);
    await screen.findByRole("table");
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "High" } });
    fireEvent.change(screen.getByLabelText("Review"), { target: { value: "IN_REVIEW" } });
    fireEvent.change(screen.getByLabelText("View name"), { target: { value: "Manual QA Columns" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Current View" }));

    await waitFor(() => expect(requests.some((item) => item.url === "/api/finding-views" && item.method === "POST")).toBe(true));
    const mutation = requests.find((item) => item.url === "/api/finding-views" && item.method === "POST")!;
    expect(mutation.body).toMatchObject({
      name: "Manual QA Columns",
      query: { severity: "High", reviewStatus: "IN_REVIEW", sort: "last_seen_desc" }
    });
    expect((mutation.body as { query: Record<string, unknown> }).query).not.toHaveProperty("q");
    expect((mutation.body as { query: Record<string, unknown> }).query).not.toHaveProperty("projectId");
    expect((mutation.body as { query: Record<string, unknown> }).query).not.toHaveProperty("evidence");
    expect(await screen.findByText("Finding view saved.")).toBeTruthy();
  });
});

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
