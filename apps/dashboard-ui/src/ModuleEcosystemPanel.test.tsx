// @vitest-environment jsdom
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ModuleEcosystemPanel } from "./ModuleEcosystemPanel";
import { apiMutation } from "./api";
vi.mock("./api", () => ({ apiMutation: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
const approved = { id: "module-id", moduleId: "reference-detector", version: "1.0.0", status: "APPROVED", packageDigest: "a".repeat(64), description: "Reviewed detector", capabilities: { requestBroker: { maxRequests: 1 } }, signature: { signed: true, publisher: "fixture-publisher", expiresAt: "2026-10-03T00:00:00Z" } };
describe("module ecosystem review UI", () => {
  it("registers a signed bundle separately from approval and exposes the package contract", async () => {
    const run = vi.fn().mockResolvedValue(undefined); render(<ModuleEcosystemPanel data={{ modules: [{ ...approved, status: "REGISTERED" }] }} organizationId="org" canManage run={run} />);
    fireEvent.change(screen.getByLabelText("Installed package directory"), { target: { value: "module/root" } }); fireEvent.change(screen.getByLabelText("Verified signed bundle path"), { target: { value: "module/bundle.json" } });
    fireEvent.click(screen.getByText("Register package for review")); await waitFor(() => expect(run).toHaveBeenCalledWith("/api/operations/modules", expect.objectContaining({ bundlePath: "module/bundle.json", packageDirectory: "module/root" }), expect.any(String)));
    expect(run).toHaveBeenCalledTimes(1); expect(screen.getByText(/Signed by fixture-publisher/)).toBeTruthy(); expect(screen.getByText("Review permissions and contracts")).toBeTruthy();
  });
  it("blocks execution without target approval and displays the returned broker evidence", async () => {
    render(<ModuleEcosystemPanel data={{ modules: [approved] }} organizationId="org" canManage run={vi.fn()} />);
    fireEvent.click(screen.getByText("Execute reference-detector")); await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("digest-bound")); expect(apiMutation).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Reviewed broker binding JSON"), { target: { value: '{"approval":{"packageDigest":"reviewed"}}' } });
    vi.mocked(apiMutation).mockResolvedValue({ result: { observations: [], capabilitySummary: { transmittedRequests: 1 } } }); fireEvent.click(screen.getByText("Execute reference-detector"));
    await waitFor(() => expect(screen.getByLabelText("Module execution result").textContent).toContain("transmittedRequests"));
  });
  it("shows read-only review data without management controls", () => {
    render(<ModuleEcosystemPanel data={{ modules: [approved] }} organizationId="org" canManage={false} run={vi.fn()} />);
    expect(screen.queryByText("Execute reference-detector")).toBeNull(); expect(screen.queryByText("Disable reference-detector")).toBeNull(); expect(screen.queryByText("Register package for review")).toBeNull(); expect(screen.getByText(approved.packageDigest)).toBeTruthy();
  });
});
