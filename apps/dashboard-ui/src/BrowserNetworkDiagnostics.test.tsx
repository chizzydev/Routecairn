// @vitest-environment jsdom
import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BrowserNetworkDiagnostics } from "./BrowserNetworkDiagnostics";

describe("BrowserNetworkDiagnostics", () => {
  it("shows connection-time health, counters, coverage, and safe failure codes", () => {
    render(<BrowserNetworkDiagnostics value={{ state: "DEGRADED", generation: 1, connectionsAttempted: 4, connectionsAllowed: 2, connectionsBlocked: 2, activeConnections: 0, pinnedDestinationCount: 1, lastFailureCode: "DNS_PRIVATE_ORIGIN_NOT_ALLOWED", coverage: ["pages", "frames", "workers", "downloads", "websockets", "browser-api"] }} />);
    expect(screen.getByRole("region", { name: "Browser network isolation" })).toBeTruthy();
    expect(screen.getByText("DEGRADED")).toBeTruthy();
    expect(screen.getByText("2/4")).toBeTruthy();
    expect(screen.getByText("DNS_PRIVATE_ORIGIN_NOT_ALLOWED")).toBeTruthy();
    expect(screen.getByText(/websockets/)).toBeTruthy();
  });
});
