import React from "react";

export interface BrowserBoundaryView {
  state: "STARTING" | "HEALTHY" | "DEGRADED" | "STOPPED";
  generation: number;
  connectionsAttempted: number;
  connectionsAllowed: number;
  connectionsBlocked: number;
  activeConnections: number;
  pinnedDestinationCount: number;
  lastFailureCode?: string;
  coverage: string[];
}

export function BrowserNetworkDiagnostics({ value }: { value?: BrowserBoundaryView }) {
  if (!value) return null;
  return <section className="browser-network-diagnostics" aria-label="Browser network isolation">
    <h3>Browser Network Isolation</h3>
    <div className="cards">
      <div className={`metric ${value.state === "DEGRADED" ? "danger-metric" : ""}`}><strong>{value.state}</strong><span>Proxy health</span></div>
      <div className="metric"><strong>{value.generation + 1}</strong><span>Boundary generation</span></div>
      <div className="metric"><strong>{value.connectionsAllowed}/{value.connectionsAttempted}</strong><span>Pinned connections</span></div>
      <div className="metric"><strong>{value.connectionsBlocked}</strong><span>Connection-time blocks</span></div>
      <div className="metric"><strong>{value.activeConnections}</strong><span>Active tunnels</span></div>
      <div className="metric"><strong>{value.pinnedDestinationCount}</strong><span>Destination fingerprints</span></div>
    </div>
    {value.lastFailureCode && <p className="notice"><strong>Latest boundary result:</strong> {value.lastFailureCode}</p>}
    <p className="muted">Connection-time DNS pinning covers {value.coverage.join(", ")}. Destination IPs and proxy credentials are never exposed in dashboard events.</p>
  </section>;
}
