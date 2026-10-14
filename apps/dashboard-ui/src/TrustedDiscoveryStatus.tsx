import React from "react";
import { DashboardApiError } from "./api";

export function discoveryErrorCopy(error: unknown): string {
  const status = error instanceof DashboardApiError ? error.statusCode : undefined;
  return ({
    400: "The selection is invalid. Refresh the available review metadata.",
    401: "Your owner session is unavailable or expired. Sign in again before reviewing.",
    403: "An active owner membership in the selected organization is required.",
    404: "Preview is OFF or unavailable in this dashboard mode. Execution is unavailable.",
    409: "The review or source is expired, stale, already used or unavailable. Select a fresh retained scan.",
    413: "The review input exceeds the permitted size. Refresh the available metadata.",
    503: "Unavailable — operator investigation required. Storage, custody or cleanup could not be verified."
  } as Record<number, string>)[status ?? 0] ?? "Request outcome UNKNOWN. Check your session and refresh read-only metadata. Do not repeat a confirmation automatically.";
}
export interface DiscoveryExecutionEvidence {
  attempted: number;
  initiated: number;
  responseObserved: number;
  assessment: "NOT_ASSESSED";
  cleanup?: "FAILED" | "CONFIRMED" | "NOT_REQUIRED";
  outcomePersistence?: "COMMITTED" | "UNKNOWN";
}
/** Pure presentation boundary. The shipping workspace supplies no native result.
 * Test-only adapters exercise facts without adding an execution transport. */
export function TrustedDiscoveryStatus({ evidence }: { evidence?: DiscoveryExecutionEvidence }) {
  if (!evidence) return <section className="trusted-discovery-lock" aria-labelledby="discovery-execution-title">
    <h3 id="discovery-execution-title">Execution unavailable</h3>
    <p id="discovery-execution-explanation">This workspace records review and historical pre-consent only. Execution requires a separately reviewed deployment and independent witness custody.</p>
    <button type="button" disabled aria-describedby="discovery-execution-explanation">Execute (unavailable)</button>
    <p>No HTTP GET is sent by this workspace.</p>
  </section>;
  const valid = [evidence.attempted, evidence.initiated, evidence.responseObserved].every((v) => v === 0 || v === 1) && evidence.responseObserved <= evidence.initiated && evidence.initiated <= evidence.attempted && evidence.assessment === "NOT_ASSESSED";
  const cleanupUnknown = evidence.cleanup !== "CONFIRMED" && evidence.cleanup !== "NOT_REQUIRED" && evidence.cleanup !== "FAILED";
  const blocked = !valid || evidence.cleanup === "FAILED" || cleanupUnknown || evidence.outcomePersistence !== "COMMITTED";
  const title = !valid ? "Custody UNKNOWN — unavailable" : evidence.cleanup === "FAILED" ? "Cleanup FAILED — unavailable" : evidence.outcomePersistence !== "COMMITTED" ? "Custody UNKNOWN — unavailable" : cleanupUnknown ? "Cleanup UNKNOWN — unavailable" : evidence.responseObserved ? "Response observed" : evidence.initiated ? "Native request initiated — inconclusive" : evidence.attempted ? "Attempted — zero wire initiation" : "Not executed";
  return <section className={blocked ? "trusted-discovery-alert" : "trusted-discovery-lock"} aria-labelledby="discovery-evidence-title" role={blocked ? "alert" : "status"} aria-live={blocked ? "assertive" : "polite"}>
    <h3 id="discovery-evidence-title">{title}</h3>
    {blocked && <p>Operator investigation required. No resend or retry permission is granted.</p>}
    {valid && <dl className="trusted-discovery-facts">
      <dt>Attempted</dt><dd>{evidence.attempted} — irreversible possibly-spent commitment; not wire proof.</dd>
      <dt>Initiated</dt><dd>{evidence.initiated} — native request-start fact.</dd>
      <dt>Response observed</dt><dd>{evidence.responseObserved} — status fact only; no vulnerability assessment.</dd>
      <dt>Outcome persistence</dt><dd>{evidence.outcomePersistence === "COMMITTED" ? "COMMITTED — signed outcome persisted" : "UNKNOWN — no committed evidence claim"}</dd>
      <dt>Cleanup</dt><dd>{evidence.cleanup === "CONFIRMED" ? "Confirmed" : evidence.cleanup === "NOT_REQUIRED" ? "Not required" : evidence.cleanup === "FAILED" ? "FAILED" : "Unknown"}</dd>
    </dl>}
    <p>Assessment: not assessed. These facts are not a security finding.</p>
  </section>;
}
