import React, { useEffect, useRef, useState } from "react";
import { apiGet, apiMutation, getActiveOrganizationId } from "./api";
import { TrustedDiscoveryStatus, discoveryErrorCopy } from "./TrustedDiscoveryStatus";
import type { DiscoveryWorkspaceStatus, DiscoveryCandidateProjection } from "../../../src/dashboard/execution/TrustedDiscoveryProjection";

const phrase = "I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET";
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
interface PublicReview {
  reviewId: string; scanId: string; candidateId: string; targetId: string;
  routeLabel: string; method: "GET"; effect: "NON_MUTATING"; reviewDigest: string; expiresAt: string;
}
function exactReview(value: PublicReview, scanId: string, candidateId: string, targetId: string): boolean {
  return !!value && Object.keys(value).sort().join(",") === "candidateId,effect,expiresAt,method,reviewDigest,reviewId,routeLabel,scanId,targetId" && /^[A-Za-z0-9_-]{43}$/.test(value.reviewId) && value.scanId === scanId && value.targetId === targetId && value.candidateId === candidateId && /^[a-f0-9]{64}$/.test(value.reviewDigest) && value.method === "GET" && value.effect === "NON_MUTATING" && typeof value.routeLabel === "string" && value.routeLabel.length <= 160 && /^\/(?:[a-z][a-z_-]{0,31}\/?)*$/.test(value.routeLabel) && Number.isFinite(Date.parse(value.expiresAt)) && Date.parse(value.expiresAt) > Date.now() && Date.parse(value.expiresAt) <= Date.now() + 60_000;
}
function validStatus(value: DiscoveryWorkspaceStatus): boolean {
  return !!value && value.availability === "PREVIEW_ONLY" && value.execution === "UNAVAILABLE" && typeof value.truncated === "boolean" && Array.isArray(value.targets) && value.targets.length <= 64 && value.targets.every((t) => uuid.test(t.id) && t.label === `Local target ${t.id.slice(0, 8)}`) && Array.isArray(value.scans) && value.scans.length <= 64 && value.scans.every((s) => uuid.test(s.id) && value.targets.some((t) => t.id === s.targetId) && s.label === `Completed scan ${s.id.slice(0, 8)}`);
}
export function TrustedDiscoveryWorkspace({ organizationId }: { organizationId: string }) {
  const [status, setStatus] = useState<DiscoveryWorkspaceStatus>();
  const [targetId, setTargetId] = useState("");
  const [scanId, setScanId] = useState("");
  const [candidateId, setCandidateId] = useState("");
  const [candidates, setCandidates] = useState<DiscoveryCandidateProjection>();
  const [review, setReview] = useState<PublicReview>();
  const [confirmation, setConfirmation] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const generation = useRef(0), pending = useRef<"read" | "write" | null>(null), controller = useRef<AbortController | null>(null);
  const reviewHeading = useRef<HTMLHeadingElement>(null), notice = useRef<HTMLParagraphElement>(null);
  function clearReview() { setReview(undefined); setConfirmation(""); setSeconds(0); }
  function interrupt(all: boolean, copy = "Selection changed. Review state discarded.") {
    const unknown = pending.current === "write";
    generation.current++; controller.current?.abort(); controller.current = null; pending.current = null;
    setBusy(false); clearReview(); setCandidates(undefined); setCandidateId("");
    if (all) { setStatus(undefined); setTargetId(""); setScanId(""); }
    setError(unknown); setMessage(unknown ? "Request interrupted — outcome UNKNOWN. A review or pre-consent may have been recorded. No target GET is available. Do not repeat the confirmation automatically." : copy);
  }
  function begin(kind: "read" | "write") {
    if (pending.current || getActiveOrganizationId() !== organizationId) return undefined;
    const token = ++generation.current;
    controller.current = new AbortController(); pending.current = kind; setBusy(true); setError(false); setMessage(kind === "write" ? "Recording historical intention; execution remains unavailable." : "Loading read-only review metadata…");
    return { token, signal: controller.current.signal };
  }
  function current(token: number) { return generation.current === token && getActiveOrganizationId() === organizationId; }
  function finish(token: number) { if (current(token)) { pending.current = null; controller.current = null; setBusy(false); } }
  function fail(cause: unknown, token: number) {
    if (!current(token)) return;
    clearReview(); setCandidates(undefined); setCandidateId(""); setStatus(undefined);
    setMessage(discoveryErrorCopy(cause)); setError(true);
  }
  async function refresh() {
    interrupt(true, "Loading read-only review metadata…");
    const request = begin("read"); if (!request) return;
    try {
      const body = await apiGet<DiscoveryWorkspaceStatus>("/api/trusted-discovery/status", { signal: request.signal });
      if (!current(request.token)) return;
      if (!validStatus(body)) throw Error("UNSAFE_METADATA");
      setStatus(body); setMessage("Owner-only preview available. Selection alone does not send a request.");
    } catch (cause) { fail(cause, request.token); } finally { finish(request.token); }
  }
  useEffect(() => {
    void refresh();
    const discard = () => interrupt(true, "Review invalidated by navigation, connection or session change. Refresh read-only metadata when ready.");
    const visibility = () => { if (document.visibilityState === "hidden") discard(); };
    const expired = () => { const wasWrite = pending.current === "write"; interrupt(true); setError(true); if (!wasWrite) setMessage("Your owner session is unavailable or expired. Sign in again before reviewing."); };
    window.addEventListener("routecairn:session-expired", expired);
    const events = [ "popstate", "hashchange", "offline", "online", "pagehide", "pageshow"];
    events.forEach((event) => window.addEventListener(event, discard)); document.addEventListener("visibilitychange", visibility);
    return () => { generation.current++; controller.current?.abort(); pending.current = null; events.forEach((event) => window.removeEventListener(event, discard)); document.removeEventListener("visibilitychange", visibility); window.removeEventListener("routecairn:session-expired", expired); };
    // Selection state is remounted on organization changes; never execution authority.
  }, [organizationId]);
  useEffect(() => { if (error || message.startsWith("Pre-consent recorded")) notice.current?.focus(); }, [error, message]);
  useEffect(() => {
    if (!review) return;
    reviewHeading.current?.focus(); let timer: ReturnType<typeof setTimeout>;
    const tick = () => {
      const remaining = Date.parse(review.expiresAt) - Date.now();
      if (remaining <= 0) { const unknown = pending.current === "write"; generation.current++; controller.current?.abort(); pending.current = null; setBusy(false); clearReview(); setError(true); setMessage(unknown ? "Review expired during confirmation — outcome UNKNOWN. Do not repeat the confirmation automatically." : "Review expired. Select a fresh review. No execution permission was granted."); return; }
      setSeconds(Math.ceil(remaining / 1000)); timer = setTimeout(tick, Math.min(1000, remaining));
    };
    tick(); return () => clearTimeout(timer);
  }, [review]);
  async function chooseScan(id: string) {
    interrupt(false); setScanId(id);
    if (!uuid.test(id)) return;
    const request = begin("read"); if (!request) return;
    try {
      const body = await apiGet<DiscoveryCandidateProjection>(`/api/trusted-discovery/candidates/${id}`, { signal: request.signal });
      if (!current(request.token)) return;
      if (body.scanId !== id || body.targetId !== targetId || body.executionAuthority !== "NONE" || typeof body.truncated !== "boolean" || !Array.isArray(body.candidates) || body.candidates.length > 64 || body.candidates.some((c) => !/^[a-f0-9]{64}$/.test(c.candidateId) || c.method !== "GET" || c.executionAuthority !== "NONE" || !/^Anonymous GET candidate \d{1,6}$/.test(c.label))) throw Error("UNSAFE_METADATA");
      setCandidates(body); setMessage(body.candidates.length ? "Choose a retained candidate, then explicitly request a review." : "No eligible anonymous GET candidates in this retained scan.");
    } catch (cause) { fail(cause, request.token); } finally { finish(request.token); }
  }
  async function requestReview() {
    if (!status || !candidates?.candidates.some((c) => c.candidateId === candidateId)) return;
    clearReview(); const request = begin("write"); if (!request) return;
    try {
      const body = await apiMutation<{ review: PublicReview; status: string; attempted: number; initiated: number; observed: number; executionAuthority: string }>("/api/trusted-discovery/review", "POST", { scanId, candidateId }, { signal: request.signal });
      if (!current(request.token)) return;
      if (body.status !== "NOT_EXECUTED" || body.attempted !== 0 || body.initiated !== 0 || body.observed !== 0 || body.executionAuthority !== "NONE" || !exactReview(body.review, scanId, candidateId, targetId)) throw Error("UNSAFE_REVIEW");
      setReview(body.review); setMessage("Review complete — awaiting deliberate historical pre-consent. No HTTP GET was sent.");
    } catch (cause) { fail(cause, request.token); } finally { finish(request.token); }
  }
  async function preconsent() {
    if (!review || confirmation !== phrase || Date.now() >= Date.parse(review.expiresAt)) return;
    const exact = review; const request = begin("write"); if (!request) return;
    setConfirmation("");
    try {
      const body = await apiMutation<{ code: string; status: string; attempted: number; initiated: number; observed: number; executionAuthority: string }>("/api/trusted-discovery/pre-consent", "POST", { ...exact, confirmation: phrase }, { signal: request.signal });
      if (!current(request.token)) return;
      if (body.code !== "PRECONSENT_RECORDED" || body.status !== "NOT_EXECUTED" || body.attempted !== 0 || body.initiated !== 0 || body.observed !== 0 || body.executionAuthority !== "NONE") throw Error("UNKNOWN_WRITE_RESULT");
      clearReview(); setCandidateId(""); setMessage("Pre-consent recorded — NOT EXECUTED. No HTTP GET was sent.");
    } catch (cause) { fail(cause, request.token); } finally { finish(request.token); }
  }
  return <section className="trusted-discovery-workspace" aria-labelledby="trusted-discovery-title">
    <header className="page-header"><h2 id="trusted-discovery-title">Trusted Discovery</h2><p>Review retained local discovery candidates and record historical intention.</p></header>
    <p ref={notice} tabIndex={-1} role={error ? "alert" : "status"} aria-live={error ? "assertive" : "polite"} className={error ? "trusted-discovery-alert" : ""}>{message || "Preview availability is checked by the server."}</p>
    <button type="button" disabled={busy} onClick={() => void refresh()}>Refresh read-only metadata</button>
    {status && <>
      <p>Preview only — active owner session verified by the server. This is not execution authority.</p>
      {(status.truncated || candidates?.truncated) && <p>Only the first 64 items are shown. Review metadata is bounded.</p>}
      {!status.targets.length && <p>No registered authorized local targets are available in this organization.</p>}
      <div className="form">
        <label>Registered local target<select disabled={busy} value={targetId} onChange={(event) => { interrupt(false); setTargetId(event.target.value); setScanId(""); }}><option value="">Select target</option>{status.targets.map((target) => <option key={target.id} value={target.id}>{target.label}</option>)}</select></label>
        <label>Completed dashboard scan<select disabled={!targetId || busy} value={scanId} onChange={(event) => void chooseScan(event.target.value)}><option value="">Select retained scan</option>{status.scans.filter((scan) => scan.targetId === targetId).map((scan) => <option key={scan.id} value={scan.id}>{scan.label}</option>)}</select></label>
        {targetId && !status.scans.some((scan) => scan.targetId === targetId) && <p>No completed retained dashboard scans for this target.</p>}
        <label>Retained candidate<select disabled={!candidates || busy} value={candidateId} onChange={(event) => { clearReview(); setCandidateId(event.target.value); }}><option value="">Select candidate</option>{candidates?.candidates.map((candidate) => <option key={candidate.candidateId} value={candidate.candidateId}>{candidate.label} · {candidate.candidateId.slice(0, 12)}</option>)}</select></label>
        <button type="button" disabled={!candidateId || busy} onClick={() => void requestReview()}>Review selected candidate</button>
      </div>
    </>}
    {review && <section aria-labelledby="discovery-review-title" className="trusted-discovery-review">
      <h3 id="discovery-review-title" ref={reviewHeading} tabIndex={-1}>Reviewed candidate</h3>
      <dl className="trusted-discovery-facts"><dt>Registered target</dt><dd>{review.targetId}</dd><dt>Retained scan</dt><dd>{review.scanId}</dd><dt>Route</dt><dd>{review.routeLabel}</dd><dt>Method</dt><dd>GET</dd><dt>Effect</dt><dd>Non-mutating</dd><dt>Review digest</dt><dd>{review.reviewDigest.slice(0, 12)}…</dd><dt>Expires</dt><dd><time dateTime={review.expiresAt}>{new Date(review.expiresAt).toLocaleTimeString()}</time> · {seconds} seconds remaining</dd></dl>
      <p role="note">Historical pre-consent destroys this native review. It is not fresh native execution consent and cannot execute or revive a request.</p>
      <label htmlFor="discovery-confirmation">Type the exact confirmation phrase</label>
      <p id="discovery-confirmation-help"><code>{phrase}</code></p>
      <input id="discovery-confirmation" aria-describedby="discovery-confirmation-help" autoComplete="off" spellCheck={false} disabled={busy} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
      <button type="button" disabled={busy || confirmation !== phrase || seconds <= 0} onClick={() => void preconsent()}>Record pre-consent (does not execute)</button>
      <button type="button" onClick={() => interrupt(false, "Review discarded locally. This does not revoke or refund any server operation.")}>Discard displayed review</button>
    </section>}
    <TrustedDiscoveryStatus />
  </section>;
}
