import { useCallback, useEffect, useState } from "react";
import type { AssistedReviewService } from "../../../src/dashboard/reviews/AssistedReviewService";
import { apiGet, apiMutation } from "./api";

type Review = ReturnType<AssistedReviewService["get"]>;

export function AssistedReviewPanel(props: { scanId: string; onReviewFindings: () => void }) {
  const [review, setReview] = useState<Review>();
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    try { setReview(await apiGet<Review>(`/api/scans/${props.scanId}/assisted-review`)); setMessage(""); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Review could not be loaded."); }
  }, [props.scanId]);
  useEffect(() => { setReview(undefined); void load(); }, [load]);
  const publish = async () => {
    setBusy(true);
    try { await apiMutation(`/api/scans/${props.scanId}/assisted-review/publish`, "POST", {}); await load(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Publication failed."); }
    finally { setBusy(false); }
  };
  return <section aria-label="Assisted security review" className="card">
    <h3>Assisted Security Review</h3>
    {message && <p role="status">{message}</p>}
    <div className="actions"><button onClick={() => void load()}>Refresh Review</button>{review && <button onClick={props.onReviewFindings}>Review Findings and Evidence</button>}</div>
    {review && <>
      <h4>{review.report.title}</h4>
      {review.report.targetMode && <p>Target mode: {review.report.targetMode}</p>}
      {review.report.preHandover && <section aria-label="Pre-handover readiness"><h4>Pre-Handover Readiness</h4><p>Revision {review.report.preHandover.revision} · {review.report.preHandover.environment} · {review.report.preHandover.objectCount} disposable objects · {review.report.preHandover.invariantCount} invariants · {review.report.preHandover.raceCount} races</p><ol>{review.report.preHandover.sequence.map((module) => <li key={module}>{module}</li>)}</ol><p>{review.report.preHandover.criticalCoverage.filter((item) => item.passed).length}/{review.report.preHandover.criticalCoverage.length} critical cases passed; {review.report.preHandover.regressions.filter((item) => item.passed).length}/{review.report.preHandover.regressions.length} regressions verified.</p></section>}
      <p>Publication gate: <strong>{review.gate.state}</strong>. Human review is required; cleanup is evaluated independently.</p>
      {review.gate.blockers.length > 0 && <ul>{review.gate.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul>}
      <div className="table"><table><thead><tr><th>Lane</th><th>Proven</th><th>Inconclusive</th><th>Not assessed</th><th>Blocked</th><th>Cleanup unresolved</th></tr></thead><tbody>
        {Object.entries(review.report.coverageMatrix).filter(([, value]) => value.selected).map(([lane, value]) => <tr key={lane}><td>{lane}{value.required ? " (required)" : ""}</td><td>{value.outcomes.PROVEN}</td><td>{value.outcomes.INCONCLUSIVE}</td><td>{value.outcomes.NOT_ASSESSED}</td><td>{value.outcomes.BLOCKED}</td><td>{value.cleanupFailures}</td></tr>)}
      </tbody></table></div>
      <h4>Human Review Queue</h4>
      {review.queue.length === 0 ? <p>No findings awaiting decisions.</p> : review.queue.map((item) => <article key={item.occurrenceId}>
        <strong>{item.title}</strong><p>{item.severity} · {item.reviewState}{item.occurrenceReviewed ? " · occurrence reviewed" : " · this occurrence needs review"} · {item.workflowId}/{item.caseId}</p>
        <p>{item.evidenceIds.length} evidence record(s) · {item.proofPackIds.length} proof pack(s) · {item.comparisonIds.length} comparison(s){item.cleanupUnresolved ? " · CLEANUP UNRESOLVED" : ""}</p>
        <details><summary>Evidence and comparison references</summary><pre>{JSON.stringify({ occurrenceId: item.occurrenceId, evidence: item.evidenceIds, proofPacks: item.proofPackIds, comparisons: item.comparisonIds }, null, 2)}</pre></details>
      </article>)}
      <h4>Remediation Roadmap (operator draft)</h4>
      <ol>{review.report.remediationRoadmap.map((item) => <li key={item.findingId}>{item.severity}: {item.title} — {item.customerSafeRemediation}</li>)}</ol>
      <button disabled={busy || review.gate.state !== "READY"} onClick={() => void publish()}>{busy ? "Publishing…" : "Publish Human-reviewed Customer Report"}</button>
      {review.publications.map((item) => <p key={item.id}><a href={`/api/artifacts/${item.artifactId}/download`}>Customer report — {item.createdAt}</a></p>)}
      <details><summary>Review case timeline</summary><ol>{review.report.timeline.map((item) => <li key={item.sequence}>{item.workflowId}/{item.caseId}: {item.outcome}</li>)}</ol></details>
    </>}
  </section>;
}
