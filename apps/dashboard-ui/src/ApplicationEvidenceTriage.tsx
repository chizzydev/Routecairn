import "./BusinessFlowTriage.css";
import { AnalystHandoff } from "./AnalystHandoff";
import React, { useEffect, useRef, useState } from "react";
import { apiGet, apiMutation } from "./api";
import type { ApplicationEvidenceTriage as Service } from "../../../src/dashboard/execution/ApplicationEvidenceTriage";
type Evidence = ReturnType<Service["get"]>;
export function ApplicationEvidenceTriage({
  proposalId,
  canExecute,
  onScan
}: {
  proposalId: string;
  canExecute: boolean;
  onScan?: ((id: string) => void) | undefined;
}) {
  const [evidence, setEvidence] = useState<Evidence>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [rationale, setRationale] = useState(""),
    [disposition, setDisposition] = useState("INVESTIGATE"),
    [consent, setConsent] = useState(false),
    [saved, setSaved] = useState("");
  const generation = useRef(0);
  useEffect(() => {
    generation.current++;
    setEvidence(undefined);
    setConsent(false);
    setRationale("");
    setSaved("");
    setBusy(false);
    setError("");
    return () => {
      generation.current++;
    };
  }, [proposalId]);
  const base = "/api/authorization-workbench/mapping/hypotheses/" + proposalId;
  const load = async () => {
    const n = ++generation.current;
    setBusy(true);
    setError("");
    try {
      const r = await apiGet<Evidence>(base + "/triage");
      if (n === generation.current) {
        setEvidence(r);
        setConsent(false);
      }
    } catch {
      if (n === generation.current) setError("Evidence unavailable. No healthy or resolved outcome can be inferred.");
    } finally {
      if (n === generation.current) setBusy(false);
    }
  };
  return (
    <section className="application-evidence-triage" aria-label="Evidence-centered assessment triage">
      <h4>Observed → declared → proven → compared</h4>
      <AnalystHandoff proposalId={proposalId} />
      <p>
        Suggestions are questions. Only native proof can establish a tested policy deviation; operator notes do not
        change findings, comparison coverage, quarantine or execution authority.
      </p>
      <button disabled={busy} onClick={() => void load()}>
        Refresh linked assessment evidence
      </button>
      {error && <p role="alert">{error}</p>}
      {saved && <p role="status">{saved}</p>}
      {evidence && (
        <>
          <p role="status">
            Next action: {evidence.nextAction}. Source freshness: {evidence.freshness}.
          </p>
          <p>
            Observed scan {evidence.source.sourceScanId ?? "UNOBSERVED"} · source digest{" "}
            {evidence.source.sourceHash ?? "UNKNOWN"} · owner policy {evidence.policyAuthority}.
          </p>
          <ol aria-label="Assessment evidence journey">
            <li>Observe exact routes, actors and versions.</li>
            <li>Review relationships and missing controls; declare owner policy.</li>
            <li>Review the existing proof matrix and separately authorize its exact native GETs.</li>
            <li>Inspect verified deviations and abstentions below.</li>
            <li>
              Use existing remediation comparison and Observed-State Regression; incomplete evidence never proves
              resolution.
            </li>
          </ol>
          {evidence.historyIncomplete && (
            <p role="alert">
              History is incomplete in this bounded view. Showing the newest retained proofs and notes;{" "}
              {evidence.proofCount} linked proof revisions, {evidence.noteCount} notes. No complete or quiet assessment
              is implied.
            </p>
          )}
          <table aria-label="Ranked security questions">
            <thead>
              <tr>
                <th>Question</th>
                <th>Priority / eligibility</th>
                <th>Missing evidence</th>
              </tr>
            </thead>
            <tbody>
              {evidence.questions.map((c) => (
                <tr key={c.candidateId}>
                  <td>{c.routeId}</td>
                  <td>
                    {c.priority} / {c.eligibility}
                  </td>
                  <td>{c.missingControls.join("; ") || "Owner-declared policy required; no finding inferred."}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {evidence.proofs.length === 0 && <p>No proof has been dispatched. This assessment is UNTESTED.</p>}
          {evidence.proofs.map((p) => (
            <article key={p.revisionId}>
              <h5>Native proof {p.status}</h5>
              <p>
                Matrix {p.revisionId}; scan {p.scanId ?? "UNKNOWN"}; hash {p.sourceHash ?? "UNKNOWN"}.
              </p>
              {p.scanId && onScan && <button onClick={() => onScan(p.scanId!)}>Open exact native scan evidence</button>}
              <p>{p.missing.join("; ")}</p>
              <ul>
                {p.findings.map((f, i) => (
                  <li key={i}>
                    Verified native policy deviation: {f.title}. {f.severity} / {f.confidence}
                  </li>
                ))}
              </ul>
              <table aria-label={"Native proof " + p.revisionId}>
                <thead>
                  <tr>
                    <th>Exact check / actor</th>
                    <th>Outcome</th>
                    <th>Evidence fingerprint</th>
                  </tr>
                </thead>
                <tbody>
                  {p.checks.map((c) => (
                    <tr key={c.checkId}>
                      <td>
                        {c.checkId} / {c.actorId ?? "unverified"}
                      </td>
                      <td>{c.outcome}</td>
                      <td>{c.comparisonFingerprint}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </article>
          ))}
          {evidence.comparisons.length === 0 && <p>No recorded remediation comparison. Resolution is NOT TESTED.</p>}
          {evidence.comparisons.map((c, i) => (
            <article key={i}>
              <h5>Comparison {String(c.state)}</h5>
              <p>
                {String(c.comparisonId)} · {String(c.disposition)}. Complete coverage:{" "}
                {c.coverageComplete ? "yes" : "no; explicit review required"}.
              </p>
              <pre>{JSON.stringify(c.summary ?? { reason: "No trustworthy summary" }, null, 2)}</pre>
            </article>
          ))}
          <section aria-label="Linked observed-state assurance">
            <h5>Observed-State Regression &amp; Continuous Assurance</h5>
            <p>
              Business references grant no transition or continuous-execution authority. Use the existing separately
              reviewed trusted-event policy workflow.
            </p>
            {!evidence.observationPolicies?.length ? (
              <p>
                No separately reviewed observed-state policy is linked. Continuous Assurance is NOT TESTED for this
                relationship.
              </p>
            ) : (
              <pre>{JSON.stringify(evidence.observationPolicies, null, 2)}</pre>
            )}
          </section>
          <fieldset disabled={!canExecute || busy}>
            <legend>Append owner/analyst context</legend>
            <label>
              Analyst disposition
              <select
                aria-label="Triage disposition"
                value={disposition}
                onChange={(e) => {
                  setDisposition(e.target.value);
                  setConsent(false);
                }}
              >
                <option value="INVESTIGATE">Investigate verified evidence</option>
                <option value="NEEDS_OWNER_CONTEXT">Needs owner context</option>
                <option value="OWNER_EXPECTED_BEHAVIOR">Owner says expected behavior; review retained</option>
              </select>
            </label>
            <label>
              Non-secret triage rationale
              <textarea
                aria-label="Triage rationale"
                value={rationale}
                onChange={(e) => {
                  setRationale(e.target.value);
                  setConsent(false);
                }}
                maxLength={500}
              />
            </label>
            <label>
              <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />I reviewed this
              exact evidence. This note does not resolve or suppress a scanner finding.
            </label>
            <button
              disabled={!canExecute || busy || !consent || rationale.trim().length < 10}
              onClick={() => {
                const n = generation.current;
                setBusy(true);
                setError("");
                void apiMutation(base + "/triage-notes", "POST", {
                  digest: evidence.digest,
                  disposition,
                  rationale,
                  reviewConfirmed: true
                })
                  .then(() => {
                    if (n === generation.current) {
                      setSaved("Immutable context note retained. Scanner outcomes and execution authority unchanged.");
                      setConsent(false);
                      void load();
                    }
                  })
                  .catch(() => {
                    if (n === generation.current) {
                      setError(
                        "Note could not be confirmed or evidence changed. Refresh history; do not infer rollback or automatically replay."
                      );
                      setConsent(false);
                    }
                  })
                  .finally(() => {
                    if (n === generation.current) setBusy(false);
                  });
              }}
            >
              Record evidence-bound triage note
            </button>
          </fieldset>
          <details>
            <summary>Immutable analyst context history</summary>
            <pre>{JSON.stringify(evidence.notes, null, 2)}</pre>
          </details>
        </>
      )}
    </section>
  );
}
