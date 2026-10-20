import React, { useEffect, useRef, useState } from "react";
import { apiGet } from "./api";
import type { ApplicationAssessmentReadiness } from "../../../src/dashboard/execution/ApplicationAssessmentReadiness";
type Snapshot = ReturnType<ApplicationAssessmentReadiness["get"]>;
export function AssessmentJourney({
  targetId,
  credentials,
  mapRevisionId
}: {
  targetId: string;
  credentials: { primary: string; account_a: string; account_b: string };
  mapRevisionId?: string | undefined;
}) {
  const [snapshot, setSnapshot] = useState<Snapshot>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    epoch = useRef(0);
  const key = JSON.stringify([targetId, credentials, mapRevisionId]);
  useEffect(() => {
    epoch.current++;
    setSnapshot(undefined);
    setBusy(false);
    setError("");
    return () => {
      epoch.current++;
    };
  }, [key]);
  const inspect = () => {
    const n = ++epoch.current;
    setBusy(true);
    setSnapshot(undefined);
    setError("");
    const query = new URLSearchParams({
      targetId,
      ...Object.fromEntries(Object.entries(credentials).filter(([, v]) => v)),
      ...(mapRevisionId ? { mapRevisionId } : {})
    });
    void apiGet<Snapshot>("/api/authorization-workbench/mapping/readiness?" + query)
      .then((s) => {
        if (n === epoch.current) setSnapshot(s);
      })
      .catch(() => {
        if (n === epoch.current)
          setError(
            "Readiness unavailable. Check selected target, actor profiles and retained source; no approval or retry occurred."
          );
      })
      .finally(() => {
        if (n === epoch.current) setBusy(false);
      });
  };
  return (
    <section className="assessment-journey" aria-label="Assessment readiness and next steps">
      <h4>Your assessment journey</h4>
      <p>
        Register scope → verify actors → observe → review relationships and policy → separately approve proof → compare
        remediation → hand off evidence.
      </p>
      <p>Readiness inspects saved records only. It sends no target request and never approves execution.</p>
      <button type="button" disabled={!targetId || busy} onClick={inspect}>
        Inspect assessment readiness
      </button>
      {error && <p role="alert">{error}</p>}
      {snapshot && (
        <>
          <ol aria-label="Readiness checklist">
            {snapshot.steps.map((s) => (
              <li key={s.id}>
                <strong>
                  {s.id}: {s.status}
                </strong>
                <p>{s.next}</p>
              </li>
            ))}
          </ol>
          <p role="status">
            Native actor/route evidence: {snapshot.observation.nativeActorRoutePairs}/
            {snapshot.observation.expectedPairs}. {snapshot.observation.missing.join("; ")}. Owner declaration is not a
            security pass.
          </p>
          <details>
            <summary>What the owner and evaluator must provide</summary>
            <dl>
              {Object.entries(snapshot.ownerInputContract).map(([k, v]) => (
                <React.Fragment key={k}>
                  <dt>{k}</dt>
                  <dd>{v}</dd>
                </React.Fragment>
              ))}
            </dl>
          </details>
          <p>Independent evaluation: {snapshot.independentEvaluation}. State-changing execution: HOLD.</p>
        </>
      )}
    </section>
  );
}
