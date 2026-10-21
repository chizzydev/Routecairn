import type { RouteCairnReport } from "../../../src/reports/ReportTypes";
export function AssessmentCapabilitiesPanel({
  value
}: {
  value: NonNullable<RouteCairnReport["assessmentCapabilities"]>;
}) {
  return (
    <section aria-label="Assessment capability coverage">
      <h3>What was assessed</h3>
      <p>
        Eligibility is not a test result. Native observations do not establish that an application is secure. Missing
        capabilities remain explicit.
      </p>
      <ul>
        {value.actors.map((a) => (
          <li key={a.id}>
            {a.label}: {a.mechanism} · {a.assurance}; role {a.roleVerified ? "verified" : "unverified"}; tenant{" "}
            {a.tenantVerified ? "verified" : "unverified"}
          </li>
        ))}
      </ul>
      <table>
        <caption>Native coverage and manual review</caption>
        <thead>
          <tr>
            <th>Workflow</th>
            <th>Status</th>
            <th>Evidence / missing prerequisite</th>
          </tr>
        </thead>
        <tbody>
          {value.workflows.map((w) => (
            <tr key={w.workflowId}>
              <td>
                {w.workflowId} · {w.family}
              </td>
              <td>{w.status}</td>
              <td>
                <p>{w.reason}</p>
                {"authenticationResult" in w && (
                  <p>
                    Authentication response: {String(w.authenticationResult)}. An HTTP success status alone is not
                    session or principal proof.
                  </p>
                )}
                <p>
                  {"evidenceCoverage" in w
                    ? String(w.evidenceCoverage)
                    : "Complete native evidence is retained in the JSON report."}
                </p>
                {w.evidence.map((e) => (
                  <p key={e.checkId}>
                    {e.checkId} · {e.outcome} · {e.comparisonFingerprint}
                    {"responseStatuses" in e && <span> · HTTP {e.responseStatuses.join(", ") || "not observed"}</span>}
                  </p>
                ))}
                {"reportArtifactId" in w && typeof w.reportArtifactId === "string" && (
                  <a href={"/api/artifacts/" + encodeURIComponent(w.reportArtifactId) + "/download"}>
                    Inspect complete native source report
                  </a>
                )}
                <details>
                  <summary>Human verification path</summary>
                  <p>{w.manualVerification.instructions}</p>
                  <p>Human review only; never native scanner proof.</p>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
