export function ScanCancellationNotice({ status, hasArtifacts, onRecovery }: { status: string; hasArtifacts: boolean; onRecovery: () => void }) {
  if (status === "CANCEL_REQUESTED") return <p role="status">Cancellation requested. New test actions are stopping; restoration has a separate two-minute budget, followed by a 15-second report-writing grace period. Keep the dashboard running while cleanup finishes.</p>;
  if (!["CANCELLED", "INTERRUPTED", "FAILED"].includes(status)) return null;
  return <aside role="status">
    <p>{status === "INTERRUPTED" ? "Execution was interrupted." : status === "FAILED" ? "Execution failed." : "Execution was cancelled."} {hasArtifacts ? "Partial reports and collected evidence are available below." : "No report checkpoint is available yet."} Missing coverage is not a security pass.</p>
    <p>Cancellation does not prove rollback. Check the cleanup events and <button onClick={onRecovery}>Offensive Safety recovery</button> before reusing disposable accounts or objects.</p>
  </aside>;
}
