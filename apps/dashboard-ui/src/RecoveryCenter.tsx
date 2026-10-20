import { ObservedStateAttention } from "./ObservedStateRegression";
import { CleanupAttemptHistory } from "./CleanupAttemptHistory";
import { useEffect, useRef, useState } from "react";
import { apiGet, apiMutation } from "./api";
import { WorkflowRecoveryPanel } from "./WorkflowRecoveryPanel";
import type { RecoveryCenterSnapshot, RecoveryIssue } from "../../../src/dashboard/contracts/RecoveryCenterContracts";

function validate(value: RecoveryCenterSnapshot): RecoveryCenterSnapshot {
  if (
    !value ||
    value.schemaVersion !== 1 ||
    value.automaticReplay !== false ||
    !Array.isArray(value.issues) ||
    !Array.isArray(value.inventoryWarnings) ||
    value.issues.some(
      (i) =>
        !i ||
        !["CUSTODY", "CLEANUP", "ASSURANCE", "DEPLOYMENT", "COMPARISON", "RECOVERY"].includes(i.kind) ||
        typeof i.subjectId !== "string" ||
        !/^[a-f0-9]{64}$/.test(i.snapshotDigest) ||
        !Array.isArray(i.evidence) ||
        !Array.isArray(i.blockedActions) ||
        !i.actions ||
        [i.actions.review, i.actions.recompute, i.actions.cleanup].some((v) => typeof v !== "boolean")
    )
  )
    throw Error("Recovery inventory is invalid. Actions are unavailable.");
  return value;
}
export function RecoveryCenter({
  onOpenScan,
  onOpenComparison,
  onOpenWorkers
}: { onOpenScan?(id: string): void; onOpenComparison?(id: string): void; onOpenWorkers?(): void } = {}) {
  const [data, setData] = useState<RecoveryCenterSnapshot>(),
    [kind, setKind] = useState(""),
    [page, setPage] = useState(1),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [reload, setReload] = useState(0),
    [cleanupCase, setCleanupCase] = useState("");
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    let sequence = 0;
    const load = async () => {
      const id = ++sequence;
      try {
        const body = validate(
          await apiGet<RecoveryCenterSnapshot>(
            `/api/recovery-center?page=${page}&pageSize=25${kind ? `&kind=${kind}` : ""}`,
            { signal: controller.signal }
          )
        );
        if (!controller.signal.aborted && id === sequence) {
          setData(body);
          setError("");
        }
      } catch {
        if (!controller.signal.aborted && id === sequence) {
          setData(undefined);
          setCleanupCase("");
          setError("Recovery evidence is unavailable. No healthy outcome or recovery authority can be inferred.");
        }
      }
    };
    setData(undefined);
    setCleanupCase("");
    void load();
    const timer = window.setInterval(() => void load(), 10000);
    return () => {
      mounted.current = false;
      controller.abort();
      window.clearInterval(timer);
    };
  }, [kind, page, reload]);
  const action = async (path: string, body: unknown, message: string) => {
    if (busy || !data) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await apiMutation<{ status?: string }>(path, "POST", body);
      if (mounted.current) {
        setNotice(
          result.status === "FAILED"
            ? "Comparison attempt failed. Failure evidence is retained; original evidence and gates remain unchanged."
            : message
        );
        setReload((v) => v + 1);
      }
    } catch {
      if (mounted.current) {
        setError(
          "Action refused or acknowledgement unavailable. Refresh and inspect current evidence before any new request. No replay or clearance is implied."
        );
        setData(undefined);
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  };
  return (
    <section aria-label="Recovery and uncertainty">
      <ObservedStateAttention onScan={onOpenScan} onComparison={onOpenComparison} />
      <header className="page-header">
        <h2>Recovery & Uncertainty</h2>
        <p>
          Evidence, blockers and explicitly authorized recovery across worker custody, cleanup, assurance and
          comparisons.
        </p>
      </header>
      <div className="cleanup-emergency" role="note">
        <strong>Acknowledgement does not resolve uncertainty</strong>
        <p>
          Review notes never clear custody, release dispatch, erase cleanup obligations, replay deployments or change
          historical assurance gates.
        </p>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
      <div className="toolbar">
        <label>
          Evidence category
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All categories</option>
            {["CUSTODY", "CLEANUP", "ASSURANCE", "DEPLOYMENT", "COMPARISON", "RECOVERY"].map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
        </label>
        <button disabled={busy} onClick={() => setReload((v) => v + 1)}>
          Refresh evidence
        </button>
      </div>
      {!data && !error && <p role="status">Loading current evidence…</p>}
      {data && (
        <>
          <p>
            <strong>Worker dispatch: {data.dispatchState}</strong>{" "}
            {onOpenWorkers && <button onClick={onOpenWorkers}>Open worker diagnostics</button>}. Custody and cleanup are
            separate obligations. Some fleet blockers may belong to another organization; their private evidence is
            withheld.
          </p>
          {data.inventoryWarnings.map((w) => (
            <p className="cleanup-warning" role="alert" key={w}>
              {w}
            </p>
          ))}
          {!data.issues.length && (
            <p>
              {data.inventoryWarnings.length
                ? "Inventory is incomplete; no clean-state claim is available."
                : "No items in this inventory page. This is not scan coverage or deployment acceptance."}
            </p>
          )}
          <div className="recovery-issues">
            {data.issues.map((issue) => (
              <Issue
                key={`${issue.kind}:${issue.subjectId}:${issue.snapshotDigest}`}
                issue={issue}
                busy={busy}
                onAction={action}
                onCleanup={() => setCleanupCase(issue.subjectId)}
                onOpenScan={onOpenScan}
                onOpenComparison={onOpenComparison}
              />
            ))}
          </div>
          <div className="pagination">
            <button disabled={busy || page === 1} onClick={() => setPage((p) => p - 1)}>
              Previous evidence page
            </button>
            <span>Page {page} per evidence source</span>
            <button disabled={busy || !data.hasMore} onClick={() => setPage((p) => p + 1)}>
              Next evidence page
            </button>
          </div>
          {cleanupCase &&
            data.issues.some((i) => i.kind === "CLEANUP" && i.subjectId === cleanupCase && i.actions.cleanup) &&
            (cleanupCase.startsWith("approval:") ? (
              <ControlledCleanup
                key={cleanupCase}
                issue={data.issues.find((i) => i.subjectId === cleanupCase)!}
                busy={busy}
                onAction={action}
              />
            ) : (
              <WorkflowRecoveryPanel key={cleanupCase} initialCaseId={cleanupCase} canRecover={true} />
            ))}
        </>
      )}
    </section>
  );
}
function Issue({
  issue,
  busy,
  onAction,
  onCleanup,
  onOpenScan,
  onOpenComparison
}: {
  issue: RecoveryIssue;
  busy: boolean;
  onAction(path: string, body: unknown, message: string): Promise<void>;
  onCleanup(): void;
  onOpenScan?: ((id: string) => void) | undefined;
  onOpenComparison?: ((id: string) => void) | undefined;
}) {
  const [reviewConfirmed, setReviewConfirmed] = useState(false),
    [analysisConfirmed, setAnalysisConfirmed] = useState(false);
  const review = (decision: "ACKNOWLEDGED" | "ESCALATED") =>
    void onAction(
      "/api/recovery-center/reviews",
      {
        kind: issue.kind,
        subjectId: issue.subjectId,
        snapshotDigest: issue.snapshotDigest,
        decision,
        reason: decision === "ESCALATED" ? "OWNER_INVESTIGATION" : "EVIDENCE_INCOMPLETE",
        confirmation: "I_REVIEWED_EVIDENCE_WITHOUT_RESOLVING_UNCERTAINTY"
      },
      "Review recorded. Uncertainty and safety blockers remain in force."
    );
  return (
    <article className="panel recovery-issue" aria-label={`${issue.kind} ${issue.subjectId}`}>
      <h3>{issue.title}</h3>
      <p>
        <strong>
          {issue.kind} · {issue.state}
        </strong>
      </p>
      <p>{issue.explanation}</p>
      <h4>Available evidence</h4>
      <dl className="dense-dl">
        {issue.evidence.map((e, n) => (
          <div key={n}>
            <dt>{e.label}</dt>
            <dd>
              <code>{e.value}</code>
            </dd>
          </div>
        ))}
      </dl>
      <p>
        Snapshot <code>{issue.snapshotDigest}</code>
      </p>
      <div className="actions">
        {issue.evidence
          .filter((e) => ["Older scan", "Newer scan", "Scan"].includes(e.label) && /^[a-f0-9-]{36}$/.test(e.value))
          .map((e, n) => (
            <button key={n} onClick={() => onOpenScan?.(e.value)} disabled={!onOpenScan}>
              Open {e.label.toLowerCase()} {e.value.slice(0, 8)}
            </button>
          ))}
        {issue.kind === "COMPARISON" && onOpenComparison && (
          <button onClick={() => onOpenComparison(issue.subjectId)}>Inspect comparison evidence</button>
        )}
      </div>
      {issue.subjectId.startsWith("attempt:") && (
        <CleanupAttemptHistory attemptId={issue.subjectId.slice(8)} snapshotDigest={issue.snapshotDigest} />
      )}
      <h4>{issue.humanReviewRequired ? "Blocked actions and required review" : "Authorization boundaries"}</h4>
      <ul>
        {issue.blockedActions.map((b) => (
          <li key={b}>{b}</li>
        ))}
      </ul>
      {issue.review && (
        <p role="note">
          {issue.review.decision} · {issue.review.reason} · {issue.review.createdAt}.{" "}
          {issue.review.current
            ? "Review binds this snapshot; uncertainty remains open."
            : "Evidence changed after this review. Fresh review is required."}
        </p>
      )}
      {issue.actions.review ? (
        <fieldset disabled={busy}>
          <legend>Human evidence review</legend>
          <label>
            <input type="checkbox" checked={reviewConfirmed} onChange={(e) => setReviewConfirmed(e.target.checked)} />I
            reviewed this exact snapshot. No safety hold is cleared.
          </label>
          <div className="actions">
            <button disabled={!reviewConfirmed} onClick={() => review("ACKNOWLEDGED")}>
              Acknowledge review
            </button>
            <button disabled={!reviewConfirmed} onClick={() => review("ESCALATED")}>
              Escalate to owner investigation
            </button>
          </div>
        </fieldset>
      ) : (
        <p>Review permission is required. Worker custody review requires worker-management authority.</p>
      )}
      {issue.actions.recompute && (
        <fieldset disabled={busy}>
          <legend>Offline comparison recovery</legend>
          <label>
            <input
              type="checkbox"
              checked={analysisConfirmed}
              onChange={(e) => setAnalysisConfirmed(e.target.checked)}
            />
            I authorize a new comparison only. No scan or historical gate change.
          </label>
          <button
            disabled={!analysisConfirmed}
            onClick={() =>
              void onAction(
                "/api/recovery-center/comparison-recompute",
                {
                  subjectId: issue.subjectId,
                  snapshotDigest: issue.snapshotDigest,
                  requestId: crypto.randomUUID(),
                  confirmation: "I_AUTHORIZE_COMPARISON_ONLY_NO_SCAN_OR_GATE_CHANGE"
                },
                "New comparison attempt retained. Original evidence and historical assurance gates are unchanged."
              )
            }
          >
            Create new comparison evidence
          </button>
        </fieldset>
      )}
      {issue.actions.cleanup && (
        <button disabled={busy} onClick={onCleanup}>
          Open authorized cleanup recovery
        </button>
      )}
      {!issue.actions.cleanup && issue.kind === "CLEANUP" && (
        <p>
          Automatic recovery is unavailable without a verifiable workflow checkpoint, exclusive organization binding and
          recovery permission. Human review remains required.
        </p>
      )}
    </article>
  );
}

function ControlledCleanup({
  issue,
  busy,
  onAction
}: {
  issue: RecoveryIssue;
  busy: boolean;
  onAction(path: string, body: unknown, message: string): Promise<void>;
}) {
  const [profiles, setProfiles] = useState<Array<{ id: string; name: string; targetId?: string; enabled: boolean }>>(
      []
    ),
    [credential, setCredential] = useState(""),
    [confirmed, setConfirmed] = useState(false),
    [error, setError] = useState("");
  const target = issue.evidence.find((e) => e.label === "Target")?.value;
  useEffect(() => {
    const controller = new AbortController();
    setConfirmed(false);
    setCredential("");
    void apiGet<{ profiles: typeof profiles }>("/api/credential-profiles", { signal: controller.signal })
      .then((body) => {
        if (!Array.isArray(body.profiles)) throw Error("Invalid profiles");
        if (!controller.signal.aborted) setProfiles(body.profiles.filter((p) => p.enabled && p.targetId === target));
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setProfiles([]);
          setError("Fresh target-bound credentials are unavailable. Recovery cannot be started.");
        }
      });
    return () => controller.abort();
  }, [issue.snapshotDigest, target]);
  return (
    <section className="panel" aria-label="Bound controlled cleanup">
      <h3>Bound controlled cleanup</h3>
      <p>
        The server derives the encrypted cleanup bundle from this approval. Target revision, scope, actor identity,
        expiry and stored plan binding are rechecked. No original mutation or scan is authorized.
      </p>
      {error && <p role="alert">{error}</p>}
      <label>
        Fresh target-bound credential
        <select
          value={credential}
          onChange={(e) => {
            setCredential(e.target.value);
            setConfirmed(false);
          }}
        >
          <option value="">Select saved credential</option>
          {profiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />I authorize only
        this approval’s bound cleanup and restoration verification.
      </label>
      <button
        disabled={busy || !credential || !confirmed || !issue.actions.cleanup}
        onClick={() =>
          void onAction(
            "/api/recovery-center/controlled-cleanup",
            {
              subjectId: issue.subjectId,
              snapshotDigest: issue.snapshotDigest,
              credentialProfileId: credential,
              confirmation: "I_AUTHORIZE_BOUND_CONTROLLED_CLEANUP_ONLY"
            },
            "Bound cleanup requested. Monitor the approval and recovery evidence; restoration is not yet verified."
          )
        }
      >
        Request bound cleanup
      </button>
    </section>
  );
}
