import { useEffect, useState } from "react";
import { apiGet } from "./api";
interface Timeline {
  attemptId: string;
  phase: string;
  jobId: string;
  immutableBindingDigest: string;
  automaticReplay: false;
  authorizationReusable: false;
  history: Array<{ sequence: number; kind: string; at: string; hash: string; previousHash: string }>;
}
export function CleanupAttemptHistory({ attemptId, snapshotDigest }: { attemptId: string; snapshotDigest: string }) {
  const [open, setOpen] = useState(false),
    [data, setData] = useState<Timeline>(),
    [error, setError] = useState("");
  useEffect(() => {
    setData(undefined);
    setError("");
    if (!open) return;
    const abort = new AbortController();
    void apiGet<Timeline>("/api/recovery-center/attempts/" + attemptId, { signal: abort.signal })
      .then((value) => {
        if (
          ![
            "REQUESTED",
            "AUTHORIZED",
            "WORKER_PENDING",
            "WORKER_ACTIVATED",
            "DISPATCH_ARMED",
            "DISPATCH_ATTEMPTED",
            "RESULT_RECEIVED",
            "RESTORATION_VERIFIED",
            "FAILED",
            "UNKNOWN",
            "NOT_EXECUTED"
          ].includes(value.phase) ||
          value.attemptId !== attemptId ||
          value.automaticReplay !== false ||
          value.authorizationReusable !== false ||
          !Array.isArray(value.history) ||
          value.history.some((e, i) => e.sequence !== i + 1 || !/^[a-f0-9]{64}$/.test(e.hash))
        )
          throw Error("Invalid history");
        if (!abort.signal.aborted) setData(value);
      })
      .catch(() => {
        if (!abort.signal.aborted) {
          setData(undefined);
          setError(
            "Attempt history is unavailable or failed integrity verification. No outcome or retry authority can be inferred."
          );
        }
      });
    return () => abort.abort();
  }, [attemptId, snapshotDigest, open]);
  return (
    <section aria-label="Immutable cleanup attempt history">
      <button type="button" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        {open ? "Hide attempt history" : "Inspect immutable attempt history"}
      </button>
      {error && <p role="alert">{error}</p>}
      {open && !data && !error && <p role="status">Loading source-bound history…</p>}
      {data && (
        <>
          <p>
            <strong>Current attempt: {data.phase}</strong>. Authorization is consumed. No automatic replay or quarantine
            clearance is available.
          </p>
          <ol style={{ listStyle: "none" }}>
            {data.history.map((e) => (
              <li key={e.sequence}>
                <strong>
                  {e.sequence}. {e.kind}
                </strong>{" "}
                — <time>{e.at}</time>
                <br />
                <code>{e.hash}</code>
              </li>
            ))}
          </ol>
          <p>
            Immutable binding <code>{data.immutableBindingDigest}</code>
          </p>
        </>
      )}
    </section>
  );
}
