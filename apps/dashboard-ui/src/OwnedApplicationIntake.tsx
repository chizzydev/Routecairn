import React, { useEffect, useRef, useState } from "react";
import { apiGet, apiMutation } from "./api";
import type { ApplicationMappingInput } from "../../../src/dashboard/contracts/ApplicationMappingContracts";
import type { OwnedApplicationIntakeService } from "../../../src/dashboard/execution/OwnedApplicationIntake";
type Receipt = ReturnType<OwnedApplicationIntakeService["get"]>;
type History = ReturnType<OwnedApplicationIntakeService["list"]>;
export function OwnedApplicationIntake({
  target,
  credentials,
  disabled,
  onApply
}: {
  target: string;
  credentials: ApplicationMappingInput["credentials"];
  disabled: boolean;
  onApply: (draft: ApplicationMappingInput) => void;
}) {
  const [text, setText] = useState(""),
    [receipt, setReceipt] = useState<Receipt>(),
    [history, setHistory] = useState<History>(),
    [retainedId, setRetainedId] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [consent, setConsent] = useState(false),
    generation = useRef(0);
  useEffect(() => {
    generation.current++;
    setText("");
    setReceipt(undefined);
    setHistory(undefined);
    setRetainedId("");
    setBusy(false);
    setError("");
    setConsent(false);
    return () => {
      generation.current++;
    };
  }, [target, credentials.primary, credentials.account_a, credentials.account_b]);
  const invalidate = () => {
    generation.current++;
    setReceipt(undefined);
    setBusy(false);
    setError("");
    setConsent(false);
  };
  return (
    <section aria-label="Owned application offline intake">
      <h4>Import an owner-prepared application evidence export</h4>
      <p>
        Use an already registered owned loopback application and its saved actors. Paste only minimized GET metadata: no
        raw HAR, headers, cookies, bodies or session secrets. The export is a declaration; fresh native identity
        verification is still required.
      </p>
      <details>
        <summary>Export contract and provenance requirements</summary>
        <p>
          Version 1 · kind MINIMIZED_HAR or OWNER_EVIDENCE_EXPORT · exact origin · capturedAt within seven days ·
          exportSha256 · provenance · routes with exact GET URLs, identityPath, tenantPath and up to two statePaths ·
          three actor slots with principal/tenant/role fingerprints and a non-secret sessionEvidenceSha256. Use the
          documented offline minimizer; this form never fetches the application.
        </p>
      </details>
      <label>
        Minimized owner evidence JSON
        <textarea
          aria-label="Minimized owner evidence JSON"
          value={text}
          maxLength={120000}
          disabled={disabled}
          onChange={(e) => {
            invalidate();
            setText(e.target.value);
          }}
          rows={8}
        />
      </label>
      <label>
        <input
          type="checkbox"
          checked={consent}
          disabled={disabled || busy}
          onChange={(e) => setConsent(e.target.checked)}
        />
        I own this application's evidence, reviewed the scope and removed secrets. Importing authorizes no traffic.
      </label>
      <button
        disabled={disabled || busy || !consent || !target || Object.values(credentials).some((c) => !c)}
        onClick={() => {
          const n = ++generation.current;
          setBusy(true);
          setError("");
          void Promise.resolve()
            .then(() =>
              apiMutation<Receipt>("/api/authorization-workbench/mapping/intake", "POST", {
                targetId: target,
                credentials,
                artifact: JSON.parse(text),
                ownerScopeConfirmed: true,
                offlineOnlyConfirmed: true
              })
            )
            .then((r) => {
              if (n === generation.current) {
                setReceipt(r);
                setConsent(false);
              }
            })
            .catch(() => {
              if (n === generation.current) {
                setReceipt(undefined);
                setConsent(false);
                setError(
                  "Import not confirmed. Validate the minimized contract, exact target and actor fingerprints; retained imports grant no execution authority. Inspect retained offline intakes before another explicit save; never automatically replay."
                );
              }
            })
            .finally(() => {
              if (n === generation.current) setBusy(false);
            });
        }}
      >
        Validate and retain offline intake
      </button>
      <button
        disabled={busy || !target}
        onClick={() => {
          const n = ++generation.current;
          setBusy(true);
          setError("");
          void apiGet<History>("/api/authorization-workbench/mapping/intakes?targetId=" + encodeURIComponent(target))
            .then((r) => {
              if (n === generation.current) setHistory(r);
            })
            .catch(() => {
              if (n === generation.current)
                setError("Retained intake history unavailable; no save or rollback can be inferred.");
            })
            .finally(() => {
              if (n === generation.current) setBusy(false);
            });
        }}
      >
        Inspect retained offline intakes
      </button>
      {history && (
        <>
          <p role="status">
            {history.records.length} newest of {history.total} retained intakes.{" "}
            {history.truncated
              ? "History is bounded; use an exact receipt ID for older records."
              : "No implicit replay."}
          </p>
          <label>
            Retained intake receipt
            <select
              aria-label="Retained intake receipt"
              value={retainedId}
              onChange={(e) => {
                invalidate();
                setRetainedId(e.target.value);
              }}
            >
              <option value="">Choose a source-bound receipt</option>
              {history.records.map((r) => (
                <option key={r.revisionId} value={r.revisionId}>
                  {r.createdAt} · {r.revisionId} · {r.artifactSha256}
                </option>
              ))}
            </select>
          </label>
        </>
      )}
      <label>
        Exact retained intake ID
        <input
          aria-label="Exact retained intake ID"
          value={retainedId}
          onChange={(e) => {
            invalidate();
            setRetainedId(e.target.value);
          }}
          maxLength={36}
        />
      </label>
      <button
        disabled={busy || !/^[a-f0-9-]{36}$/.test(retainedId)}
        onClick={() => {
          const n = ++generation.current;
          setBusy(true);
          setError("");
          void apiGet<Receipt>("/api/authorization-workbench/mapping/intakes/" + retainedId)
            .then((r) => {
              if (n !== generation.current) return;
              if (
                r.draft.targetId !== target ||
                (["primary", "account_a", "account_b"] as const).some((s) => r.draft.credentials[s] !== credentials[s])
              )
                throw Error("SELECTED_CONTEXT_MISMATCH");
              setReceipt(r);
              setConsent(false);
            })
            .catch(() => {
              if (n === generation.current) {
                setReceipt(undefined);
                setError(
                  "Receipt unavailable or belongs to different selected actors. No replay or authority restoration occurred."
                );
              }
            })
            .finally(() => {
              if (n === generation.current) setBusy(false);
            });
        }}
      >
        Open retained intake without replay
      </button>
      {error && <p role="alert">{error}</p>}
      {receipt && (
        <>
          <p role="status">
            Offline intake retained. Requests sent: {receipt.requestsSent}. Identity: {receipt.identityStatus}.
            Provenance: {receipt.provenance}.
          </p>
          <p>
            Immutable receipt {receipt.revisionId} · {receipt.digest} · context {receipt.freshness}
          </p>
          <ul>
            {receipt.missing.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          <button disabled={disabled || busy || receipt.freshness !== "CURRENT"} onClick={() => onApply(receipt.draft)}>
            Apply reviewed intake routes without execution
          </button>
        </>
      )}
    </section>
  );
}
