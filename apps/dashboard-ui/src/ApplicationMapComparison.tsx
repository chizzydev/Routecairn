import React, { useState } from "react";
import { apiGet, apiMutation } from "./api";
import type { ApplicationMapComparisonService } from "../../../src/dashboard/execution/ApplicationMapComparison";
type Comparison = ReturnType<ApplicationMapComparisonService["create"]>;
export function ApplicationMapComparison({
  maps,
  saved,
  currentId,
  onSaved
}: {
  maps: { id: string; version: number }[];
  saved: { id: string }[];
  currentId?: string | undefined;
  onSaved?: () => void;
}) {
  const [baseline, setBaseline] = useState(""),
    [result, setResult] = useState<Comparison>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const run = async (fn: () => Promise<Comparison>) => {
    setBusy(true);
    setError("");
    try {
      setResult(await fn());
      onSaved?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Comparison unavailable");
    } finally {
      setBusy(false);
    }
  };
  return (
    <details>
      <summary>Compare retained application maps</summary>
      <p>
        Read-only observed differences are hypotheses, never authorization findings. Missing evidence remains UNKNOWN.
      </p>
      <label>
        Baseline application map
        <select aria-label="Baseline application map" value={baseline} onChange={(e) => setBaseline(e.target.value)}>
          <option value="">Choose retained baseline</option>
          {maps.map((m) => (
            <option key={m.id} value={m.id}>
              {m.id} · {m.version}
            </option>
          ))}
        </select>
      </label>
      <button
        disabled={busy || !baseline || !currentId}
        onClick={() =>
          void run(() =>
            apiMutation<Comparison>("/api/authorization-workbench/mapping/comparisons", "POST", {
              baselineRevisionId: baseline,
              currentRevisionId: currentId
            })
          )
        }
      >
        Compare observed maps
      </button>
      <label>
        Retained immutable map comparison
        <select
          aria-label="Retained immutable map comparison"
          defaultValue=""
          onChange={(e) => {
            const id = e.target.value;
            if (id) void run(() => apiGet<Comparison>("/api/authorization-workbench/mapping/comparisons/" + id));
          }}
        >
          <option value="">Open saved comparison</option>
          {saved.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id}
            </option>
          ))}
        </select>
      </label>
      {error && <p role="alert">{error}</p>}
      {result && (
        <>
          <p role="status">
            Map comparison: {result.status} · {result.comparisonId}
          </p>
          <small>
            Immutable digest: {result.digest}. Native source hashes: {result.baseline.sourceHash ?? "UNOBSERVED"} /{" "}
            {result.current.sourceHash ?? "UNOBSERVED"}
          </small>
          <table aria-label="Application map differences">
            <thead>
              <tr>
                <th>Route</th>
                <th>Declared membership</th>
                <th>Observed changes</th>
              </tr>
            </thead>
            <tbody>
              {result.routes.map((r) => (
                <tr key={r.key}>
                  <td>{r.url}</td>
                  <td>{r.membership}</td>
                  <td>
                    {r.observation}
                    <ul>
                      {r.cells.map((c) => (
                        <li key={c.actorId}>
                          {c.actorId}: {c.before.classification} → {c.after.classification} · {c.accessChange}; response{" "}
                          {c.responseChange}; {c.markerTypes.map((m) => m.path + ": " + m.change).join(", ")}
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>No policy or vulnerability conclusion is inferred.</p>
        </>
      )}
    </details>
  );
}
