import { useEffect, useState } from "react";
import { apiGet, apiMutation, DashboardApiError } from "./api";
import type { ObservedStateRegressionService } from "../../../src/dashboard/execution/ObservedStateRegressionService";
type Policy = ReturnType<ObservedStateRegressionService["get"]>;
type Assessment = ReturnType<ObservedStateRegressionService["assessment"]>;
const base = "/api/authorization-workbench/observed-state";
type EvidenceNav = { onScan?: ((id: string) => void) | undefined; onComparison?: ((id: string) => void) | undefined };
export function ObservedStateAssessment({ value, onScan, onComparison }: { value: Assessment } & EvidenceNav) {
  return (
    <article aria-label="Immutable observed-state assessment">
      <h4>
        {value.outcome} · {value.id}
      </h4>
      <p>
        Policy {value.policyId} · digest {value.policyDigest}
      </p>
      <p>
        Scope: observed state and access policy only. State-change authorization: NOT_TESTED. No causal proof, confirmed
        vulnerability, automatic replay or full application pass.
      </p>
      <p>Reasons: {value.reasons.join("; ") || "Exact reviewed observation policy compared"}</p>
      {value.sourceErrorCode && <p>Source diagnostic: {value.sourceErrorCode}</p>}
      <p>Native comparison: {value.comparisonId ?? "UNAVAILABLE — inspect reasons"}</p>
      <p>
        Baseline scan: {value.baselineSource.sourceScanId} · later scan:{" "}
        {value.currentSource?.sourceScanId ?? "UNTESTED"}
      </p>
      {onScan && value.currentSource?.sourceScanId && (
        <button onClick={() => onScan(value.currentSource!.sourceScanId!)}>Open observation scan evidence</button>
      )}
      {onScan && value.baselineSource.sourceScanId && (
        <button onClick={() => onScan(value.baselineSource.sourceScanId!)}>Open baseline observation evidence</button>
      )}
      {onComparison && value.comparisonId && (
        <button onClick={() => onComparison(value.comparisonId!)}>
          Open native scan comparison (policy assessed separately)
        </button>
      )}
      <table>
        <caption>Exact actor and route evidence</caption>
        <thead>
          <tr>
            <th>Actor / route</th>
            <th>Expected / observed access</th>
            <th>State outcome</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {value.cells.map((c) => (
            <tr key={c.checkId}>
              <td>
                {c.actorId} / {c.routeId}
              </td>
              <td>
                {c.expectedDecision} / {c.observedDecision}
              </td>
              <td>
                {c.outcome} · {c.stateAssessment}
                <br />
                {c.reasons.join("; ")}
              </td>
              <td>
                <details>
                  <summary>Typed marker fingerprints and binding</summary>
                  <pre>
                    {JSON.stringify(
                      {
                        actorBinding: c.actorBindingFingerprint,
                        expected: c.expectedMarkers,
                        observed: c.observedMarkers
                      },
                      null,
                      2
                    )}
                  </pre>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <details>
        <summary>Immutable source provenance</summary>
        <pre>
          {JSON.stringify(
            { baseline: value.baselineSource, current: value.currentSource, algorithm: value.algorithm },
            null,
            2
          )}
        </pre>
      </details>
    </article>
  );
}
export function ObservedStateAttention({ eager = false, ...nav }: { eager?: boolean } & EvidenceNav = {}) {
  const [opened, setOpened] = useState(false);
  return eager ? (
    <ObservedStateAttentionContent {...nav} />
  ) : (
    <details
      onToggle={(e) => {
        if (e.currentTarget.open) setOpened(true);
      }}
    >
      <summary>Observed-state attention &amp; evidence</summary>
      {opened && <ObservedStateAttentionContent {...nav} />}
    </details>
  );
}
function ObservedStateAttentionContent({ onScan, onComparison }: EvidenceNav) {
  const [data, setData] = useState<{
      alerts: Array<{
        id: string;
        category: string;
        safe_summary: string;
        acknowledged_at: string | null;
        summary: { observationAssessmentId: string };
      }>;
      policiesConfigured: number;
    }>(),
    [error, setError] = useState(""),
    [assessment, setAssessment] = useState<Assessment>();
  const load = async () => {
    try {
      const value = await apiGet<NonNullable<typeof data>>(base + "/attention");
      if (
        !value ||
        !Number.isSafeInteger(value.policiesConfigured) ||
        value.policiesConfigured < 0 ||
        !Array.isArray(value.alerts) ||
        value.alerts.length > 100 ||
        value.alerts.some(
          (n) =>
            !n ||
            typeof n.id !== "string" ||
            typeof n.category !== "string" ||
            typeof n.safe_summary !== "string" ||
            !n.summary ||
            typeof n.summary.observationAssessmentId !== "string"
        )
      )
        throw Error("INVALID_OBSERVATION_ATTENTION_PAYLOAD");
      setData(value);
      setError("");
    } catch {
      setData(undefined);
      setError("Observed-state evidence unavailable or permission denied. No healthy result is inferred.");
    }
  };
  useEffect(() => {
    void load();
  }, []);
  return (
    <section aria-label="Observed-state attention">
      <h3>Observed-state attention</h3>
      <p>Policy drift and missing evidence require review; these alerts are not confirmed findings.</p>
      <button onClick={() => void load()}>Refresh observed-state attention</button>
      {error && <p role="status">{error}</p>}
      {data && (
        <p>
          {data.policiesConfigured
            ? data.alerts.length
              ? "Review retained alerts below."
              : "No pending observed-state alerts in this view; this does not establish application security."
            : "UNTESTED — no reviewed observed-state policy configured."}
        </p>
      )}
      {data?.alerts.map((n) => (
        <article key={n.id}>
          <strong>{n.category}</strong>
          <p>{n.safe_summary}</p>
          <p>{n.acknowledged_at ? "Acknowledged; immutable assessment remains." : "Human review pending"}</p>
          <button
            onClick={() =>
              void apiGet<Assessment>(base + "/assessments/" + n.summary.observationAssessmentId)
                .then(setAssessment)
                .catch(() => setError("Assessment unavailable; no healthy result inferred."))
            }
          >
            Inspect observed-state alert {n.id.slice(0, 8)}
          </button>
        </article>
      ))}
      {assessment && <ObservedStateAssessment value={assessment} onScan={onScan} onComparison={onComparison} />}
    </section>
  );
}
export function ObservedStateRegression(props: { canManage: boolean } & EvidenceNav) {
  const [opened, setOpened] = useState(false);
  return (
    <details
      onToggle={(e) => {
        if (e.currentTarget.open) setOpened(true);
      }}
    >
      <summary>Observed-State Regression &amp; Continuous Assurance</summary>
      {opened && <ObservedStateRegressionContent {...props} />}
    </details>
  );
}
function ObservedStateRegressionContent({ canManage, onScan, onComparison }: { canManage: boolean } & EvidenceNav) {
  const [reviewAllowed, setReviewAllowed] = useState(false);
  const [policies, setPolicies] = useState<Policy[]>([]),
    [policy, setPolicy] = useState<Policy>(),
    [matrices, setMatrices] = useState<Array<{ id: string; version: number }>>([]),
    [matrix, setMatrix] = useState(""),
    [paths, setPaths] = useState<Array<{ routeId: string; path: string }>>([]),
    [name, setName] = useState("Reviewed observed-state expectations"),
    [purpose, setPurpose] = useState("Compare exact reviewed actor, object, tenant and business-state observations."),
    [age, setAge] = useState(60),
    [preview, setPreview] = useState<{ digest: string }>(),
    [consent, setConsent] = useState(false),
    [reason, setReason] = useState(""),
    [history, setHistory] = useState<Assessment[]>([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [caId, setCaId] = useState(""),
    [proof, setProof] = useState(""),
    [proofDigest, setProofDigest] = useState(""),
    [mapId, setMapId] = useState(""),
    [message, setMessage] = useState("");
  const load = async () => {
    const [p, w] = await Promise.all([
      apiGet<{ policies: Policy[]; canReviewPolicies: boolean }>(base + "/policies"),
      apiGet<{ revisions: Array<{ id: string; version: number }> }>("/api/authorization-workbench")
    ]);
    if (
      !Array.isArray(p.policies) ||
      !Array.isArray(w.revisions) ||
      p.policies.some(
        (v) => !v || typeof v.id !== "string" || !v.snapshot?.input || typeof v.snapshot.input.name !== "string"
      )
    )
      throw Error("Observed-state policy listing unavailable");
    setPolicies(p.policies);
    setReviewAllowed(p.canReviewPolicies === true);
    setMatrices(w.revisions);
  };
  useEffect(() => {
    void load().catch((e) => setError(e.message));
  }, []);
  const action = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(
        e instanceof DashboardApiError
          ? e.message + " " + e.diagnostics.map((d) => d.path.join(".") + ": " + d.message).join("; ")
          : e instanceof Error
            ? e.message
            : "Evidence unavailable"
      );
    } finally {
      setBusy(false);
    }
  };
  const open = async (id: string) => {
    const p = await apiGet<Policy>(base + "/policies/" + id);
    setPolicy(p);
    setCaId("");
    setConsent(false);
    setPreview(undefined);
    setHistory((await apiGet<{ assessments: Assessment[] }>(base + "/policies/" + id + "/assessments")).assessments);
  };
  const draft = () => ({
    name,
    purpose,
    matrixRevisionId: matrix,
    maximumObservationAgeMinutes: age,
    revisionPaths: paths,
    ...(policy ? { supersedes: policy.id } : {})
  });
  const caInput = () => ({
    schemaVersion: 1,
    name: name + " assurance",
    targetId: policy!.targetId,
    authorization: {
      proofReference: proof,
      proofDigest,
      validFrom: new Date(Date.now() - 60000).toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString()
    },
    triggers: { scheduleEnabled: false, intervalMinutes: 15, deploymentEnabled: false, quietWhenHealthy: true },
    observedStatePolicyVersionId: policy!.id,
    adapterProfileIds: [],
    baselines: [],
    requiredCases: [],
    gates: {
      failOnRegression: true,
      failOnNewFinding: true,
      failOnOpenDrift: true,
      requireExactCases: true,
      requireCleanupResolved: true
    },
    evidence: { retentionDays: 90, autoExportOn: [], preserveFailures: true, preserveCleanupEvidence: true }
  });
  return (
    <section aria-label="Reviewed observed-state regression">
      <p>
        Read retained native observations against immutable reviewed expectations. This workflow sends zero target
        requests. State-changing execution remains HOLD and state-change authorization is NOT_TESTED.
      </p>
      {(!canManage || !reviewAllowed) && <p>Owner review permission required for changes.</p>}
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
      <button disabled={busy} onClick={() => void action(load)}>
        Refresh observed-state policies
      </button>
      <label>
        Observed-state policy history
        <select
          aria-label="Observed-state policy history"
          value={policy?.id ?? ""}
          onChange={(e) => e.target.value && void action(() => open(e.target.value))}
        >
          <option value="">Select immutable policy</option>
          {policies.map((p) => (
            <option key={p.id} value={p.id}>
              {p.snapshot.input.name} · v{p.revision} · {p.status}
            </option>
          ))}
        </select>
      </label>
      {policy && (
        <p>
          Selected policy: {policy.status} · digest {policy.digest} · source {policy.snapshot.source.sourceScanId}
        </p>
      )}
      <fieldset disabled={!canManage || !reviewAllowed || busy}>
        <legend>1. Review exact expectations</legend>
        <label>
          Reviewed transition matrix
          <select
            aria-label="Reviewed transition matrix"
            value={matrix}
            onChange={(e) => {
              setMatrix(e.target.value);
              setPreview(undefined);
              void action(async () => {
                const m = await apiGet<{
                  input: { expectations: Array<{ routeId: string; states?: Array<{ path: string }> }> };
                }>("/api/authorization-workbench/" + e.target.value);
                setPaths(
                  m.input.expectations.map((r) => ({
                    routeId: r.routeId,
                    path: r.states?.find((s) => s.path.includes("revision"))?.path ?? ""
                  }))
                );
              });
            }}
          >
            <option value="">Select reviewed transition matrix</option>
            {matrices.map((m) => (
              <option key={m.id} value={m.id}>
                {m.id} · v{m.version}
              </option>
            ))}
          </select>
        </label>
        <label>
          Observed-state policy name
          <input
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setPreview(undefined);
            }}
          />
        </label>
        <label>
          Observed-state purpose
          <input
            value={purpose}
            onChange={(e) => {
              setPurpose(e.target.value);
              setPreview(undefined);
            }}
          />
        </label>
        <label>
          Maximum observation age minutes
          <input
            type="number"
            min={1}
            max={10080}
            value={age}
            onChange={(e) => {
              setAge(Number(e.target.value));
              setPreview(undefined);
            }}
          />
        </label>
        {paths.map((p, i) => (
          <label key={p.routeId}>
            Revision marker for {p.routeId}
            <input
              value={p.path}
              onChange={(e) => {
                setPaths((v) => v.map((r, j) => (j === i ? { ...r, path: e.target.value } : r)));
                setPreview(undefined);
              }}
            />
          </label>
        ))}
        <p>
          Revision changes require a newly reviewed policy. Fingerprints do not prove numeric ordering or causality.
        </p>
        <button
          disabled={!matrix}
          onClick={() => void action(async () => setPreview(await apiMutation(base + "/preview", "POST", draft())))}
        >
          Preview observed-state policy
        </button>
        {preview && (
          <>
            <pre aria-label="Observed-state policy preview">{JSON.stringify(preview, null, 2)}</pre>
            <button
              onClick={() =>
                void action(async () => {
                  const p = await apiMutation<Policy>(base + "/policies", "POST", draft());
                  await load();
                  await open(p.id);
                })
              }
            >
              Save immutable observation policy
            </button>
          </>
        )}
        {policy?.status === "REVIEW_REQUIRED" && (
          <>
            <label>
              <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />I trust the
              exact reviewed authority, actor, object, tenant, state and revision expectations; transition authorization
              remains NOT_TESTED.
            </label>
            <button
              disabled={!consent}
              onClick={() =>
                void action(async () => {
                  await apiMutation(base + "/policies/" + policy.id + "/decisions", "POST", {
                    action: "APPROVE",
                    digest: policy.digest,
                    authorityConfirmed: true,
                    expectationsConfirmed: true,
                    scopeConfirmation: "OBSERVATIONS_ONLY_TRANSITION_AUTHORIZATION_NOT_TESTED"
                  });
                  await load();
                  await open(policy.id);
                })
              }
            >
              Approve exact observation policy
            </button>
          </>
        )}
        {policy && policy.status !== "REVOKED" && (
          <>
            <label>
              Policy revocation reason
              <input value={reason} onChange={(e) => setReason(e.target.value)} />
            </label>
            <button
              disabled={reason.trim().length < 10}
              onClick={() =>
                void action(async () => {
                  await apiMutation(base + "/policies/" + policy.id + "/decisions", "POST", {
                    action: "REVOKE",
                    digest: policy.digest,
                    reason
                  });
                  await load();
                  await open(policy.id);
                })
              }
            >
              Revoke future observation policy use
            </button>
          </>
        )}
      </fieldset>
      {policy?.status === "APPROVED" && (
        <fieldset disabled={!canManage || !reviewAllowed || busy}>
          <legend>2. Review an observation-only assurance policy</legend>
          <label>
            Observation authorization reference
            <input value={proof} onChange={(e) => setProof(e.target.value)} />
          </label>
          <label>
            Observation authorization SHA-256
            <input value={proofDigest} onChange={(e) => setProofDigest(e.target.value)} />
          </label>
          <p>
            Manual assessments only in this form; authorization valid for one day. Scheduling and deployment triggers
            require a separate exact policy review. No new observations or replay are dispatched.
          </p>
          <button
            disabled={!proof || !/^[a-f0-9]{64}$/.test(proofDigest)}
            onClick={() =>
              void action(async () => {
                const value = caInput(),
                  created = await apiMutation<{ policy: { id: string; pendingVersionId: string } }>(
                    "/api/continuous-assurance/policies",
                    "POST",
                    value
                  ),
                  v = await apiMutation<{ preview: { policyDigest: string } }>(
                    "/api/continuous-assurance/preview",
                    "POST",
                    value
                  );
                await apiMutation("/api/continuous-assurance/policies/" + created.policy.id + "/review", "POST", {
                  versionId: created.policy.pendingVersionId,
                  policyDigest: v.preview.policyDigest,
                  confirmation: "I_CONFIRM_CONTINUOUS_ASSURANCE_POLICY"
                });
                setCaId(created.policy.id);
                setMessage("Observation-only assurance policy reviewed. No target requests sent.");
              })
            }
          >
            Create and review observation-only assurance
          </button>
          {caId && (
            <>
              <label>
                Later native map revision UUID (blank uses newest)
                <input value={mapId} onChange={(e) => setMapId(e.target.value)} />
              </label>
              <button
                onClick={() =>
                  void action(async () => {
                    await apiMutation("/api/continuous-assurance/policies/" + caId + "/run", "POST", {
                      confirmation: "I_CONFIRM_CONTINUOUS_ASSURANCE_RUN",
                      ...(mapId ? { mapRevisionId: mapId } : {})
                    });
                    const h = await apiGet<{ assessments: Assessment[] }>(
                      base + "/policies/" + policy.id + "/assessments"
                    );
                    setHistory(h.assessments);
                    setMessage("Retained observations evaluated. Inspect scope and evidence; no target requests sent.");
                  })
                }
              >
                Evaluate retained observations
              </button>
            </>
          )}
        </fieldset>
      )}
      <section aria-label="Observation policy immutable history">
        {policy && (
          <details>
            <summary>Immutable review and authority history</summary>
            <pre>
              {JSON.stringify(
                {
                  expectations: policy.snapshot.expectations,
                  revisionPaths: policy.snapshot.input.revisionPaths,
                  authority: policy.snapshot.authority,
                  decisions: policy.decisions,
                  source: policy.snapshot.source
                },
                null,
                2
              )}
            </pre>
          </details>
        )}
        {history.length ? (
          history.map((a) => (
            <ObservedStateAssessment key={a.id} value={a} onScan={onScan} onComparison={onComparison} />
          ))
        ) : (
          <p>UNTESTED — no retained assessment selected.</p>
        )}
      </section>
      <ObservedStateAttention
        eager
        key={history[0]?.id ?? policy?.id ?? "unselected"}
        onScan={onScan}
        onComparison={onComparison}
      />
    </section>
  );
}
