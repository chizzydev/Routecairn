import { ApplicationEvidenceTriage } from "./ApplicationEvidenceTriage";
import { ObservedStateRegression } from "./ObservedStateRegression";
import { GuidedApplicationMapping } from "./GuidedApplicationMapping";
import "./AuthorizationWorkbench.css";
import React, { useEffect, useState } from "react";
import { apiGet, apiMutation } from "./api";
import type { AuthorizationWorkbenchInput } from "../../../src/dashboard/contracts/AuthorizationWorkbenchContracts";
import type { AuthorizationWorkbenchService } from "../../../src/dashboard/execution/AuthorizationWorkbenchService";
type Review = Awaited<ReturnType<AuthorizationWorkbenchService["create"]>>;
type Result = ReturnType<AuthorizationWorkbenchService["result"]>;
export function AuthorizationWorkbench({
  onScan,
  onComparison,
  canExecute
}: {
  onScan: (id: string) => void;
  onComparison: (id: string) => void;
  canExecute: boolean;
}) {
  const [guided, setGuided] = useState(false);
  const [input, setInput] = useState<AuthorizationWorkbenchInput>(),
    [review, setReview] = useState<Review>(),
    [result, setResult] = useState<Result>(),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [consent, setConsent] = useState(false),
    [baseline, setBaseline] = useState(""),
    [comparison, setComparison] = useState<any>(),
    [options, setOptions] = useState<any>();
  const load = async () => setOptions(await apiGet("/api/authorization-workbench"));
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
        e instanceof Error
          ? e.message.includes("WORKBENCH_BINDINGS_CHANGED")
            ? "Bindings changed. Create and review a new revision; this request was refused (WORKBENCH_BINDINGS_CHANGED)."
            : e.message
          : "Evidence unavailable"
      );
    } finally {
      setBusy(false);
    }
  };
  const refresh = async () => {
    if (!review) return;
    const r = await apiGet<{ result: Result }>("/api/authorization-workbench/" + review.revisionId);
    setResult(r.result);
  };
  useEffect(() => {
    if (!review || !result?.scanId || !["QUEUED", "RUNNING", "PLANNING"].includes(result.status)) return;
    const t = setInterval(() => void refresh().catch((e) => setError(e.message)), 1000);
    return () => clearInterval(t);
  }, [review?.revisionId, result?.status]);
  return (
    <section className="authorization-workbench" aria-label="Application authorization workbench">
      <h2>Application Authorization</h2>
      <ObservedStateRegression canManage={canExecute} onScan={onScan} onComparison={onComparison} />
      <p>
        Observe the application, review a role and object matrix, run the exact permitted checks, and compare a
        remediation.
      </p>
      <div role="note">
        Owned loopback application only. Observations and proposed security questions are not findings or execution
        authority. Unknown bindings block execution. Trusted Discovery execution remains OFF.
      </div>
      {error && <p role="alert">{error}</p>}
      <button onClick={() => setGuided((v) => !v)}>
        {guided ? "Hide guided mapping" : "Start guided application mapping"}
      </button>
      {guided && (
        <GuidedApplicationMapping
          canExecute={canExecute}
          onScan={onScan}
          onMatrix={(r) => {
            if (r.classification === "READY_READ_ONLY") setGuided(false);
            setInput(r.input);
            setReview(r);
            setResult(undefined);
            setConsent(false);
            setComparison(undefined);
            void load().catch((e) => setError(e.message));
          }}
        />
      )}
      <label>
        Retained revision
        <select
          aria-label="Retained workbench revision"
          value={review?.revisionId ?? ""}
          disabled={busy}
          onChange={(e) => {
            if (!e.target.value) return;
            const id = e.target.value;
            void action(async () => {
              const r = await apiGet<Review & { result: Result }>("/api/authorization-workbench/" + id);
              setReview(r);
              setInput(r.input);
              setResult(r.result.status === "REVIEW_REQUIRED" ? undefined : r.result);
              setConsent(false);
              setComparison(undefined);
            });
          }}
        >
          <option value="">Open retained matrix and execution</option>
          {options?.revisions?.map((r: any) => (
            <option key={r.id} value={r.id}>
              {r.id} · version {r.version}
            </option>
          ))}
        </select>
      </label>
      <details>
        <summary>Advanced: import existing observation bindings</summary>
        <h3>1. Import observed application bindings</h3>
        <p>
          Use a completed API observation scan and its registered target. Import an expectation file with credential
          profile references, exact URLs bound to observed templates, object/tenant markers and an ALLOW/DENY control
          pair per operation. Credentials stay in the vault.
        </p>
        <details>
          <summary>Available observations and saved credentials</summary>
          <ul>
            {options?.scans?.map((s: any) => (
              <li key={s.id}>
                Scan {s.id} · target {s.target_id}
              </li>
            ))}
          </ul>
          <ul>
            {options?.credentials?.map((c: any) => (
              <li key={c.id}>
                {c.safeAlias} · {c.id}
              </li>
            ))}
          </ul>
        </details>
        <label>
          Import authorization expectations
          <input
            type="file"
            accept="application/json,.json"
            disabled={busy || !canExecute}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (!f) return;
              void action(async () => {
                if (f.size > 65536) throw Error("Expectation file exceeds 64 KiB");
                setInput(JSON.parse(await f.text()));
                setReview(undefined);
                setResult(undefined);
                setConsent(false);
                setComparison(undefined);
              });
            }}
          />
        </label>
      </details>
      {input && (
        <p>
          Target {input.targetId} · observation scan {input.sourceScanId} · {input.expectations.length} operations
        </p>
      )}
      <button
        disabled={busy || !input || !canExecute}
        onClick={() =>
          void action(async () => {
            const r = await apiMutation<Review>("/api/authorization-workbench/revisions", "POST", input);
            setReview(r);
            setResult(undefined);
            setConsent(false);
            await load();
          })
        }
      >
        Create versioned matrix
      </button>
      {review && (
        <>
          <h3>2. Review exact cases and proof budget</h3>
          <p role="status">
            {review.classification} · revision {review.revisionId}
          </p>
          <p>
            Maximum {review.proofBudget.totalRequestCeiling} requests; {review.proofBudget.checks} explicit checks,{" "}
            {review.proofBudget.identityRequests} identity verifications; {review.proofBudget.maxResponseBytes} bytes
            per response. GET only, no state-changing checks.
          </p>
          <ul>
            {review.blockers.map((b) => (
              <li key={b}>{b}</li>
            ))}
          </ul>
          <table>
            <caption>Role, tenant and object operation matrix</caption>
            <thead>
              <tr>
                <th>Operation</th>
                <th>Actor / role</th>
                <th>Actor tenant</th>
                <th>Object / function marker</th>
                <th>Expected decision</th>
                <th>Readiness</th>
                <th>Why proposed</th>
              </tr>
            </thead>
            <tbody>
              {review.matrix.map((c) => (
                <tr key={c.routeId + ":" + c.actorId}>
                  <td>{c.routeId}</td>
                  <td>
                    {c.actorId} · {c.role ?? "anonymous"}
                  </td>
                  <td>{c.tenantFingerprint ? c.tenantFingerprint.slice(0, 8) : "anonymous"}</td>
                  <td>
                    {String(
                      review.input.expectations.find((e) => e.routeId === c.routeId)?.identity?.expectedValue ??
                        "missing"
                    )}
                  </td>
                  <td>{c.decision}</td>
                  <td>{c.status}</td>
                  <td>
                    {c.reason}
                    <small>{c.securityCaseIds.length} linked SecurityCase IR sources</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <details>
            <summary>Exact request contracts and provenance</summary>
            <pre>
              {JSON.stringify(
                {
                  contract: review.request.apiGraphql,
                  transportIntents: review.transportIntents,
                  sharedScanLimits: review.preview?.limits,
                  sourceHash: review.sourceHash,
                  securityCases: review.provenance.securityCases,
                  authorizationQuestions: review.provenance.authorizationReview,
                  observations: review.provenance.observations
                },
                null,
                2
              )}
            </pre>
          </details>
          <p>
            Observation: routes and HTTP responses. Declared policy: expected role/tenant/ownership decisions.
            Hypothesis: the declared boundary might be violated. Proof requires the named object, a working allowed
            control and the actual denied actor response.
          </p>
          <label>
            <input
              type="checkbox"
              checked={consent}
              disabled={!canExecute || busy || !!result?.scanId}
              onChange={(e) => setConsent(e.target.checked)}
            />
            I authorize these exact bounded read-only fixture checks with the shown actor and tenant bindings.
          </label>
          <button
            disabled={busy || !consent || !canExecute || review.classification !== "READY_READ_ONLY" || !!result}
            onClick={() =>
              void action(async () => {
                const started = await apiMutation<{ scanId: string; status: string }>(
                  "/api/authorization-workbench/" + review.revisionId + "/execute",
                  "POST",
                  { digest: review.digest, confirmation: "I_AUTHORIZE_THE_EXACT_READ_ONLY_FIXTURE_CHECKS" }
                );
                setResult({
                  ...started,
                  revisionId: review.revisionId,
                  version: 0,
                  verifiedPass: false,
                  verifiedReadOnlyChecksPass: false,
                  transitionObservation: null
                });
              })
            }
          >
            Authorize and run selected matrix
          </button>
          <button disabled={busy} onClick={() => void action(refresh)}>
            Refresh execution evidence
          </button>
        </>
      )}
      {result?.hypothesisProposalId && (
        <ApplicationEvidenceTriage
          key={result.hypothesisProposalId}
          proposalId={result.hypothesisProposalId}
          canExecute={canExecute}
          onScan={onScan}
        />
      )}
      {result && (
        <>
          <h3>3. What actually executed</h3>
          <p role="status">
            Execution outcome: {result.status}.{" "}
            {result.transitionObservation
              ? result.verifiedReadOnlyChecksPass
                ? "The bounded read-only checks passed. State-change authorization was not tested; transition interpretation requires human review."
                : "Read-only findings or incomplete evidence require review. State-change authorization was not tested."
              : result.verifiedPass
                ? "All selected contracts matched in this execution."
                : "This is not a verified clean application or release."}
          </p>
          {result.transitionObservation && (
            <section aria-label="Transition evidence context">
              <h4>Transition evidence context</h4>
              <p>
                Event {result.transitionObservation.eventId}. Human-declared policy:{" "}
                {result.transitionObservation.declaredPolicy}. State {result.transitionObservation.statePath}:{" "}
                {JSON.stringify(result.transitionObservation.beforeState)} →{" "}
                {JSON.stringify(result.transitionObservation.afterState)}; revision{" "}
                {result.transitionObservation.fromRevision} → {result.transitionObservation.toRevision}.
              </p>
              <p>{result.transitionObservation.purpose}</p>
              <p>
                Before source {result.transitionObservation.beforeSourceHash}; after source{" "}
                {result.transitionObservation.afterSourceHash}. Reviewed authority key{" "}
                {result.transitionObservation.authorityKeySha256}; decision{" "}
                {result.transitionObservation.reviewDecisionId}.
              </p>
              <p>
                These are recorded event correlations and role-access checks. They do not verify state-change
                authorization or causality; explicit human interpretation is required.
              </p>
              <button onClick={() => onScan(result.transitionObservation!.beforeScanId)}>
                Open before transition observation
              </button>
              <button onClick={() => onScan(result.transitionObservation!.afterScanId)}>
                Open after transition observation
              </button>
            </section>
          )}
          {result.scanId && <button onClick={() => onScan(result.scanId!)}>Open scan and finding evidence</button>}
          {result.checks && (
            <table>
              <caption>Observed authorization results</caption>
              <thead>
                <tr>
                  <th>Case</th>
                  <th>Actor</th>
                  <th>Outcome</th>
                  <th>Proof / uncertainty</th>
                </tr>
              </thead>
              <tbody>
                {result.checks.map((c) => (
                  <tr key={c.checkId}>
                    <td>{c.checkId}</td>
                    <td>{c.actorAlias}</td>
                    <td>{c.outcome}</td>
                    <td>
                      {c.reasonCode === "EXPECTED_OBJECT_NOT_PROVEN"
                        ? "Returned a different object; access to the requested object is not proven."
                        : c.reasonCode === "ALLOW_CONTROL_NOT_CONFIRMED"
                          ? "The allowed control did not establish the expected resource."
                          : c.outcome === "PASS"
                            ? "The response matched the declared policy."
                            : c.outcome === "FAIL"
                              ? "The named resource was accessible contrary to the declared boundary."
                              : "Execution or proof is incomplete."}
                      <small>
                        {c.reasonCode} · HTTP {c.requests[0]?.statusCode ?? "not transmitted"}
                      </small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <h3>4. Verify remediation without rewriting history</h3>
          <label>
            Baseline revision
            <select aria-label="Baseline revision" value={baseline} onChange={(e) => setBaseline(e.target.value)}>
              <option value="">Select previous execution</option>
              {options?.revisions
                ?.filter((r: any) => r.id !== review?.revisionId)
                .map((r: any) => (
                  <option key={r.id} value={r.id}>
                    {r.id} · version {r.version}
                  </option>
                ))}
            </select>
          </label>
          <button
            disabled={busy || !baseline || !review || !canExecute}
            onClick={() =>
              void action(async () =>
                setComparison(
                  await apiMutation("/api/authorization-workbench/" + review!.revisionId + "/compare", "POST", {
                    baselineRevisionId: baseline
                  })
                )
              )
            }
          >
            Compare retained executions
          </button>
          {comparison && (
            <>
              <p role="status">
                Remediation comparison: {comparison.comparison.state} · resolved{" "}
                {comparison.comparison.summary.resolved} · not retested {comparison.comparison.summary.notRetested}.
                Historical gates unchanged.
              </p>
              <button onClick={() => onComparison(comparison.comparison.comparisonId)}>
                Open existing comparison evidence
              </button>
            </>
          )}
        </>
      )}
      {!canExecute && (
        <p>
          Read-only access. Scan creation and credential-use permissions are required to import and authorize a matrix.
        </p>
      )}
    </section>
  );
}
