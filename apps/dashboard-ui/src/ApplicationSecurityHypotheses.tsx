import { CollectionOwnershipSummary } from "./CollectionOwnership";
import { reviewedScalar, assertReviewedScalar } from "./ReviewedPolicyInput";
import { BusinessRelationshipPanel } from "./BusinessRelationshipPanel";
import { ApplicationEvidenceTriage } from "./ApplicationEvidenceTriage";
import { ApplicationDifferentialReview } from "./ApplicationDifferentialReview";
import React, { useState } from "react";
import { apiGet, apiMutation } from "./api";
import type { ApplicationHypothesisService } from "../../../src/dashboard/execution/ApplicationHypothesisService";
import type { AuthorizationWorkbenchService } from "../../../src/dashboard/execution/AuthorizationWorkbenchService";
import type { buildApplicationHypotheses } from "../../../src/dashboard/execution/ApplicationSecurityHypotheses";
type Proposal = ReturnType<ApplicationHypothesisService["generate"]>;
type Candidate = ReturnType<typeof buildApplicationHypotheses>[number];
type Matrix = Awaited<ReturnType<AuthorizationWorkbenchService["create"]>>;
export function ApplicationSecurityHypotheses({
  mapId,
  canExecute,
  onMatrix,
  onScan
}: {
  mapId: string;
  canExecute: boolean;
  onMatrix: (value: Matrix) => void;
  onScan?: ((id: string) => void) | undefined;
}) {
  const [proposal, setProposal] = useState<Proposal>(),
    [detail, setDetail] = useState<{
      freshness: string;
      decisions: { id: string; action: string; createdAt: string; receipt: unknown }[];
      matrices: { id: string }[];
    }>(),
    [history, setHistory] = useState<{ id: string; created_at: string; supersedes: string | null }[]>([]),
    [selected, setSelected] = useState<Candidate>(),
    [identity, setIdentity] = useState(""),
    [tenant, setTenant] = useState(""),
    [explanation, setExplanation] = useState(""),
    [decisions, setDecisions] = useState({
      primary: "ALLOW",
      "account-a": "UNKNOWN",
      "account-b": "UNKNOWN",
      anonymous: "UNKNOWN"
    }),
    [confirmed, setConfirmed] = useState(false),
    [ownership, setOwnership] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [outcome, setOutcome] = useState("");
  const base = "/api/authorization-workbench/mapping/hypotheses";
  const load = async () => {
    const value = await apiGet<unknown>(base + "?mapRevisionId=" + mapId);
    if (!Array.isArray(value)) throw Error("UNKNOWN hypothesis history response");
    setHistory(value as { id: string; created_at: string; supersedes: string | null }[]);
  };
  const action = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "UNKNOWN hypothesis evidence");
    } finally {
      setBusy(false);
    }
  };
  const choose = (c: Candidate) => {
    setSelected(c);
    setIdentity("");
    setTenant("");
    setExplanation("");
    setDecisions({ primary: "ALLOW", "account-a": "UNKNOWN", "account-b": "UNKNOWN", anonymous: "UNKNOWN" });
    setConfirmed(false);
    setOwnership(false);
    setOutcome("");
  };
  const scalar = (path: string, value: string) => {
    const type = selected?.evidence[0]?.markers.find((m) => m.path === path)?.scalarType;
    const parsed = reviewedScalar(value, type === "number");
    assertReviewedScalar(parsed, type);
    return parsed;
  };
  return (
    <details
      onToggle={(e) => {
        if (e.currentTarget.open) void load().catch((e) => setError(e.message));
      }}
    >
      <summary>Evidence-grounded security hypotheses</summary>
      <p>
        Native observations suggest questions, never authorization truth or findings. Priority is a deterministic review
        order, not vulnerability probability. Read-only generation sends zero application requests.
      </p>
      {error && <p role="alert">{error}</p>}
      {outcome && <p role="status">Hypothesis review: {outcome}</p>}
      <label>
        Retained hypothesis proposal
        <select
          aria-label="Retained hypothesis proposal"
          value={proposal?.proposalId ?? ""}
          disabled={busy}
          onChange={(e) => {
            const id = e.target.value;
            if (id)
              void action(async () => {
                const value = await apiGet<
                  Proposal & {
                    freshness: string;
                    decisions: { id: string; action: string; createdAt: string; receipt: unknown }[];
                    matrices: { id: string }[];
                  }
                >(base + "/" + id);
                setProposal(value);
                setDetail(value);
                setSelected(undefined);
                setConfirmed(false);
              });
          }}
        >
          <option value="">Choose saved proposal</option>
          {history.map((h) => (
            <option key={h.id} value={h.id}>
              {h.id} · {h.created_at}
            </option>
          ))}
        </select>
      </label>
      <button
        disabled={busy || !canExecute}
        onClick={() =>
          void action(async () => {
            setProposal(await apiMutation(base, "POST", { mapRevisionId: mapId }));
            setSelected(undefined);
            setDetail(undefined);
            setOutcome("");
            await load();
          })
        }
      >
        Generate grounded hypotheses
      </button>
      {proposal && (
        <>
          <p>
            Proposal {proposal.proposalId} · algorithm {proposal.algorithm} · source{" "}
            {proposal.source.sourceHash ?? "UNKNOWN"}. Findings inferred: no.
          </p>
          <p>
            Target {proposal.source.targetId}; immutable map {proposal.source.mapRevisionId}; native scan{" "}
            {proposal.source.sourceScanId ?? "UNKNOWN"}.
          </p>
          {proposal.source.sourceScanId && onScan && (
            <button onClick={() => onScan(proposal.source.sourceScanId!)}>Open hypothesis source scan evidence</button>
          )}
          <BusinessRelationshipPanel
            key={"relationships-" + proposal.proposalId}
            proposal={proposal}
            canExecute={canExecute}
            onProposal={(p) => {
              setProposal(p);
              setDetail(undefined);
              setSelected(undefined);
              setOutcome("");
              void load();
            }}
          />
          <ApplicationEvidenceTriage
            key={"triage-" + proposal.proposalId}
            proposalId={proposal.proposalId}
            canExecute={canExecute}
            onScan={onScan}
          />
          <ApplicationDifferentialReview
            key={proposal.proposalId}
            proposal={proposal}
            canExecute={canExecute}
            onProposal={(p) => {
              setProposal(p);
              setDetail(undefined);
              setSelected(undefined);
              setOutcome("");
              void load();
            }}
            onMatrix={onMatrix}
          />
          <table aria-label="Grounded hypothesis candidates">
            <thead>
              <tr>
                <th>Declared route group</th>
                <th>Eligibility</th>
                <th>Review priority</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {proposal.candidates.map((c) => (
                <tr key={c.candidateId}>
                  <td>{c.group}</td>
                  <td>
                    {c.eligibility}
                    <br />
                    {c.missingControls.join(", ")}
                  </td>
                  <td>
                    {c.priority} · {c.priorityBasis}
                  </td>
                  <td>
                    <button disabled={busy} onClick={() => choose(c)}>
                      Inspect hypothesis {c.routeId}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button
            disabled={busy || !canExecute}
            onClick={() =>
              void action(async () => {
                setProposal(await apiMutation(base, "POST", { mapRevisionId: mapId, supersedes: proposal.proposalId }));
                setSelected(undefined);
                await load();
              })
            }
          >
            Create explicit superseding proposal
          </button>
          <button
            disabled={busy}
            onClick={() =>
              void action(async () => {
                const result = await apiGet<{
                  freshness: string;
                  decisions: { id: string; action: string; createdAt: string; receipt: unknown }[];
                  matrices: { id: string }[];
                }>(base + "/" + proposal.proposalId);
                setDetail(result);
                setOutcome(
                  result.freshness +
                    " · retained decisions " +
                    result.decisions.length +
                    " · linked matrices " +
                    result.matrices.length
                );
              })
            }
          >
            Inspect proposal freshness and history
          </button>
          {detail && (
            <section aria-label="Hypothesis review history">
              <p>Evidence freshness: {detail.freshness}</p>
              <ul>
                {detail.decisions.map((d) => (
                  <li key={d.id}>
                    {d.action} · {d.createdAt} · {d.id}
                    <pre>{JSON.stringify(d.receipt, null, 2)}</pre>
                  </li>
                ))}
              </ul>
              {detail.matrices.map((m) => (
                <button
                  key={m.id}
                  onClick={() =>
                    void action(async () => onMatrix(await apiGet<Matrix>("/api/authorization-workbench/" + m.id)))
                  }
                >
                  Open linked reviewed matrix {m.id}
                </button>
              ))}
              {detail.decisions.length > 0 && detail.matrices.length === 0 && (
                <p role="note">
                  Review retained; no matrix acknowledgement. No scan or replay was authorized. Retain this history for
                  explicit operator review.
                </p>
              )}
            </section>
          )}
        </>
      )}
      {selected && proposal && (
        <section aria-label="Hypothesis evidence review">
          <h4>
            {selected.routeId}: {selected.vulnerabilityConclusion}
          </h4>
          <p>
            GET {selected.url}. Policy and ownership are unknown until you declare them. Adaptive IR references:{" "}
            {selected.irCaseIds.join(", ")}
          </p>
          <table aria-label="Hypothesis native controls">
            <thead>
              <tr>
                <th>Actor / native check</th>
                <th>Observed control</th>
                <th>Typed non-secret markers (fingerprints)</th>
              </tr>
            </thead>
            <tbody>
              {selected.evidence.map((c) => (
                <tr key={c.actorId}>
                  <td>
                    {c.actorId} · {c.checkId}
                    <br />
                    Credential reference {c.credentialReference ?? "anonymous"}
                  </td>
                  <td>
                    {c.collection && <CollectionOwnershipSummary evidence={c.collection} />}
                    {c.nativeOutcome} · {c.decision} · HTTP {c.statusCode ?? "UNKNOWN"} · identity{" "}
                    {c.identityVerified ? "verified" : "UNKNOWN"}
                  </td>
                  <td>
                    {c.markers.map((m) => (
                      <div key={m.path}>
                        {m.path} ({m.scalarType}): {m.fingerprint ?? "UNKNOWN"}
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <ul>
            {selected.counterevidence.map((c) => (
              <li key={c.actorId}>
                {c.actorId}: {c.reason}
              </li>
            ))}
          </ul>
          <fieldset disabled={busy || !canExecute}>
            <legend>Human policy and ownership review</legend>
            <p>
              Enter approved non-secret fixture identifiers only. Values must match the successful typed primary
              control; nothing is extracted as policy.
            </p>
            <label>
              Expected hypothesis object marker
              <input
                disabled={!!selected.collection}
                aria-label="Expected hypothesis object marker"
                value={identity}
                onChange={(e) => {
                  setIdentity(e.target.value);
                  setConfirmed(false);
                }}
              />
            </label>
            {selected.tenantPath && (
              <label>
                Expected hypothesis tenant marker
                <input
                  aria-label="Expected hypothesis tenant marker"
                  value={tenant}
                  onChange={(e) => {
                    setTenant(e.target.value);
                    setConfirmed(false);
                  }}
                />
              </label>
            )}
            <label>
              Policy rationale
              <input
                aria-label="Hypothesis policy rationale"
                value={explanation}
                onChange={(e) => {
                  setExplanation(e.target.value);
                  setConfirmed(false);
                }}
              />
            </label>
            {(["account-a", "account-b", "anonymous"] as const).map((a) => (
              <label key={a}>
                {a} expected access
                <select
                  aria-label={"Hypothesis policy " + a}
                  value={decisions[a]}
                  onChange={(e) => {
                    setDecisions((d) => ({ ...d, [a]: e.target.value }));
                    setConfirmed(false);
                  }}
                >
                  <option value="UNKNOWN">Unknown</option>
                  <option value="ALLOW">Allow</option>
                  <option value="DENY">Deny</option>
                </select>
              </label>
            ))}
            <label>
              <input type="checkbox" checked={ownership} onChange={(e) => setOwnership(e.target.checked)} />I explicitly
              confirm ownership of this exact non-secret test resource.
            </label>
            <label>
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />I declare
              the expected policy; this observation does not establish a vulnerability.
            </label>
            <button
              disabled={
                !!proposal.transition ||
                !!proposal.relationships ||
                selected.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW" ||
                !confirmed ||
                !ownership ||
                (!selected.collection && !identity) ||
                (!!selected.tenantPath && !tenant) ||
                explanation.length < 10 ||
                Object.values(decisions).includes("UNKNOWN")
              }
              onClick={() =>
                void action(async () => {
                  const result = await apiMutation<Awaited<ReturnType<ApplicationHypothesisService["decide"]>>>(
                    base + "/" + proposal.proposalId + "/decisions",
                    "POST",
                    {
                      digest: proposal.digest,
                      candidateId: selected.candidateId,
                      action: "REVIEW",
                      policyConfirmed: true,
                      ownershipConfirmed: true,
                      ...(!selected.collection ? { identity: scalar(selected.identityPath, identity) } : {}),
                      ...(selected.tenantPath ? { tenant: scalar(selected.tenantPath, tenant) } : {}),
                      decisions,
                      explanation
                    }
                  );
                  setOutcome(result.status);
                  setConfirmed(false);
                  if (result.matrix) onMatrix(result.matrix);
                })
              }
            >
              Record policy and review bounded matrix
            </button>
            <button
              onClick={() =>
                void action(async () => {
                  const result = await apiMutation<{ status: string }>(
                    base + "/" + proposal.proposalId + "/decisions",
                    "POST",
                    {
                      digest: proposal.digest,
                      candidateId: selected.candidateId,
                      action: "REJECT",
                      reason: "EXPECTED_SHARED_ACCESS"
                    }
                  );
                  setOutcome(result.status);
                  setConfirmed(false);
                })
              }
            >
              Reject as expected shared access
            </button>
          </fieldset>
        </section>
      )}
    </details>
  );
}
