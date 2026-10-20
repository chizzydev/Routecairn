import { ApplicationTransitionPanel } from "./ApplicationTransitionPanel";
import type { TransitionReview } from "../../../src/dashboard/contracts/ApplicationTransitionContracts";
import React, { useState } from "react";
import { apiMutation } from "./api";
import type { ApplicationHypothesisService } from "../../../src/dashboard/execution/ApplicationHypothesisService";
import type { AuthorizationWorkbenchService } from "../../../src/dashboard/execution/AuthorizationWorkbenchService";
type Proposal = ReturnType<ApplicationHypothesisService["generate"]>;
type Matrix = Awaited<ReturnType<AuthorizationWorkbenchService["create"]>>;
export function ApplicationDifferentialReview({
  proposal,
  canExecute,
  onProposal,
  onMatrix
}: {
  proposal: Proposal;
  canExecute: boolean;
  onProposal: (p: Proposal) => void;
  onMatrix: (m: Matrix) => void;
}) {
  const [steps, setSteps] = useState(proposal.candidates.slice(0, 2).map((c) => c.routeId)),
    [transitionReview, setTransitionReview] = useState<TransitionReview>(),
    [name, setName] = useState("Reviewed role and business-state observations"),
    [values, setValues] = useState<Record<string, string>>({}),
    [ownership, setOwnership] = useState(false),
    [policy, setPolicy] = useState(false),
    [relationship, setRelationship] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [outcome, setOutcome] = useState("");
  const flow = proposal.flow,
    base = "/api/authorization-workbench/mapping/hypotheses";
  const action = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "UNKNOWN differential evidence");
    } finally {
      setBusy(false);
    }
  };
  const update = (key: string, value: string) => {
    setValues((v) => ({ ...v, [key]: value }));
    setPolicy(false);
    setOwnership(false);
  };
  const scalar = (route: string, path: string) => {
    const c = proposal.candidates.find((c) => c.routeId === route)!,
      raw = values[route + ":" + path] ?? "";
    if (!raw.trim()) throw Error("Exact non-secret typed values required");
    return c.evidence[0]!.markers.find((m) => m.path === path)?.scalarType === "number" ? Number(raw) : raw;
  };
  return (
    <section aria-label="Reviewed role and business-flow differential testing">
      <h4>Reviewed role &amp; business-flow differential testing</h4>
      <p>
        Ordered, owner-declared read-only prerequisites. No mutation, causal transition or vulnerability is inferred.
        Each step retains its native actor, typed state, counterevidence and case references. Mutation execution remains
        HOLD.
      </p>
      {flow && flow.steps.length >= 2 && (
        <ApplicationTransitionPanel
          proposal={proposal}
          canExecute={canExecute}
          onProposal={onProposal}
          onReview={(r) => {
            setTransitionReview(r);
            setOwnership(false);
            setPolicy(false);
          }}
        />
      )}
      {!flow ? (
        <>
          <label>
            Workflow name
            <input aria-label="Differential workflow name" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          {steps.map((id, i) => (
            <label key={i}>
              Ordered step {i + 1}
              <select
                aria-label={"Differential step " + (i + 1)}
                value={id}
                onChange={(e) => setSteps((v) => v.map((id, n) => (n === i ? e.target.value : id)))}
              >
                {proposal.candidates.map((c) => (
                  <option value={c.routeId} key={c.candidateId}>
                    {c.routeId} · {c.kind}
                  </option>
                ))}
              </select>
            </label>
          ))}
          <button
            disabled={busy || !canExecute || steps.length >= 4 || steps.length >= proposal.candidates.length}
            onClick={() => setSteps((v) => [...v, proposal.candidates.find((c) => !v.includes(c.routeId))!.routeId])}
          >
            Add differential step
          </button>
          <button
            disabled={
              busy || !canExecute || steps.length < 2 || new Set(steps).size !== steps.length || name.trim().length < 4
            }
            onClick={() =>
              void action(async () => {
                onProposal(
                  await apiMutation(base, "POST", {
                    mapRevisionId: proposal.source.mapRevisionId,
                    workflow: { name, routeIds: steps }
                  })
                );
              })
            }
          >
            Draft reviewed differential workflow
          </button>
        </>
      ) : (
        <>
          <p>
            Flow {flow.flowId} · {flow.version} · {flow.eligibility}. Shared budget ≤{flow.maximumSharedRequests};
            selected module checks {flow.maximumModuleRequests}; concurrency1; exact GET only.
          </p>
          <p>{flow.missingControls.join(", ") || "Observed controls ready for explicit policy review."}</p>
          {flow.steps.map((step, i) => {
            const c = proposal.candidates.find((c) => c.candidateId === step.candidateId)!;
            return (
              <fieldset key={step.routeId}>
                <legend>
                  Flow step {i + 1}: {step.routeId}
                </legend>
                <p>
                  Prerequisite: {step.dependsOn.join(", ") || "None declared"}; {c.url}; {c.kind}. Native checks{" "}
                  {c.nativeCheckIds.join(", ")}; cases {step.irCaseIds.join(", ")}.
                </p>
                <p>
                  Observed typed state fingerprints:{" "}
                  {c.evidence[0]!.markers.filter((m) => step.statePaths.includes(m.path))
                    .map((m) => m.path + ":" + m.scalarType + ":" + m.fingerprint)
                    .join("; ")}
                  . Counterevidence: {c.counterevidence.map((v) => v.actorId + ":" + v.reason).join("; ")}
                </p>
                {[c.identityPath, ...(c.tenantPath ? [c.tenantPath] : []), ...step.statePaths].map((path) => (
                  <label key={path}>
                    Expected non-secret {path} (
                    {c.evidence[0]!.markers.find((m) => m.path === path)?.scalarType ?? "UNKNOWN"})
                    <input
                      aria-label={"Flow " + step.routeId + " " + path}
                      value={values[step.routeId + ":" + path] ?? ""}
                      onChange={(e) => update(step.routeId + ":" + path, e.target.value)}
                    />
                  </label>
                ))}
                {c.evidence.map((actor) => (
                  <label key={actor.actorId}>
                    {actor.actorId} · role {actor.roleLabel ?? "anonymous"} · observed {actor.decision},{" "}
                    {actor.nativeOutcome}
                    <select
                      aria-label={"Flow " + step.routeId + " " + actor.actorId + " decision"}
                      value={
                        actor.actorId === "primary"
                          ? "ALLOW"
                          : (values[step.routeId + ":" + actor.actorId] ?? "UNKNOWN")
                      }
                      disabled={actor.actorId === "primary"}
                      onChange={(e) => update(step.routeId + ":" + actor.actorId, e.target.value)}
                    >
                      <option>UNKNOWN</option>
                      <option>ALLOW</option>
                      <option>DENY</option>
                    </select>
                  </label>
                ))}
              </fieldset>
            );
          })}
          <label>
            Resource relationship and prerequisite explanation
            <textarea
              aria-label="Flow relationship explanation"
              value={relationship}
              onChange={(e) => {
                setRelationship(e.target.value);
                setPolicy(false);
                setOwnership(false);
              }}
            />
          </label>
          <label>
            <input type="checkbox" checked={ownership} onChange={(e) => setOwnership(e.target.checked)} />I confirm
            ownership and these exact cross-step resource relationships.
          </label>
          <label>
            <input type="checkbox" checked={policy} onChange={(e) => setPolicy(e.target.checked)} />I declare the exact
            role, tenant and state policies for every step.
          </label>
          <button
            disabled={
              busy ||
              !canExecute ||
              flow.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW" ||
              (!!proposal.relationships && proposal.relationships.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW") ||
              (!!proposal.transition && !transitionReview) ||
              !ownership ||
              !policy ||
              relationship.trim().length < 10
            }
            onClick={() =>
              void action(async () => {
                const expectations = flow.steps.map((step) => {
                  const c = proposal.candidates.find((c) => c.candidateId === step.candidateId)!;
                  const decisions = Object.fromEntries(
                    c.evidence.map((a) => [
                      a.actorId,
                      a.actorId === "primary" ? "ALLOW" : (values[step.routeId + ":" + a.actorId] ?? "UNKNOWN")
                    ])
                  );
                  if (Object.values(decisions).includes("UNKNOWN"))
                    throw Error("Every actor policy must be explicitly declared");
                  return {
                    routeId: c.routeId,
                    url: c.url,
                    kind:
                      c.kind === "FUNCTION"
                        ? "FUNCTION_AUTHORIZATION"
                        : c.tenantPath
                          ? "TENANT_ISOLATION"
                          : "OBJECT_AUTHORIZATION",
                    explanation: relationship,
                    decisions,
                    identity: { path: c.identityPath, expectedValue: scalar(c.routeId, c.identityPath) },
                    ...(c.tenantPath
                      ? { tenant: { path: c.tenantPath, expectedValue: scalar(c.routeId, c.tenantPath) } }
                      : {}),
                    states: step.statePaths.map((path) => ({ path, expectedValue: scalar(c.routeId, path) })),
                    dependsOn: step.dependsOn
                  };
                });
                const d = await apiMutation<{ matrix: Matrix }>(
                  base + "/" + proposal.proposalId + "/decisions",
                  "POST",
                  {
                    action: "REVIEW_FLOW",
                    digest: proposal.digest,
                    candidateId: flow.flowId,
                    policyConfirmed: true,
                    ownershipConfirmed: true,
                    relationshipExplanation: relationship,
                    ...(proposal.transition ? { transitionReview } : {}),
                    expectations
                  }
                );
                setOutcome(
                  "Immutable flow review recorded. Review the existing exact matrix and separately approve native proof."
                );
                onMatrix(d.matrix);
              })
            }
          >
            Review flow into existing proof matrix
          </button>
          <button
            disabled={busy || !canExecute}
            onClick={() =>
              void action(async () => {
                await apiMutation(base + "/" + proposal.proposalId + "/decisions", "POST", {
                  action: "REJECT",
                  digest: proposal.digest,
                  candidateId: flow.flowId,
                  reason: "NOT_A_SECURITY_BOUNDARY"
                });
                setOutcome("Flow rejected and retained without execution.");
              })
            }
          >
            Reject differential workflow
          </button>
        </>
      )}
      {outcome && <p role="status">{outcome}</p>}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
