import "./BusinessFlowTriage.css";
import React, { useEffect, useRef, useState } from "react";
import { apiMutation } from "./api";
import type { ApplicationHypothesisService } from "../../../src/dashboard/execution/ApplicationHypothesisService";
import type { BusinessRelationship } from "../../../src/dashboard/contracts/BusinessRelationshipContracts";
type Proposal = ReturnType<ApplicationHypothesisService["generate"]>;
export function BusinessRelationshipPanel({
  proposal,
  canExecute,
  onProposal
}: {
  proposal: Proposal;
  canExecute: boolean;
  onProposal: (p: Proposal) => void;
}) {
  const ids = proposal.flow?.steps.map((s) => s.routeId) ?? proposal.candidates.slice(0, 2).map((c) => c.routeId),
    first = proposal.candidates.find((c) => c.routeId === ids[0]),
    second = proposal.candidates.find((c) => c.routeId === ids[1]);
  const paths = (id: string) =>
    proposal.candidates.find((c) => c.routeId === id)?.evidence[0]?.markers.map((m) => m.path) ?? [];
  const version = (id: string) => {
    const c = proposal.candidates.find((c) => c.routeId === id);
    return paths(id).find((p) => p !== c?.identityPath && p !== c?.tenantPath && /version|revision/i.test(p)) ?? "";
  };
  const [edges, setEdges] = useState<BusinessRelationship[]>(
      first && second
        ? [
            {
              name: "Reviewed producer and consumer",
              producer: first.routeId,
              consumer: second.routeId,
              identifier: first.identityPath,
              reference: second.identityPath,
              producerVersion: version(first.routeId),
              consumerVersion: version(second.routeId)
            }
          ]
        : []
    ),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const update = (i: number, k: Exclude<keyof BusinessRelationship, "ownership">, v: string) =>
    setEdges((old) => old.map((e, n) => (n === i ? { ...e, [k]: v } : e)));
  const r = proposal.relationships;
  return (
    <section className="business-relationship-panel" aria-label="Business relationship witnesses">
      <h4>Connect observed business operations</h4>
      <p>
        Choose exact observed fields. Matching typed identifiers establish a recorded reference, never ownership,
        permission or causality. Each entity version is separately pinned; these reads are not a transactional database
        snapshot. Declare access policy in the existing flow review, then separately authorize native GET proof.
      </p>
      {r ? (
        <>
          <table aria-label="Cross-step security questions">
            <thead>
              <tr>
                <th>Question / actor</th>
                <th>Review priority</th>
                <th>Evidence eligibility</th>
              </tr>
            </thead>
            <tbody>
              {r.questions.map((q) => (
                <tr key={q.questionId}>
                  <td>
                    {q.question}
                    <br />
                    {q.actorId} / {q.role ?? "anonymous"}: {q.producer} → {q.consumer}
                  </td>
                  <td>{q.priority} (deterministic review order, not probability)</td>
                  <td>
                    {q.eligibility}
                    <br />
                    {q.reasons.join("; ") || "Exact typed reference witnessed; owner policy still unknown."}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>
            Source scan {r.source.sourceScanId ?? "UNOBSERVED"} · {r.eligibility}. State-changing execution HOLD.
          </p>
          {r.relationships.map((e) => (
            <article key={e.relationshipId}>
              <h5>{e.declaration.name}</h5>
              <p>
                {e.declaration.producer} → {e.declaration.consumer}; {e.declaration.identifier} ={" "}
                {e.declaration.reference}. Versions: {e.declaration.producerVersion}, {e.declaration.consumerVersion}.
                Ownership: {e.ownership}. Owner evidence never implies access policy.
              </p>
              <p>
                {e.missingControls.join("; ") || "Primary relationship control observed. Owner policy still required."}
              </p>
              <table aria-label={"Relationship " + e.declaration.name}>
                <thead>
                  <tr>
                    <th>Actor / role</th>
                    <th>Observed relationship</th>
                    <th>Native evidence / missing controls</th>
                  </tr>
                </thead>
                <tbody>
                  {e.cells.map((c) => (
                    <tr key={c.actorId}>
                      <td>
                        {c.actorId} · {c.actorBinding.role ?? "anonymous"} · {c.ownerRelationship}
                        <br />
                        Principal {c.actorBinding.principalFingerprint ?? "unverified"}
                        <br />
                        Tenant {c.actorBinding.tenantFingerprint ?? "unverified"}
                      </td>
                      <td>
                        {c.relationshipObserved ? "Typed reference and versions align" : "Not established"}
                        <br />
                        {c.producerDecision} → {c.consumerDecision}
                      </td>
                      <td>
                        {c.producerCheckId} / {c.consumerCheckId}
                        <br />
                        {c.reasons.join("; ") || "Retained typed fingerprints; no policy inferred."}
                        <details>
                          <summary>Exact marker fingerprints</summary>
                          <pre>
                            {JSON.stringify(
                              {
                                observedOwner: c.observedOwner,
                                identifier: c.identifier,
                                reference: c.reference,
                                producerVersion: c.producerVersion,
                                consumerVersion: c.consumerVersion
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
            </article>
          ))}
        </>
      ) : (
        <fieldset disabled={busy || !canExecute || ids.length < 2}>
          <legend>Declare testable read-only producer/consumer relationships</legend>
          {edges.map((e, i) => (
            <div key={i}>
              <label>
                Relationship name
                <input
                  aria-label={"Relationship " + (i + 1) + " name"}
                  value={e.name}
                  onChange={(v) => update(i, "name", v.target.value)}
                />
              </label>
              {(["producer", "consumer"] as const).map((k) => (
                <label key={k}>
                  {k} operation
                  <select
                    aria-label={"Relationship " + (i + 1) + " " + k}
                    value={e[k]}
                    onChange={(v) => {
                      const id = v.target.value;
                      setEdges((old) =>
                        old.map((e, n) =>
                          n === i
                            ? {
                                ...e,
                                [k]: id,
                                ...(k === "producer"
                                  ? {
                                      identifier: proposal.candidates.find((c) => c.routeId === id)!.identityPath,
                                      producerVersion: version(id)
                                    }
                                  : {
                                      reference: proposal.candidates.find((c) => c.routeId === id)!.identityPath,
                                      consumerVersion: version(id)
                                    })
                              }
                            : e
                        )
                      );
                    }}
                  >
                    {ids.map((id) => (
                      <option key={id}>{id}</option>
                    ))}
                  </select>
                </label>
              ))}
              {(["identifier", "reference", "producerVersion", "consumerVersion"] as const).map((k) => (
                <label key={k}>
                  {k} observed field
                  <select
                    aria-label={"Relationship " + (i + 1) + " " + k}
                    value={e[k]}
                    onChange={(v) => update(i, k, v.target.value)}
                  >
                    <option value="">Choose observed field</option>
                    {paths(k === "identifier" || k === "producerVersion" ? e.producer : e.consumer).map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </label>
              ))}
              <label>
                <input
                  type="checkbox"
                  aria-label={"Relationship " + (i + 1) + " declare observed owner"}
                  checked={!!e.ownership}
                  onChange={(v) =>
                    setEdges((old) =>
                      old.map((x, n) =>
                        n === i
                          ? {
                              ...x,
                              ownership: v.target.checked
                                ? { path: "", actorId: "primary", principalId: "", tenantId: "" }
                                : undefined
                            }
                          : x
                      )
                    )
                  }
                />
                Corroborate an explicit owner using an already observed producer field
              </label>
              {e.ownership && (
                <fieldset>
                  <legend>Owner declaration, not permission</legend>
                  <label>
                    Observed owner field
                    <select
                      aria-label={"Relationship " + (i + 1) + " owner field"}
                      value={e.ownership.path}
                      onChange={(v) =>
                        setEdges((old) =>
                          old.map((x, n) =>
                            n === i ? { ...x, ownership: { ...x.ownership!, path: v.target.value } } : x
                          )
                        )
                      }
                    >
                      <option value="">Choose observed owner field</option>
                      {paths(e.producer)
                        .filter((p) => p !== e.identifier && p !== e.producerVersion)
                        .map((p) => (
                          <option key={p}>{p}</option>
                        ))}
                    </select>
                  </label>
                  <label>
                    Declared owner actor
                    <select
                      aria-label={"Relationship " + (i + 1) + " owner actor"}
                      value={e.ownership.actorId}
                      onChange={(v) =>
                        setEdges((old) =>
                          old.map((x, n) =>
                            n === i
                              ? {
                                  ...x,
                                  ownership: {
                                    ...x.ownership!,
                                    actorId: v.target.value as "primary" | "account-a" | "account-b"
                                  }
                                }
                              : x
                          )
                        )
                      }
                    >
                      {["primary", "account-a", "account-b"].map((a) => (
                        <option key={a}>{a}</option>
                      ))}
                    </select>
                  </label>
                  {(["principalId", "tenantId"] as const).map((k) => (
                    <label key={k}>
                      Declared owner {k}
                      <input
                        aria-label={"Relationship " + (i + 1) + " owner " + k}
                        maxLength={160}
                        value={e.ownership![k]}
                        onChange={(v) =>
                          setEdges((old) =>
                            old.map((x, n) =>
                              n === i ? { ...x, ownership: { ...x.ownership!, [k]: v.target.value } } : x
                            )
                          )
                        }
                      />
                    </label>
                  ))}
                </fieldset>
              )}
              {edges.length > 1 && (
                <button type="button" onClick={() => setEdges((v) => v.filter((_, n) => n !== i))}>
                  Remove relationship {i + 1}
                </button>
              )}
            </div>
          ))}
          <button
            disabled={edges.length >= 3}
            onClick={() => setEdges((v) => [...v, { ...v[0]!, name: "Another reviewed relationship" }])}
          >
            Add relationship
          </button>
          <button
            disabled={
              !canExecute || busy || !edges.length || edges.some((e) => !e.producerVersion || !e.consumerVersion)
            }
            onClick={() => {
              setBusy(true);
              setError("");
              void apiMutation<Proposal>("/api/authorization-workbench/mapping/hypotheses", "POST", {
                mapRevisionId: proposal.source.mapRevisionId,
                workflow: {
                  name: proposal.flow?.name ?? "Reviewed multi-step business relationships",
                  routeIds: ids,
                  relationships: edges
                }
              })
                .then((p) => {
                  if (alive.current) onProposal(p);
                })
                .catch(() => {
                  if (alive.current)
                    setError(
                      "Relationship proposal could not be confirmed. It may have been retained; inspect proposal history before another explicit action. No target request or proof was authorized."
                    );
                })
                .finally(() => {
                  if (alive.current) setBusy(false);
                });
            }}
          >
            Build evidence-bound relationship questions
          </button>
        </fieldset>
      )}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
