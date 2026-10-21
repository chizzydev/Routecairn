import type { AssessmentResourcePolicy } from "../../../src/dashboard/execution/AssessmentResourcePolicy";
export type ResourcePolicyDraft = AssessmentResourcePolicy extends infer P
  ? P extends { reviewed: true }
    ? Omit<P, "reviewed"> & { reviewed: boolean }
    : never
  : never;
type Policy = ResourcePolicyDraft;
/** UI drafts are proposals. The server validates scope, native prerequisites and every policy. */
export function ReviewedAssessmentResources({
  actors,
  resources,
  onChange
}: {
  actors: readonly { id: string; label: string }[];
  resources: Policy[];
  onChange: (p: Policy[]) => void;
}) {
  const update = (i: number, patch: Record<string, unknown>) =>
    onChange(resources.map((r, n) => (n === i ? ({ ...r, ...patch } as Policy) : r)));
  const create = (kind: Policy["kind"], i: number): Policy =>
    ({
      id: "policy" + i,
      path: "/",
      policyReference: "",
      reviewed: false,
      allowedStatuses: [200],
      deniedStatuses: [401, 403, 404],
      ...(kind === "OBJECT_OWNERSHIP"
        ? { kind, pathTemplate: "/resource/:id", ownerActorId: actors[0]?.id ?? "", ownerPath: "owner", ownerValue: "" }
        : kind === "COLLECTION_OWNERSHIP"
          ? {
              kind,
              collection: {
                kind: "COLLECTION",
                algorithm: "bounded-native-collection-v1",
                collectionPath: "items",
                itemIdentityPath: "id",
                ownerPath: "owner",
                ownerRule: "EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING",
                maxItems: 16,
                maxResponseBytes: 16384,
                coverage: "THIS_RESPONSE_ONLY",
                pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
              }
            }
          : kind === "FIELD_EXPOSURE"
            ? { kind, fieldPath: "internal", permittedActorIds: [actors[0]?.id ?? ""], roleAssuranceRequired: false }
            : kind === "BUSINESS_READ"
              ? { kind, actorIds: actors.map((a) => a.id), markerPath: "state", markerValue: "" }
              : { kind, actorIds: actors.map((a) => a.id) })
    }) as Policy;
  return (
    <section aria-label="Reviewed resource and workflow policies">
      <h4>Choose meaningful native checks</h4>
      <p>
        Review exact resources and policy evidence. Identity endpoints remain optional for observations. Ownership,
        field and business-state assertions require native principal proof. Policies never authorize writes or missing
        accounts.
      </p>
      {resources.map((r, i) => (
        <fieldset key={i}>
          <legend>Reviewed resource {i + 1}</legend>
          <label>
            Check family
            <select
              value={r.kind}
              onChange={(e) =>
                onChange(resources.map((x, n) => (n === i ? create(e.target.value as Policy["kind"], i) : x)))
              }
            >
              <option value="OBJECT_OWNERSHIP" disabled={actors.length < 2}>
                Object ownership comparison
              </option>
              <option value="COLLECTION_OWNERSHIP" disabled={actors.length < 2}>
                Bounded collection ownership
              </option>
              <option value="FIELD_EXPOSURE">Field exposure matrix</option>
              <option value="BUSINESS_READ">Business-state read with prior evidence</option>
              <option value="SESSION_READ">Session response observation</option>
            </select>
          </label>
          <label>
            Policy ID
            <input value={r.id} onChange={(e) => update(i, { id: e.target.value })} />
          </label>
          <label>
            Exact resource path
            <input value={r.path} onChange={(e) => update(i, { path: e.target.value })} />
          </label>
          <label>
            Reviewed policy reference
            <input value={r.policyReference} onChange={(e) => update(i, { policyReference: e.target.value })} />
          </label>
          {r.kind === "OBJECT_OWNERSHIP" && (
            <>
              <label>
                Safe resource path template
                <input value={r.pathTemplate} onChange={(e) => update(i, { pathTemplate: e.target.value })} />
              </label>
              <label>
                Resource owner actor
                <select value={r.ownerActorId} onChange={(e) => update(i, { ownerActorId: e.target.value })}>
                  {actors.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Owner field path
                <input value={r.ownerPath} onChange={(e) => update(i, { ownerPath: e.target.value })} />
              </label>
              <label>
                Exact owner principal
                <input value={r.ownerValue} onChange={(e) => update(i, { ownerValue: e.target.value })} />
              </label>
              <p>
                The owner must receive this exact resource; every other selected actor must be denied. The principal
                must match the bound owner profile and native proof.
              </p>
            </>
          )}
          {r.kind === "COLLECTION_OWNERSHIP" && (
            <>
              <p>
                Each actor may see only their own entries. Empty, truncated, duplicate, unknown-owner or incomplete
                pagination evidence is inconclusive.
              </p>
              {(["collectionPath", "itemIdentityPath", "ownerPath"] as const).map((k) => (
                <label key={k}>
                  {k}
                  <input
                    value={r.collection[k]}
                    onChange={(e) => update(i, { collection: { ...r.collection, [k]: e.target.value } })}
                  />
                </label>
              ))}
              <label>
                Maximum collection entries
                <input
                  type="number"
                  min="1"
                  max="64"
                  value={r.collection.maxItems}
                  onChange={(e) => update(i, { collection: { ...r.collection, maxItems: Number(e.target.value) } })}
                />
              </label>
              <label>
                Collection response byte limit
                <input
                  type="number"
                  min="512"
                  max="16384"
                  value={r.collection.maxResponseBytes}
                  onChange={(e) =>
                    update(i, { collection: { ...r.collection, maxResponseBytes: Number(e.target.value) } })
                  }
                />
              </label>
              <label>
                Pagination evidence
                <select
                  value={r.collection.pagination.kind}
                  onChange={(e) =>
                    update(i, {
                      collection: {
                        ...r.collection,
                        pagination:
                          e.target.value === "OWNER_DECLARED_UNPAGINATED"
                            ? { kind: e.target.value, ownerConfirmed: true }
                            : { kind: e.target.value, path: "hasMore" }
                      }
                    })
                  }
                >
                  <option value="HAS_MORE_BOOLEAN">Explicit has-more boolean</option>
                  <option value="NEXT_CURSOR">Explicit next cursor</option>
                  <option value="OWNER_DECLARED_UNPAGINATED">I confirm this response is unpaginated</option>
                </select>
              </label>
              {"path" in r.collection.pagination && (
                <label>
                  Pagination field path
                  <input
                    value={r.collection.pagination.path}
                    onChange={(e) =>
                      update(i, {
                        collection: {
                          ...r.collection,
                          pagination: { ...r.collection.pagination, path: e.target.value }
                        }
                      })
                    }
                  />
                </label>
              )}
              <p>Evidence boundary: this response only; no automatic pagination or global-completeness claim.</p>
            </>
          )}
          {r.kind === "FIELD_EXPOSURE" && (
            <>
              <label>
                Reviewed field path
                <input value={r.fieldPath} onChange={(e) => update(i, { fieldPath: e.target.value })} />
              </label>
              <label>
                Actor permitted to see field
                <select
                  value={r.permittedActorIds[0] ?? ""}
                  onChange={(e) => update(i, { permittedActorIds: [e.target.value] })}
                >
                  {actors.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={r.roleAssuranceRequired}
                  onChange={(e) => update(i, { roleAssuranceRequired: e.target.checked })}
                />
                Require independently verified roles
              </label>
            </>
          )}
          {r.kind === "BUSINESS_READ" && (
            <>
              <label>
                Business-state field
                <input value={r.markerPath} onChange={(e) => update(i, { markerPath: e.target.value })} />
              </label>
              <label>
                Exact expected state
                <input value={String(r.markerValue)} onChange={(e) => update(i, { markerValue: e.target.value })} />
              </label>
              <label>
                Prior business resource ID (optional)
                <input
                  value={r.prerequisiteResourceId ?? ""}
                  onChange={(e) => {
                    const p = { ...r };
                    if (e.target.value) p.prerequisiteResourceId = e.target.value;
                    else delete p.prerequisiteResourceId;
                    onChange(resources.map((x, n) => (n === i ? p : x)));
                  }}
                />
              </label>
            </>
          )}
          <label>
            <input type="checkbox" checked={r.reviewed} onChange={(e) => update(i, { reviewed: e.target.checked })} />I
            reviewed this exact policy, actors and read-only resource
          </label>
          <button type="button" onClick={() => onChange(resources.filter((_, n) => n !== i))}>
            Remove resource {i + 1}
          </button>
        </fieldset>
      ))}
      <button
        type="button"
        disabled={resources.length >= 4 || actors.length === 0}
        onClick={() => {
          let n = 0;
          while (resources.some((r) => r.id === "policy" + n)) n++;
          onChange([...resources, create(actors.length >= 2 ? "OBJECT_OWNERSHIP" : "SESSION_READ", n)]);
        }}
      >
        Add reviewed resource
      </button>
    </section>
  );
}
