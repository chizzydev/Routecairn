import React from "react";
import type { CollectionContract, CollectionEvidence } from "../../../src/modules/apiGraphql/CollectionOwnership";
export function CollectionOwnershipSummary({ evidence }: { evidence: CollectionEvidence }) {
  return (
    <div role="note" aria-label="Bounded collection evidence">
      <strong>{evidence.status}</strong>
      <p>{evidence.reason}</p>
      <p>
        Checked {evidence.checkedCount} of {evidence.totalParsedCount ?? "unknown"} parsed entries ·{" "}
        {evidence.mismatchCount} foreign owners · limit {evidence.contract.maxItems} items /{" "}
        {evidence.contract.maxResponseBytes} bytes
      </p>
      <p>
        {evidence.coverage} ·{" "}
        {evidence.globalCompletenessProven ? "Owner-declared unpaginated response" : "No global completeness claim"}
      </p>
      <p>
        Empty, incomplete or ambiguous evidence cannot establish ownership. A successful own collection does not prove
        foreign-user access. Findings require exact reviewed policy and a fresh native proof.
      </p>
    </div>
  );
}
export function CollectionOwnershipControls({
  value,
  onChange
}: {
  value: CollectionContract;
  onChange: (value: CollectionContract) => void;
}) {
  return (
    <fieldset>
      <legend>Bounded collection ownership contract</legend>
      <p>
        Each entry must belong to the verified requesting principal. Entry identity is distinct from a shared public
        object ID. One GET; no page following.
      </p>
      {(["collectionPath", "itemIdentityPath", "ownerPath"] as const).map((key) => (
        <label key={key}>
          {key}
          <input
            aria-label={"Collection " + key}
            value={value[key]}
            onChange={(e) => onChange({ ...value, [key]: e.target.value })}
          />
        </label>
      ))}
      <label>
        Maximum entries
        <input
          aria-label="Collection maximum entries"
          type="number"
          min={1}
          max={64}
          value={value.maxItems}
          onChange={(e) => onChange({ ...value, maxItems: Number(e.target.value) })}
        />
      </label>
      <label>
        Maximum response bytes
        <input
          aria-label="Collection maximum response bytes"
          type="number"
          min={512}
          max={65536}
          value={value.maxResponseBytes}
          onChange={(e) => onChange({ ...value, maxResponseBytes: Number(e.target.value) })}
        />
      </label>
      <label>
        Pagination witness
        <select
          aria-label="Collection pagination witness"
          value={value.pagination.kind}
          onChange={(e) => {
            const kind = e.target.value as "HAS_MORE_BOOLEAN" | "NEXT_CURSOR";
            onChange({
              ...value,
              coverage: "THIS_RESPONSE_ONLY",
              pagination: { kind, path: kind === "HAS_MORE_BOOLEAN" ? "hasMore" : "nextCursor" }
            });
          }}
        >
          <option value="HAS_MORE_BOOLEAN">has-more must be false</option>
          <option value="NEXT_CURSOR">next cursor must be null or empty</option>
          {value.pagination.kind === "OWNER_DECLARED_UNPAGINATED" && (
            <option value="OWNER_DECLARED_UNPAGINATED">Owner declares no pagination</option>
          )}
        </select>
      </label>
      {value.pagination.kind !== "OWNER_DECLARED_UNPAGINATED" && (
        <label>
          Pagination field
          <input
            aria-label="Collection pagination path"
            value={value.pagination.path}
            onChange={(e) =>
              onChange({
                ...value,
                pagination: { ...value.pagination, path: e.target.value } as CollectionContract["pagination"]
              })
            }
          />
        </label>
      )}
      <label>
        <input
          type="checkbox"
          checked={value.pagination.kind === "OWNER_DECLARED_UNPAGINATED"}
          onChange={(e) =>
            onChange(
              e.target.checked
                ? {
                    ...value,
                    coverage: "UNPAGINATED_RESPONSE",
                    pagination: { kind: "OWNER_DECLARED_UNPAGINATED", ownerConfirmed: true }
                  }
                : {
                    ...value,
                    coverage: "THIS_RESPONSE_ONLY",
                    pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
                  }
            )
          }
        />
        I explicitly confirm this response is unpaginated. Contradictory pagination evidence still blocks proof.
      </label>
    </fieldset>
  );
}
