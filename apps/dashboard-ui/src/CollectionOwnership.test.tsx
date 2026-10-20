// @vitest-environment jsdom
import React from "react";
import { afterEach, it, expect } from "vitest";
import { cleanup, render, fireEvent, screen } from "@testing-library/react";
import { CollectionOwnershipControls, CollectionOwnershipSummary } from "./CollectionOwnership";
import type { CollectionContract, CollectionEvidence } from "../../../src/modules/apiGraphql/CollectionOwnership";
afterEach(cleanup);
const contract: CollectionContract = {
  kind: "COLLECTION",
  algorithm: "bounded-native-collection-v1",
  collectionPath: "data",
  itemIdentityPath: "id",
  ownerPath: "owner",
  ownerRule: "EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING",
  maxItems: 4,
  maxResponseBytes: 8192,
  coverage: "THIS_RESPONSE_ONLY",
  pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
};
it("requires explicit pagination declaration and exposes bounded non-secret paths", () => {
  let value = contract;
  const change = (v: CollectionContract) => {
    value = v;
  };
  render(<CollectionOwnershipControls value={value} onChange={change} />);
  expect(screen.getByLabelText("Collection maximum entries").getAttribute("max")).toBe("64");
  expect(screen.getByLabelText("Collection maximum response bytes").getAttribute("max")).toBe("65536");
  fireEvent.change(screen.getByLabelText("Collection ownerPath"), { target: { value: "user_id" } });
  expect(value.ownerPath).toBe("user_id");
  fireEvent.click(screen.getByRole("checkbox"));
  expect(value.coverage).toBe("UNPAGINATED_RESPONSE");
  expect(value.pagination.kind).toBe("OWNER_DECLARED_UNPAGINATED");
});
it.each([
  "SELF_COLLECTION_OBSERVED",
  "FOREIGN_OWNER_OBSERVED",
  "EMPTY",
  "BOUND_EXCEEDED",
  "INCOMPLETE",
  "INVALID"
] as const)("explains %s without granting execution", (status) => {
  render(
    <CollectionOwnershipSummary
      evidence={
        {
          status,
          contract,
          checkedCount: 4,
          totalParsedCount: 4,
          mismatchCount: status === "FOREIGN_OWNER_OBSERVED" ? 1 : 0,
          coverage: "THIS_RESPONSE_ONLY",
          globalCompletenessProven: false,
          reason: "Native exact evidence"
        } as CollectionEvidence
      }
    />
  );
  expect(screen.getByText(status)).toBeTruthy();
  expect(screen.getByText(/No global completeness claim/)).toBeTruthy();
  expect(screen.queryByRole("button")).toBeNull();
  expect(screen.getByText(/A successful own collection does not prove foreign-user access/)).toBeTruthy();
});
