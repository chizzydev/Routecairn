import { expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  observeCollection,
  collectionEvidenceMatches,
  collectionActorBinding,
  collectionContractSchema,
  collectionPrincipalHash
} from "../../src/modules/apiGraphql/CollectionOwnership.js";
import type { ApiGraphqlActorPlan } from "../../src/modules/apiGraphql/ApiGraphqlTypes.js";
const contract = collectionContractSchema.parse({
  kind: "COLLECTION",
  algorithm: "bounded-native-collection-v1",
  collectionPath: "items",
  itemIdentityPath: "id",
  ownerPath: "owner",
  ownerRule: "EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING",
  maxItems: 4,
  maxResponseBytes: 4096,
  coverage: "THIS_RESPONSE_ONLY",
  pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
});
it("retains legacy role requirements and separates registry identity/credential-source witnesses", () => {
  const body = JSON.stringify({ items: [{ id: "one", owner: "actor0" }], hasMore: false }),
    hash = createHash("sha256").update(body).digest("hex");
  const response = {
    requestedUrl: "http://127.0.0.1/collection",
    finalUrl: "http://127.0.0.1/collection",
    method: "GET" as const,
    headers: { "content-type": "application/json" },
    statusCode: 200,
    bodyPreview: body,
    bodyHash: hash,
    requestId: "owned",
    bytesRead: Buffer.byteLength(body),
    streamTruncated: false,
    responseTimeMs: 1,
    redirectChain: []
  };
  const legacy: ApiGraphqlActorPlan = {
    id: "actor0",
    safeAlias: "Actor",
    authSlot: "primary",
    relationship: "OWNER",
    principalFingerprint: collectionPrincipalHash("actor0")
  };
  expect(observeCollection(contract, response, legacy, "check", "route").status).toBe("UNPROVEN_IDENTITY");
  const registry: ApiGraphqlActorPlan = { ...legacy, authSlot: "registry", registryId: "native-registry-1" };
  const observed = observeCollection(contract, response, registry, "registry-source-check", "route");
  expect(observed.status).toBe("SELF_COLLECTION_OBSERVED");
  expect(collectionEvidenceMatches(observed, contract, registry, "registry-source-check", "route")).toBe(true);
  expect(
    collectionEvidenceMatches(
      observed,
      contract,
      { ...registry, registryId: "another-registry" },
      "registry-source-check",
      "route"
    )
  ).toBe(false);
  expect(collectionActorBinding({ ...legacy, role: "user" })).not.toBe(collectionActorBinding(registry));
  expect(
    collectionEvidenceMatches(observed, contract, { ...legacy, role: "user" }, "registry-source-check", "route")
  ).toBe(false);
  const missing = { ...registry };
  delete missing.registryId;
  expect(observeCollection(contract, response, missing, "check", "route").status).toBe("UNPROVEN_IDENTITY");
});
