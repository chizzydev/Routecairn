export { COLLECTION_ALGORITHM, collectionContractSchema, routeObservationSchema } from "./CollectionContracts.js";
export type { CollectionContract } from "./CollectionContracts.js";
import { COLLECTION_ALGORITHM, type CollectionContract } from "./CollectionContracts.js";
import { createHash } from "node:crypto";
import type { ApiGraphqlActorPlan } from "./ApiGraphqlTypes.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import { observedMarkerFingerprint } from "./ObservedMarker.js";
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => [k, canonical(v)])
  );
}
export const collectionHash = (v: unknown) =>
  createHash("sha256")
    .update(JSON.stringify(canonical(v ?? null)))
    .digest("hex");
export const collectionPrincipalHash = (v: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + v)
    .digest("hex")
    .slice(0, 16);
export function ownCollectionValue(value: unknown, path: string): unknown {
  let current = value;
  for (const part of path.split(".")) {
    if (
      !current ||
      typeof current !== "object" ||
      Array.isArray(current) ||
      !Object.hasOwn(current, part) ||
      ["__proto__", "prototype", "constructor"].includes(part)
    )
      return undefined;
    const d = Object.getOwnPropertyDescriptor(current, part);
    if (!d || !("value" in d)) return undefined;
    current = d.value;
  }
  return current;
}
export type CollectionEntry = {
  identityFingerprint: string;
  identityType: "string" | "number";
  ownerFingerprint: string;
  ownerType: "string";
  matchesActor: boolean;
};
export interface CollectionEvidence {
  algorithm: typeof COLLECTION_ALGORITHM;
  contract: CollectionContract;
  actorBinding: string;
  checkFingerprint: string;
  routeFingerprint: string;
  requestId: string | null;
  bodyFingerprint: string | null;
  bytesRead: number | null;
  evidenceFingerprint: string;
  status:
    | "SELF_COLLECTION_OBSERVED"
    | "FOREIGN_OWNER_OBSERVED"
    | "EMPTY"
    | "BOUND_EXCEEDED"
    | "INCOMPLETE"
    | "INVALID"
    | "UNPROVEN_IDENTITY";
  reason: string;
  totalParsedCount: number | null;
  checkedCount: number;
  mismatchCount: number;
  duplicateIds: boolean;
  unknownFields: boolean;
  entries: CollectionEntry[];
  coverage: CollectionContract["coverage"];
  globalCompletenessProven: boolean;
}
export const collectionActorBinding = (a: ApiGraphqlActorPlan) =>
  collectionHash({
    id: a.id,
    authSlot: a.authSlot,
    ...(a.authSlot === "registry" ? { registryId: a.registryId ?? null } : {}),
    identityModel: a.identityModel ?? "TENANT_AWARE",
    principalFingerprint: a.principalFingerprint ?? null,
    tenantFingerprint: a.tenantFingerprint ?? null,
    role: a.role ?? null
  });
export function observeCollection(
  contract: CollectionContract,
  response: HttpResponse,
  actor: ApiGraphqlActorPlan,
  checkFingerprint: string,
  routeFingerprint: string
): CollectionEvidence {
  const e: CollectionEvidence = {
    algorithm: COLLECTION_ALGORITHM,
    contract,
    actorBinding: collectionActorBinding(actor),
    checkFingerprint,
    routeFingerprint,
    requestId: response.requestId ?? null,
    bodyFingerprint: response.bodyHash ?? null,
    bytesRead: response.bytesRead ?? null,
    evidenceFingerprint: "",
    status: "INVALID",
    reason: "RESPONSE_NOT_COMPLETE",
    totalParsedCount: null,
    checkedCount: 0,
    mismatchCount: 0,
    duplicateIds: false,
    unknownFields: false,
    entries: [],
    coverage: contract.coverage,
    globalCompletenessProven: false
  };
  const finish = (status: CollectionEvidence["status"], reason: string) => {
    e.status = status;
    e.reason = reason;
    e.evidenceFingerprint = collectionHash({ ...e, evidenceFingerprint: "" });
    return e;
  };
  if (
    !actor.principalFingerprint ||
    actor.authSlot === "anonymous" ||
    (actor.authSlot === "registry" ? !actor.registryId : !actor.role)
  )
    return finish("UNPROVEN_IDENTITY", "VERIFIED_ACTOR_REQUIRED");
  const body = bodyPreviewForAnalysis(response);
  if (
    response.error ||
    response.streamTruncated !== false ||
    typeof body !== "string" ||
    !Number.isSafeInteger(response.bytesRead) ||
    !response.requestId ||
    !response.bodyHash
  )
    return finish("INCOMPLETE", "NATIVE_BYTE_WITNESS_REQUIRED");
  const bytes = Buffer.byteLength(body, "utf8");
  if (
    bytes > contract.maxResponseBytes ||
    response.bytesRead! > contract.maxResponseBytes ||
    (response.contentLength ?? 0) > contract.maxResponseBytes
  )
    return finish("BOUND_EXCEEDED", "RESPONSE_BYTE_BOUND_EXCEEDED");
  if (bytes !== response.bytesRead || createHash("sha256").update(body).digest("hex") !== response.bodyHash)
    return finish("INCOMPLETE", "BODY_BYTE_HASH_CONFLICT");
  const headers = headersForAnalysis(response);
  // Compressed wire lengths are not decompressed-body lengths. No guessed equivalence.
  const length = Object.entries(headers).find(([k]) => k.toLowerCase() === "content-length")?.[1];
  const encoding = Object.entries(headers).find(([k]) => k.toLowerCase() === "content-encoding")?.[1];
  if (encoding && encoding !== "identity") return finish("INCOMPLETE", "ENCODED_BODY_NOT_SUPPORTED");
  if (length !== undefined && (!/^\d+$/.test(String(length)) || Number(length) !== bytes))
    return finish("INCOMPLETE", "CONTENT_LENGTH_CONFLICT");
  const link = Object.entries(headers).find(([k]) => k.toLowerCase() === "link")?.[1];
  if (link !== undefined && /rel\s*=\s*["']?[^,;]*\bnext\b/i.test(String(link)))
    return finish("INCOMPLETE", "LINK_NEXT_PAGE");
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return finish("INVALID", "INVALID_JSON");
  }
  if (contract.pagination.kind !== "OWNER_DECLARED_UNPAGINATED") {
    const p = ownCollectionValue(parsed, contract.pagination.path);
    if (contract.pagination.kind === "HAS_MORE_BOOLEAN" ? p !== false : p !== null && p !== "")
      return finish("INCOMPLETE", "PAGINATION_NOT_COMPLETE");
  }
  for (const path of [
    "hasMore",
    "has_more",
    "pageInfo.hasNextPage",
    "pagination.hasMore",
    "nextCursor",
    "next_cursor",
    "pagination.nextCursor"
  ]) {
    const v = ownCollectionValue(parsed, path);
    if (v === true || (/cursor/i.test(path) && v !== undefined && v !== null && v !== ""))
      return finish("INCOMPLETE", "CONTRADICTORY_PAGINATION_METADATA");
  }
  const items = ownCollectionValue(parsed, contract.collectionPath);
  if (!Array.isArray(items)) return finish("INVALID", "COLLECTION_ARRAY_REQUIRED");
  e.totalParsedCount = items.length;
  if (items.length > contract.maxItems) return finish("BOUND_EXCEEDED", "ITEM_BOUND_EXCEEDED_NO_PREFIX_ACCEPTANCE");
  if (!items.length) return finish("EMPTY", "EMPTY_IS_NOT_OWNERSHIP_CONTROL");
  const ids = new Set<string>();
  for (let i = 0; i < items.length; i++) {
    if (!Object.hasOwn(items, i)) {
      e.unknownFields = true;
      continue;
    }
    const id = ownCollectionValue(items[i], contract.itemIdentityPath),
      owner = ownCollectionValue(items[i], contract.ownerPath);
    const validId =
      (typeof id === "string" && id.length > 0 && id.length <= 256) || (typeof id === "number" && Number.isFinite(id));
    if (!validId || typeof owner !== "string" || !owner.length || owner.length > 256) {
      e.unknownFields = true;
      continue;
    }
    const idHash = observedMarkerFingerprint(id as string | number),
      ownerHash = collectionPrincipalHash(owner);
    if (ids.has(idHash)) e.duplicateIds = true;
    ids.add(idHash);
    const matches = ownerHash === actor.principalFingerprint;
    if (!matches) e.mismatchCount++;
    e.entries.push({
      identityFingerprint: idHash,
      identityType: typeof id as "string" | "number",
      ownerFingerprint: ownerHash,
      ownerType: "string",
      matchesActor: matches
    });
    e.checkedCount++;
  }
  if (e.unknownFields || e.checkedCount !== items.length) return finish("INVALID", "UNKNOWN_ENTRY_FIELDS");
  if (e.duplicateIds) return finish("INVALID", "DUPLICATE_ITEM_IDENTITIES");
  e.globalCompletenessProven =
    contract.coverage === "UNPAGINATED_RESPONSE" && contract.pagination.kind === "OWNER_DECLARED_UNPAGINATED";
  return finish(
    e.mismatchCount ? "FOREIGN_OWNER_OBSERVED" : "SELF_COLLECTION_OBSERVED",
    e.mismatchCount ? "FOREIGN_OWNER_REQUIRES_REVIEW" : "OWN_COLLECTION_IS_NOT_FOREIGN_ACCESS"
  );
}
export function collectionEvidenceMatches(
  e: CollectionEvidence | undefined,
  c: CollectionContract,
  a: ApiGraphqlActorPlan,
  check: string,
  route: string
): boolean {
  if (
    !e ||
    e.algorithm !== COLLECTION_ALGORITHM ||
    e.evidenceFingerprint !== collectionHash({ ...e, evidenceFingerprint: "" }) ||
    collectionHash(c) !== collectionHash(e.contract) ||
    e.actorBinding !== collectionActorBinding(a) ||
    e.checkFingerprint !== check ||
    e.routeFingerprint !== route ||
    !e.requestId ||
    !e.bodyFingerprint ||
    !/^[a-f0-9]{64}$/.test(e.bodyFingerprint) ||
    !Number.isSafeInteger(e.bytesRead) ||
    e.bytesRead! > c.maxResponseBytes
  )
    return false;
  if (
    e.coverage !== c.coverage ||
    e.globalCompletenessProven !==
      (c.coverage === "UNPAGINATED_RESPONSE" && c.pagination.kind === "OWNER_DECLARED_UNPAGINATED") ||
    e.status !== (e.mismatchCount > 0 ? "FOREIGN_OWNER_OBSERVED" : "SELF_COLLECTION_OBSERVED")
  )
    return false;
  if (!["SELF_COLLECTION_OBSERVED", "FOREIGN_OWNER_OBSERVED"].includes(e.status)) return false;
  return (
    e.totalParsedCount !== null &&
    e.totalParsedCount > 0 &&
    e.totalParsedCount <= c.maxItems &&
    e.entries.length === e.totalParsedCount &&
    e.checkedCount === e.totalParsedCount &&
    !e.unknownFields &&
    !e.duplicateIds &&
    e.mismatchCount === e.entries.filter((x) => !x.matchesActor).length &&
    e.entries.every(
      (x) =>
        ["string", "number"].includes(x.identityType) &&
        /^[a-f0-9]{64}$/.test(x.identityFingerprint) &&
        x.ownerType === "string" &&
        /^[a-f0-9]{16}$/.test(x.ownerFingerprint) &&
        x.matchesActor === (x.ownerFingerprint === a.principalFingerprint)
    ) &&
    new Set(e.entries.map((x) => x.identityFingerprint)).size === e.entries.length
  );
}
