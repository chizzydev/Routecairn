import { it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  collectionContractSchema,
  observeCollection,
  collectionEvidenceMatches,
  collectionPrincipalHash,
  ownCollectionValue
} from "../../src/modules/apiGraphql/CollectionOwnership.js";
import type { HttpResponse } from "../../src/core/http/HttpTypes.js";
import type { ApiGraphqlActorPlan } from "../../src/modules/apiGraphql/ApiGraphqlTypes.js";
const contract = collectionContractSchema.parse({
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
});
const actor: ApiGraphqlActorPlan = {
  id: "primary",
  safeAlias: "primary",
  authSlot: "primary",
  relationship: "OWNER",
  identityModel: "PRINCIPAL_ROLE",
  principalFingerprint: collectionPrincipalHash("generated-person"),
  role: "user"
};
const hash = (s: string) => createHash("sha256").update(s).digest("hex"),
  check = hash("check"),
  route = hash("route");
const good = () => ({
  data: Array.from({ length: 4 }, (_, i) => ({
    id: "entry-" + i,
    owner: "generated-person",
    public_id: "same-shared-public-object"
  })),
  hasMore: false
});
const response = (value: unknown, patch: Partial<HttpResponse> = {}): HttpResponse => {
  const body = typeof value === "string" ? value : JSON.stringify(value);
  return {
    requestedUrl: "http://127.0.0.1/object",
    finalUrl: "http://127.0.0.1/object",
    method: "GET",
    headers: { "content-type": "application/json" },
    statusCode: 200,
    bodyPreview: body,
    bodyHash: hash(body),
    requestId: "owned-request",
    bytesRead: Buffer.byteLength(body),
    streamTruncated: false,
    responseTimeMs: 1,
    redirectChain: [],
    ...patch
  };
};
it("checks every item and distinguishes self from a final foreign owner", () => {
  const data = good(),
    self = observeCollection(contract, response(data), actor, check, route);
  expect(self.status).toBe("SELF_COLLECTION_OBSERVED");
  expect(self.checkedCount).toBe(4);
  expect(self.globalCompletenessProven).toBe(false);
  expect(collectionEvidenceMatches(self, contract, actor, check, route)).toBe(true);
  data.data[3]!.owner = "foreign";
  const e = observeCollection(contract, response(data), actor, check, route);
  expect(e.status).toBe("FOREIGN_OWNER_OBSERVED");
  expect(e.mismatchCount).toBe(1);
  expect(e.checkedCount).toBe(4);
  expect(JSON.stringify(e)).not.toContain("generated-person");
});
it.each([
  "over-cap",
  "empty",
  "duplicate",
  "missing-owner",
  "number-owner",
  "object-id",
  "null-item",
  "array-item",
  "partial",
  "missing-pagination",
  "object-collection",
  "invalid-json",
  "oversize"
])("abstains for %s", (name) => {
  const d: Record<string, unknown> = good();
  const items = d.data as Array<Record<string, unknown>>;
  if (name === "over-cap") items.push({ id: "last-foreign", owner: "foreign" });
  if (name === "empty") d.data = [];
  if (name === "duplicate") items[3] = items[0]!;
  if (name === "missing-owner") delete items[3]!.owner;
  if (name === "number-owner") items[3]!.owner = 17;
  if (name === "object-id") items[3]!.id = { nested: "id" };
  if (name === "null-item") items[3] = null as never;
  if (name === "array-item") items[3] = [] as never;
  if (name === "partial") d.hasMore = true;
  if (name === "missing-pagination") delete d.hasMore;
  if (name === "object-collection") d.data = { id: "not-array" };
  if (name === "oversize") d.padding = "x".repeat(9000);
  const e = observeCollection(contract, response(name === "invalid-json" ? "{" : d), actor, check, route);
  expect(["INVALID", "INCOMPLETE", "EMPTY", "BOUND_EXCEEDED"]).toContain(e.status);
  expect(collectionEvidenceMatches(e, contract, actor, check, route)).toBe(false);
});
it.each([
  { streamTruncated: true },
  { bytesRead: 1 },
  { bodyHash: hash("wrong") },
  { requestId: undefined },
  { error: { name: "Transport", message: "Interrupted" } },
  { headers: { link: '</next>; rel="next"' } },
  { headers: { "content-length": "2" } },
  { headers: { "content-encoding": "gzip" } }
] as Partial<HttpResponse>[])("refuses conflicting transport witness %j", (patch) => {
  const e = observeCollection(contract, response(good(), patch), actor, check, route);
  expect(["INCOMPLETE", "INVALID"]).toContain(e.status);
});
it("rejects inherited properties and accessors without evaluating them", () => {
  expect(ownCollectionValue(Object.create({ id: "inherited" }), "id")).toBeUndefined();
  let calls = 0;
  const o = Object.defineProperty({}, "id", {
    get() {
      calls++;
      return "unexpected";
    }
  });
  expect(ownCollectionValue(o, "id")).toBeUndefined();
  expect(calls).toBe(0);
  expect(ownCollectionValue({ data: [] }, "data.constructor")).toBeUndefined();
});
it.each(["__proto__.id", "constructor.id", "data[0].owner", "data.*.owner", "password", "id.__proto__"])(
  "rejects unsafe owner path %s",
  (ownerPath) => {
    expect(collectionContractSchema.safeParse({ ...contract, ownerPath }).success).toBe(false);
  }
);
it("rejects actor, slot, model, role, route and check replay", () => {
  const e = observeCollection(contract, response(good()), actor, check, route);
  for (const patch of [
    { id: "another" },
    { authSlot: "account_a" as const },
    { identityModel: "TENANT_AWARE" as const },
    { role: "admin" },
    { principalFingerprint: collectionPrincipalHash("foreign") }
  ])
    expect(collectionEvidenceMatches(e, contract, { ...actor, ...patch }, check, route)).toBe(false);
  expect(collectionEvidenceMatches(e, contract, actor, hash("other-check"), route)).toBe(false);
  expect(collectionEvidenceMatches(e, contract, actor, check, hash("other-source"))).toBe(false);
});
it("never invents global completeness from missing pagination", () => {
  expect(collectionContractSchema.safeParse({ ...contract, coverage: "UNPAGINATED_RESPONSE" }).success).toBe(false);
  const c = collectionContractSchema.parse({
      ...contract,
      coverage: "UNPAGINATED_RESPONSE",
      pagination: { kind: "OWNER_DECLARED_UNPAGINATED", ownerConfirmed: true }
    }),
    e = observeCollection(c, response(good()), actor, check, route);
  expect(e.globalCompletenessProven).toBe(true);
});
it("checks the entire ceiling of 64 and refuses a foreign 65th entry", () => {
  const c = { ...contract, maxItems: 64 },
    d = {
      data: Array.from({ length: 64 }, (_, i) => ({ id: i, owner: i === 63 ? "foreign" : "generated-person" })),
      hasMore: false
    };
  const e = observeCollection(c, response(d), actor, check, route);
  expect(e.checkedCount).toBe(64);
  expect(e.mismatchCount).toBe(1);
  d.data.push({ id: 64, owner: "foreign" });
  const exceeded = observeCollection(c, response(d), actor, check, route);
  expect(exceeded.status).toBe("BOUND_EXCEEDED");
  expect(exceeded.checkedCount).toBe(0);
  expect(exceeded.entries).toEqual([]);
});
it("refuses contradictory pagination even after an explicit unpaginated declaration", () => {
  const c = collectionContractSchema.parse({
    ...contract,
    coverage: "UNPAGINATED_RESPONSE",
    pagination: { kind: "OWNER_DECLARED_UNPAGINATED", ownerConfirmed: true }
  });
  expect(observeCollection(c, response({ ...good(), hasMore: true }), actor, check, route).status).toBe("INCOMPLETE");
});
it("canonical evidence survives object property ordering without changing meanings", () => {
  const e = observeCollection(contract, response(good()), actor, check, route);
  const reversed = JSON.parse(
    JSON.stringify(e, (_k, v) =>
      v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).reverse()) : v
    )
  );
  expect(collectionEvidenceMatches(reversed, contract, actor, check, route)).toBe(true);
});
