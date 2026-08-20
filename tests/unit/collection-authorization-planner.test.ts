import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";
import { planCollectionAuthorizationTesting, type CollectionAuthorizationInput } from "../../src/modules/collectionAuthorization/CollectionAuthorizationPlanner.js";

describe("collection authorization planner", () => {
  it("resolves a fixed collection case matrix and deeply freezes the plan", () => {
    const plan = planCollectionAuthorizationTesting(validInput("https://app.example.com"), {
      target: "https://app.example.com/",
      scope: exampleScope,
      authProfileSet: profileSet()
    });

    expect(plan.collections).toHaveLength(1);
    expect(plan.requestMatrix.map((testCase) => `${testCase.actorId}:${testCase.knownObjectId}`)).toEqual(["owner:doc-a", "viewer:doc-a", "public:doc-a"]);
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.collections[0]?.cases)).toBe(true);
    expect(JSON.stringify(plan)).not.toContain("session=account-a-secret");
    expect(JSON.stringify(plan)).not.toContain("session=account-b-secret");
  });

  it.each([
    ["missing actor", (input: CollectionAuthorizationInput) => (input.collections[0].cases[0].actorId = "ghost")],
    ["missing known object", (input: CollectionAuthorizationInput) => (input.collections[0].cases[0].knownObjectId = "missing")],
    ["duplicate known object", (input: CollectionAuthorizationInput) => (input.collections[0].knownObjects[1].objectId = "doc-a-001")],
    ["unsafe method", (input: CollectionAuthorizationInput) => (input.collections[0].method = "HEAD" as "GET")],
    ["body/query generator", (input: CollectionAuthorizationInput) => (input.collections[0].url = "https://app.example.com/api/projects?status=*")],
    ["pagination parameter", (input: CollectionAuthorizationInput) => (input.collections[0].url = "https://app.example.com/api/projects?page=2")],
    ["unsafe field path", (input: CollectionAuthorizationInput) => (input.collections[0].objectIdPath = "__proto__.id")],
    ["reference cycle", (input: CollectionAuthorizationInput) => {
      input.collections[0].cases[0].referenceCaseId = "viewer-sees-foreign";
      input.collections[0].cases[1].referenceCaseId = "owner-sees-own";
    }]
  ])("rejects %s", (_label, mutate) => {
    const input = validInput("https://app.example.com");
    mutate(input);
    expect(() => planCollectionAuthorizationTesting(input, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow();
  });

  it("rejects missing auth pair, same principal, reused auth material, and public auth", () => {
    expect(() => planCollectionAuthorizationTesting(validInput("https://app.example.com"), { target: "https://app.example.com/", scope: exampleScope })).toThrow(/requires --auth-a and --auth-b/);

    const samePrincipal = profileSet();
    samePrincipal.accountB.principalId = samePrincipal.accountA.principalId;
    const sameInput = validInput("https://app.example.com");
    sameInput.collections[0].actors[1].principalId = "principal-a";
    expect(() => planCollectionAuthorizationTesting(sameInput, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: samePrincipal })).toThrow(/same principal/);

    const reusedMaterial = profileSet();
    reusedMaterial.accountB.headers = { ...reusedMaterial.accountA.headers };
    expect(() => planCollectionAuthorizationTesting(validInput("https://app.example.com"), { target: "https://app.example.com/", scope: exampleScope, authProfileSet: reusedMaterial })).toThrow(/reused authentication material/);

    const publicAuth = validInput("https://app.example.com");
    publicAuth.collections[0].actors[2].authProfile = "account_a";
    expect(() => planCollectionAuthorizationTesting(publicAuth, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/Public collection actor/);
  });
});

function validInput(origin: string): CollectionAuthorizationInput {
  return {
    schemaVersion: 1,
    maxCollections: 1,
    maxCasesPerCollection: 10,
    maxKnownObjects: 5,
    maxRequests: 10,
    maxRetainedObservations: 10,
    maxPreviewLength: 80,
    collections: [
      {
        id: "project-list",
        label: "Project list",
        category: "LIST",
        method: "GET",
        url: `${origin}/api/projects?status=active`,
        headers: { Accept: "application/json" },
        expectedContentType: "application/json",
        completeness: "FIXED_RESULT_WINDOW",
        resultArrayPath: "items",
        objectIdPath: "id",
        objectTenantPath: "tenant",
        objectOwnerPath: "owner",
        objectStatePath: "state",
        objectTypePath: "type",
        maxInspectedEntries: 20,
        maxResponseBytes: 65536,
        maxJsonDepth: 8,
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active" },
          { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active" },
          { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
        ],
        knownObjects: [
          { id: "doc-a", objectId: "doc-a-001", objectType: "project", ownerActorId: "owner", tenantId: "tenant-a", state: "active", confirmedSafeToTest: true },
          { id: "doc-b", objectId: "doc-b-001", objectType: "project", ownerActorId: "viewer", tenantId: "tenant-b", state: "active", confirmedSafeToTest: true }
        ],
        cases: [
          { id: "owner-sees-own", actorId: "owner", knownObjectId: "doc-a", expectedMembership: "MUST_CONTAIN", requireVerifiedIdentity: false },
          { id: "viewer-sees-foreign", actorId: "viewer", knownObjectId: "doc-a", expectedMembership: "MUST_NOT_CONTAIN", expectedActorRelationship: "CROSS_TENANT_MEMBER", requireVerifiedIdentity: false },
          { id: "public-no-private", actorId: "public", knownObjectId: "doc-a", expectedMembership: "MUST_NOT_CONTAIN", requireVerifiedIdentity: false }
        ]
      }
    ]
  };
}

function profileSet(): AuthProfileSet {
  return {
    accountA: { label: "account-a", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active", headers: { Cookie: "session=account-a-secret" }, cookies: [], notes: [] },
    accountB: { label: "account-b", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active", headers: { Cookie: "session=account-b-secret" }, cookies: [], notes: [] }
  };
}
