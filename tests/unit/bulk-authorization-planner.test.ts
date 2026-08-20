import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";
import { planBulkAuthorizationTesting, type BulkAuthorizationInput } from "../../src/modules/bulkAuthorization/BulkAuthorizationPlanner.js";

describe("bulk authorization planner", () => {
  it("resolves fixed GET and JSON POST cases and freezes the request matrix", () => {
    const plan = planBulkAuthorizationTesting(validInput("https://app.example.com"), { target: "https://app.example.com/", scope: { ...exampleScope, allowedMethods: ["GET", "POST"] }, authProfileSet: profileSet() });
    expect(plan.requestMatrix).toHaveLength(2);
    expect(plan.requestMatrix[0]?.url).toContain("id=obj-a&id=obj-b");
    expect(plan.requestMatrix[1]?.body).toContain('"objectIds":["obj-a","obj-b"]');
    expect(plan.requestMatrix[1]?.body).not.toContain("{{OBJECT_IDS_ARRAY}}");
    expect(Object.isFrozen(plan.requestMatrix[0]?.objects)).toBe(true);
    expect(JSON.stringify(plan)).not.toContain("session=account-a-secret");
  });

  it.each([
    ["duplicate object IDs", (input: BulkAuthorizationInput) => (input.definitions[0].cases[0].objects[1].objectId = "obj-a")],
    ["numeric object ID", (input: BulkAuthorizationInput) => (input.definitions[0].cases[0].objects[0].objectId = 1 as unknown as string)],
    ["unsafe method", (input: BulkAuthorizationInput) => (input.definitions[0].cases[0].method = "DELETE" as "GET")],
    ["missing actor", (input: BulkAuthorizationInput) => (input.definitions[0].cases[0].actorId = "ghost")],
    ["POST missing marker", (input: BulkAuthorizationInput) => delete input.definitions[0].cases[1].safetyContract.requiredRequestMarkerPath],
    ["unknown placeholder", (input: BulkAuthorizationInput) => (input.definitions[0].cases[1].bodyTemplate = { ids: "{{UNKNOWN}}" })],
    ["out of scope", (input: BulkAuthorizationInput) => (input.definitions[0].cases[0].url = "https://evil.example.com/bulk?id={{OBJECT_ID_LIST_REPEATED}}")],
    ["incompatible baseline actor", (input: BulkAuthorizationInput) => (input.definitions[0].cases[0].objects[1].baseline = { id: "foreign-baseline", source: "SAFE_GET", actorId: "ghost", method: "GET", url: "https://app.example.com/api/projects/{{OBJECT_ID}}", expectedDecision: "MUST_DENY", objectIdentityField: "id" })],
    ["POST in GET_ONLY safety mode", (input: BulkAuthorizationInput) => (input.definitions[0].cases[1].postSafetyMode = "GET_ONLY")],
    ["verified POST without postconditions", (input: BulkAuthorizationInput) => (input.definitions[0].cases[1].postSafetyMode = "POSTCONDITION_VERIFIED_DRY_RUN")]
  ])("rejects %s", (_label, mutate) => {
    const input = validInput("https://app.example.com");
    mutate(input);
    expect(() => planBulkAuthorizationTesting(input, { target: "https://app.example.com/", scope: { ...exampleScope, allowedMethods: ["GET", "POST"] }, authProfileSet: profileSet() })).toThrow();
  });

  it("rejects missing auth pair, same principal, reused auth material, and public auth", () => {
    expect(() => planBulkAuthorizationTesting(validInput("https://app.example.com"), { target: "https://app.example.com/", scope: { ...exampleScope, allowedMethods: ["GET", "POST"] } })).toThrow(/requires --auth-a and --auth-b/);
    const samePrincipal = profileSet();
    samePrincipal.accountB.principalId = samePrincipal.accountA.principalId;
    const same = validInput("https://app.example.com");
    same.definitions[0].actors[1].principalId = "principal-a";
    expect(() => planBulkAuthorizationTesting(same, { target: "https://app.example.com/", scope: { ...exampleScope, allowedMethods: ["GET", "POST"] }, authProfileSet: samePrincipal })).toThrow(/same principal/);
    const reused = profileSet();
    reused.accountB.headers = { ...reused.accountA.headers };
    expect(() => planBulkAuthorizationTesting(validInput("https://app.example.com"), { target: "https://app.example.com/", scope: { ...exampleScope, allowedMethods: ["GET", "POST"] }, authProfileSet: reused })).toThrow(/reused authentication material/);
    const publicAuth = validInput("https://app.example.com");
    publicAuth.definitions[0].actors[2].authProfile = "account_a";
    expect(() => planBulkAuthorizationTesting(publicAuth, { target: "https://app.example.com/", scope: { ...exampleScope, allowedMethods: ["GET", "POST"] }, authProfileSet: profileSet() })).toThrow(/Public bulk actor/);
  });
});

function validInput(origin: string): BulkAuthorizationInput {
  return {
    schemaVersion: 1,
    maxDefinitions: 1,
    maxCasesPerDefinition: 4,
    maxObjectsPerCase: 4,
    maxRequests: 4,
    maxRetainedObservations: 4,
    definitions: [
      {
        id: "bulk-projects",
        label: "Bulk projects",
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active" },
          { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active" },
          { id: "public", relationship: "PUBLIC" }
        ],
        cases: [bulkCase(origin, "get-preview", "GET_REPEATED_QUERY", "GET"), bulkCase(origin, "post-dry-run", "JSON_POST", "POST")]
      }
    ]
  };
}

function bulkCase(origin: string, id: string, requestStyle: "GET_REPEATED_QUERY" | "JSON_POST", method: "GET" | "POST") {
  return {
    id,
    actorId: "owner",
    caseType: "MIXED_TENANT",
    requestStyle,
    method,
    url: requestStyle === "GET_REPEATED_QUERY" ? `${origin}/api/bulk/preview?id={{OBJECT_ID_LIST_REPEATED}}` : `${origin}/api/bulk/dry-run`,
    headers: { Accept: "application/json" },
    ...(requestStyle === "JSON_POST" ? { bodyTemplate: { objectIds: "{{OBJECT_IDS_ARRAY}}", dryRun: true, operation: "preview" } } : {}),
    objects: [
      { id: "a", objectId: "obj-a", objectType: "project", expectedDecision: "ALLOW", ownerActorId: "owner", tenantId: "tenant-a" },
      { id: "b", objectId: "obj-b", objectType: "project", expectedDecision: "FILTER_OUT", ownerActorId: "viewer", tenantId: "tenant-b" }
    ],
    expectedBatchPolicy: "MUST_FILTER_UNAUTHORIZED_OBJECTS",
    safetyContract: {
      operationType: method === "POST" ? "DRY_RUN" : "PREVIEW",
      operatorConfirmedNonMutating: true,
      environment: "LOCAL_FIXTURE",
      ...(method === "POST" ? { requiredRequestMarkerPath: "dryRun", requiredRequestMarkerValue: true } : {}),
      requiredResponseMarkerPath: "preview",
      requiredResponseMarkerValue: true,
      disallowedResponsePaths: ["jobId", "taskId"]
    },
    responseContract: { type: "PREVIEW_OBJECT_LIST", resultArrayPath: "items", resultObjectIdPath: "id", metadataPaths: ["privateName"] }
  } as BulkAuthorizationInput["definitions"][number]["cases"][number];
}

function profileSet(): AuthProfileSet {
  return {
    accountA: { label: "account-a", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-a", role: "member", accountState: "active", headers: { Cookie: "session=account-a-secret" }, cookies: [], notes: [] },
    accountB: { label: "account-b", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-b", role: "member", accountState: "active", headers: { Cookie: "session=account-b-secret" }, cookies: [], notes: [] }
  };
}
