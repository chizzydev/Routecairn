import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";
import { loadAuthorizationMatrixInput, planAuthorizationMatrixTesting, type AuthorizationMatrixInput } from "../../src/modules/authorizationMatrix/AuthorizationMatrixPlanner.js";

describe("authorization matrix planner", () => {
  it("resolves a fixed request matrix and deeply freezes the plan", () => {
    const plan = planAuthorizationMatrixTesting(validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), {
      target: "https://app.example.com/",
      scope: exampleScope,
      authProfileSet: profileSet()
    });

    expect(plan.requestMatrix.map((testCase) => `${testCase.actorId}:${testCase.objectId}`)).toEqual([
      "owner:doc-a-001",
      "viewer:doc-a-001",
      "public:doc-a-001"
    ]);
    expect(plan.requestMatrix).toHaveLength(3);
    expect(plan.requestMatrix[1]?.referenceCaseId).toBe("owner-allow");
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.matrices[0]?.cases)).toBe(true);
    expect(JSON.stringify(plan)).not.toContain("session=account-a-secret");
    expect(JSON.stringify(plan)).not.toContain("session=account-b-secret");
  });

  it.each([
    ["mutating method", (input: AuthorizationMatrixInput) => (input.matrices[0].template.method = "POST" as "GET")],
    ["unknown actor", (input: AuthorizationMatrixInput) => (input.matrices[0].cases[0].actorId = "ghost")],
    ["unsafe endpoint", (input: AuthorizationMatrixInput) => (input.matrices[0].template.url = "https://app.example.com/delete/{{OBJECT_ID}}")],
    ["secret query", (input: AuthorizationMatrixInput) => (input.matrices[0].template.url = "https://app.example.com/api/documents/{{OBJECT_ID}}?access_token=secret")],
    ["duplicate case", (input: AuthorizationMatrixInput) => input.matrices[0].cases.push({ ...input.matrices[0].cases[0] })],
    ["missing reference", (input: AuthorizationMatrixInput) => (input.matrices[0].cases[1].referenceCaseId = "missing")],
    ["state without field", (input: AuthorizationMatrixInput) => {
      delete input.matrices[0].objectStateField;
      input.matrices[0].cases[0].expectedObjectState = "published";
    }]
  ])("rejects %s", (_label, mutate) => {
    const input = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    mutate(input);
    expect(() => planAuthorizationMatrixTesting(input, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow();
  });

  it("rejects authenticated actors without an account pair, same principals, and reused auth material", () => {
    expect(() => planAuthorizationMatrixTesting(validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), { target: "https://app.example.com/", scope: exampleScope })).toThrow(/requires --auth-a and --auth-b/);

    const samePrincipal = profileSet();
    samePrincipal.accountB.principalId = samePrincipal.accountA.principalId;
    const samePrincipalInput = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    samePrincipalInput.matrices[0].actors[1].principalId = "principal-a";
    expect(() => planAuthorizationMatrixTesting(samePrincipalInput, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: samePrincipal })).toThrow(/same declared principal/);

    const reusedMaterial = profileSet();
    reusedMaterial.accountB.headers = { ...reusedMaterial.accountA.headers };
    expect(() => planAuthorizationMatrixTesting(validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), { target: "https://app.example.com/", scope: exampleScope, authProfileSet: reusedMaterial })).toThrow(/reused authentication material/);
  });

  it("rejects public auth, actor metadata conflicts, and out-of-scope cases", () => {
    const publicAuth = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    publicAuth.matrices[0].actors[2].authProfile = "account_a";
    expect(() => planAuthorizationMatrixTesting(publicAuth, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/Public authorization actor/);

    const roleConflict = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    roleConflict.matrices[0].actors[1].role = "admin";
    expect(() => planAuthorizationMatrixTesting(roleConflict, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/role metadata/);

    const outOfScope = validInput("https://evil.example.net/api/documents/{{OBJECT_ID}}");
    expect(() => planAuthorizationMatrixTesting(outOfScope, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/out of scope/);
  });

  it("fails closed for malformed, oversized, and non-strict input files", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-authz-matrix-file-"));
    const malformed = join(tempDir, "malformed.json");
    await writeFile(malformed, "{no", "utf8");
    await expect(loadAuthorizationMatrixInput(malformed)).rejects.toThrow(/not valid JSON/);

    const oversized = join(tempDir, "oversized.json");
    await writeFile(oversized, " ".repeat(257 * 1024), "utf8");
    await expect(loadAuthorizationMatrixInput(oversized)).rejects.toThrow(/maximum size/);

    const nonStrict = join(tempDir, "non-strict.json");
    await writeFile(nonStrict, JSON.stringify({ ...validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), extra: true }), "utf8");
    await expect(loadAuthorizationMatrixInput(nonStrict)).rejects.toThrow();
  });
});

function validInput(url: string): AuthorizationMatrixInput {
  return {
    schemaVersion: 1,
    maxMatrices: 1,
    maxCasesPerMatrix: 5,
    maxResponseBytes: 65536,
    maxPreviewLength: 80,
    matrices: [
      {
        id: "document-access",
        name: "Document access",
        objectType: "document",
        template: { id: "document-read", method: "GET", url, headers: {} },
        objectIdentityField: "id",
        objectStateField: "state",
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", safeAlias: "Owner", principalId: "principal-a", tenantId: "tenant-one", role: "member", accountState: "active" },
          { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", safeAlias: "Viewer", principalId: "principal-b", tenantId: "tenant-two", role: "viewer", accountState: "active" },
          { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
        ],
        cases: [
          { id: "owner-allow", actorId: "owner", objectId: "doc-a-001", expectedObjectState: "published", expectedDecision: "MUST_ALLOW", requireVerifiedIdentity: false },
          { id: "viewer-deny", actorId: "viewer", objectId: "doc-a-001", expectedObjectState: "published", expectedDecision: "MUST_DENY", referenceCaseId: "owner-allow", expectedTenantId: "tenant-two", expectedRole: "viewer", expectedAccountState: "active", requireVerifiedIdentity: false },
          { id: "public-auth", actorId: "public", objectId: "doc-a-001", expectedDecision: "MUST_REQUIRE_AUTHENTICATION", requireVerifiedIdentity: false }
        ]
      }
    ]
  };
}

function profileSet(): AuthProfileSet {
  return {
    accountA: { label: "account-a", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-one", role: "member", accountState: "active", headers: { Cookie: "session=account-a-secret" }, cookies: [], notes: [] },
    accountB: { label: "account-b", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-two", role: "viewer", accountState: "active", headers: { Cookie: "session=account-b-secret" }, cookies: [], notes: [] }
  };
}
