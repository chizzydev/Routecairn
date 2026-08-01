import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { exampleScope } from "../../src/config/defaults.js";
import { loadFieldExposureInput, planFieldExposureTesting, type FieldExposureInput } from "../../src/modules/fieldExposureTesting/FieldExposurePlanner.js";
import type { AuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";

describe("field exposure planner", () => {
  it("resolves a fixed request matrix and deeply freezes the plan", () => {
    const plan = planFieldExposureTesting(validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), {
      target: "https://app.example.com/",
      scope: exampleScope,
      authProfileSet: profileSet()
    });

    expect(plan.requestMatrix.map((request) => request.actorId)).toEqual(["owner", "non_owner", "public"]);
    expect(plan.requestMatrix).toHaveLength(3);
    expect(plan.cases[0].fieldExpectations.map((field) => field.path)).toEqual(["owner.email", "billing.last4", "members[0].role"]);
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.cases[0].fieldExpectations)).toBe(true);
    expect(JSON.stringify(plan)).not.toContain("principal-a");
    expect(JSON.stringify(plan)).not.toContain("principal-b");
  });

  it.each([
    ["wildcard path", (input: FieldExposureInput) => (input.cases[0].fieldExpectations[0].path = "owner.*")],
    ["prototype path", (input: FieldExposureInput) => (input.cases[0].fieldExpectations[0].path = "__proto__.x")],
    ["duplicate field", (input: FieldExposureInput) => input.cases[0].fieldExpectations.push({ ...input.cases[0].fieldExpectations[0] })],
    ["unknown actor", (input: FieldExposureInput) => input.cases[0].fieldExpectations[0].prohibitedActors.push("ghost")],
    ["unsafe template", (input: FieldExposureInput) => (input.cases[0].template.url = "https://app.example.com/delete/{{OBJECT_ID}}")],
    ["secret query", (input: FieldExposureInput) => (input.cases[0].template.url = "https://app.example.com/api/documents/{{OBJECT_ID}}?access_token=secret")]
  ])("rejects %s", (_label, mutate) => {
    const input = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    mutate(input);
    expect(() => planFieldExposureTesting(input, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow();
  });

  it("rejects baseline-dependent expectations without the required baseline actor", () => {
    const noPublic = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    noPublic.cases[0].actors = noPublic.cases[0].actors.filter((actor) => actor.type !== "PUBLIC");
    noPublic.cases[0].fieldExpectations = [noPublic.cases[0].fieldExpectations[0]];
    noPublic.cases[0].fieldExpectations[0].expectation = "MUST_MATCH_PUBLIC_BASELINE";
    noPublic.cases[0].fieldExpectations[0].prohibitedActors = ["non_owner"];
    expect(() => planFieldExposureTesting(noPublic, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/PUBLIC actor/);

    const noShared = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    noShared.cases[0].fieldExpectations[0].expectation = "MUST_MATCH_SHARED_BASELINE";
    noShared.cases[0].fieldExpectations[0].prohibitedActors = ["non_owner"];
    expect(() => planFieldExposureTesting(noShared, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/SHARED_PRINCIPAL actor/);
  });

  it("rejects HEAD field projection, role/tenant conflicts, and reused auth material", () => {
    const head = { ...validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), cases: [{ ...validInput("https://app.example.com/api/documents/{{OBJECT_ID}}").cases[0], template: { id: "head", method: "HEAD", url: "https://app.example.com/api/documents/{{OBJECT_ID}}", headers: {} } }] } as unknown as FieldExposureInput;
    expect(() => planFieldExposureTesting(head, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/must use GET/);

    const tenantConflict = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    tenantConflict.cases[0].actors[1].tenantId = "other-tenant";
    expect(() => planFieldExposureTesting(tenantConflict, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/tenant metadata/);

    const roleConflict = validInput("https://app.example.com/api/documents/{{OBJECT_ID}}");
    roleConflict.cases[0].actors[1].role = "admin";
    expect(() => planFieldExposureTesting(roleConflict, { target: "https://app.example.com/", scope: exampleScope, authProfileSet: profileSet() })).toThrow(/role metadata/);

    const reusedMaterial = profileSet();
    reusedMaterial.accountB.headers = { ...reusedMaterial.accountA.headers };
    expect(() => planFieldExposureTesting(validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), { target: "https://app.example.com/", scope: exampleScope, authProfileSet: reusedMaterial })).toThrow(/reused authentication material/);
  });

  it("rejects authenticated actors without an account pair and same declared principal reuse", () => {
    expect(() => planFieldExposureTesting(validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), { target: "https://app.example.com/", scope: exampleScope })).toThrow(/requires --auth-a and --auth-b/);

    const authProfileSet = profileSet();
    authProfileSet.accountB.principalId = authProfileSet.accountA.principalId;
    expect(() => planFieldExposureTesting(validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), { target: "https://app.example.com/", scope: exampleScope, authProfileSet })).toThrow(/same declared principal/);
  });

  it("fails closed for malformed, oversized, and non-strict input files", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-field-exposure-file-"));
    const malformed = join(tempDir, "malformed.json");
    await writeFile(malformed, "{no", "utf8");
    await expect(loadFieldExposureInput(malformed)).rejects.toThrow(/not valid JSON/);

    const oversized = join(tempDir, "oversized.json");
    await writeFile(oversized, " ".repeat(257 * 1024), "utf8");
    await expect(loadFieldExposureInput(oversized)).rejects.toThrow(/maximum size/);

    const nonStrict = join(tempDir, "non-strict.json");
    await writeFile(nonStrict, JSON.stringify({ ...validInput("https://app.example.com/api/documents/{{OBJECT_ID}}"), extra: true }), "utf8");
    await expect(loadFieldExposureInput(nonStrict)).rejects.toThrow();
  });
});

function validInput(url: string): FieldExposureInput {
  return {
    schemaVersion: 1,
    maxCases: 5,
    maxResponseBytes: 65536,
    maxPreviewLength: 80,
    cases: [
      {
        id: "document-fields",
        objectType: "document",
        objectId: "doc-a-001",
        declaredOwnerActor: "owner",
        expectedVisibility: "PUBLIC_SUMMARY",
        requireVerifiedIdentity: true,
        template: { id: "document-read", method: "GET", url, headers: {} },
        objectConfirmation: { expectedObjectIdField: "id", expectedOwnerField: "owner" },
        actors: [
          { id: "owner", type: "OWNER", authProfile: "account_a", safeAlias: "Owner" },
          { id: "non_owner", type: "NON_OWNER", authProfile: "account_b", safeAlias: "Non Owner" },
          { id: "public", type: "PUBLIC", safeAlias: "Public" }
        ],
        fieldExpectations: [
          { path: "owner.email", label: "Owner email", sensitivity: "OWNER_ONLY", expectation: "OWNER_ONLY_VALUE", allowedActors: ["owner"], prohibitedActors: ["non_owner", "public"], allowPreview: false },
          { path: "billing.last4", label: "Billing last four", sensitivity: "PRIVATE", expectation: "MUST_BE_REDACTED", allowedActors: ["owner"], prohibitedActors: ["non_owner"], redactionPattern: "^\\*{2,}\\d{2,4}$", allowPreview: false },
          { path: "members[0].role", label: "First member role", sensitivity: "PUBLIC", expectation: "MAY_BE_PRESENT", allowedActors: ["owner", "non_owner", "public"], prohibitedActors: [], allowPreview: true }
        ]
      }
    ]
  };
}

function profileSet(): AuthProfileSet {
  return {
    accountA: { label: "account-a", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-one", role: "member", headers: { Cookie: "session=account-a-secret" }, cookies: [], notes: [] },
    accountB: { label: "account-b", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-one", role: "viewer", headers: { Cookie: "session=account-b-secret" }, cookies: [], notes: [] }
  };
}
