import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { exampleScope } from "../../src/config/defaults.js";
import { loadObjectPairInput, planObjectPairTesting, type ObjectPairInput } from "../../src/modules/objectPairTesting/ObjectPairPlanner.js";
import type { AuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";

describe("object pair planner", () => {
  it("accepts a valid Account A/B pair and resolves a fixed four-request matrix", () => {
    const plan = planObjectPairTesting(validInput("https://app.example.com/objects/{{OBJECT_ID}}"), {
      target: "https://app.example.com/",
      scope: exampleScope,
      authProfileSet: profileSet()
    });

    expect(plan.requestMatrix.map((request) => request.direction)).toEqual(["A_TO_A", "B_TO_B", "A_TO_B", "B_TO_A"]);
    expect(plan.requestMatrix.map((request) => request.targetObjectId)).toEqual(["obj-a", "obj-b", "obj-b", "obj-a"]);
    expect(Object.isFrozen(plan.requestMatrix)).toBe(true);
  });

  it("rejects missing Account A/B authentication", () => {
    expect(() => planObjectPairTesting(validInput("https://app.example.com/objects/{{OBJECT_ID}}"), { target: "https://app.example.com/", scope: exampleScope })).toThrow(
      /requires --auth-a and --auth-b/
    );
  });

  it("rejects identical principals", () => {
    const authProfileSet = profileSet();
    authProfileSet.accountB.headers = { Cookie: "session=account-a-secret" };

    expect(() =>
      planObjectPairTesting(validInput("https://app.example.com/objects/{{OBJECT_ID}}"), {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet
      })
    ).toThrow(/distinct Account A and Account B/);
  });

  it("rejects different auth contexts with the same declared principal ID", () => {
    const authProfileSet = profileSet();
    authProfileSet.accountB.principalId = authProfileSet.accountA.principalId;

    expect(() =>
      planObjectPairTesting(validInput("https://app.example.com/objects/{{OBJECT_ID}}"), {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet
      })
    ).toThrow(/different principalId/);
  });

  it("requires declared principal IDs and accepts different auth contexts with different principal IDs", () => {
    const missingPrincipal = profileSet();
    delete missingPrincipal.accountA.principalId;
    expect(() =>
      planObjectPairTesting(validInput("https://app.example.com/objects/{{OBJECT_ID}}"), {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: missingPrincipal
      })
    ).toThrow(/principalId metadata/);

    const plan = planObjectPairTesting(validInput("https://app.example.com/objects/{{OBJECT_ID}}"), {
      target: "https://app.example.com/",
      scope: exampleScope,
      authProfileSet: profileSet()
    });
    expect(plan.principals.map((principal) => principal.principalIdHash)).toHaveLength(2);
    expect(plan.principals[0].principalIdHash).not.toBe(plan.principals[1].principalIdHash);
    expect(JSON.stringify(plan.principals)).not.toContain("principal-a");
    expect(JSON.stringify(plan.principals)).not.toContain("principal-b");
  });

  it.each([
    ["missing placeholder", "https://app.example.com/objects/static"],
    ["ambiguous placeholder", "https://app.example.com/objects/{{OBJECT_ID}}/{{OBJECT_ID}}"],
    ["unsupported protocol", "file:///tmp/{{OBJECT_ID}}"],
    ["unsafe endpoint", "https://app.example.com/delete/{{OBJECT_ID}}"],
    ["out of scope", "https://evil.example.net/objects/{{OBJECT_ID}}"]
  ])("rejects %s templates", (_label, url) => {
    expect(() =>
      planObjectPairTesting(validInput(url), {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow();
  });

  it.each(["1-10", "1..10", "*", "abc,def", "range(1,10)", "uuid-v4"])("rejects generator-like identifier %s", (id) => {
    const input = validInput("https://app.example.com/objects/{{OBJECT_ID}}");
    input.cases[0].accountAObject.id = id;
    expect(() =>
      planObjectPairTesting(input, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow(/one exact operator-supplied value/);
  });

  it("rejects raw auth material embedded in templates", () => {
    const input = validInput("https://app.example.com/objects/{{OBJECT_ID}}");
    input.cases[0].template.headers = { Authorization: "Bearer no" };
    expect(() =>
      planObjectPairTesting(input, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow(/must not embed authentication headers/);
  });

  it("rejects duplicate case IDs and duplicate logical pairs before execution", () => {
    const duplicateCase = validInput("https://app.example.com/objects/{{OBJECT_ID}}");
    duplicateCase.cases.push({ ...duplicateCase.cases[0], id: "documents" });
    expect(() =>
      planObjectPairTesting(duplicateCase, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow(/duplicated/);

    const duplicatePair = validInput("https://app.example.com/objects/{{OBJECT_ID}}");
    duplicatePair.cases.push({ ...duplicatePair.cases[0], id: "documents-copy" });
    expect(() =>
      planObjectPairTesting(duplicatePair, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow(/duplicates an existing logical object pair/);
  });

  it("rejects unsupported evidence selectors and secret-like template material", () => {
    const badSelector = validInput("https://app.example.com/objects/{{OBJECT_ID}}");
    badSelector.cases[0].accountAObject.expectedOwnerField = "owner[0]";
    expect(() =>
      planObjectPairTesting(badSelector, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow(/unsupported selector/);

    const secretTemplate = validInput("https://app.example.com/objects/{{OBJECT_ID}}?access_token=secret");
    expect(() =>
      planObjectPairTesting(secretTemplate, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow(/secret-like/);
  });

  it("fails closed for malformed, oversized, and non-strict object-pair files", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-object-pair-file-"));
    const malformed = join(tempDir, "malformed.json");
    await writeFile(malformed, "{no", "utf8");
    await expect(loadObjectPairInput(malformed)).rejects.toThrow(/not valid JSON/);

    const oversized = join(tempDir, "oversized.json");
    await writeFile(oversized, " ".repeat(257 * 1024), "utf8");
    await expect(loadObjectPairInput(oversized)).rejects.toThrow(/maximum size/);

    const nonStrict = join(tempDir, "non-strict.json");
    await writeFile(nonStrict, JSON.stringify({ ...validInput("https://app.example.com/objects/{{OBJECT_ID}}"), extra: true }), "utf8");
    await expect(loadObjectPairInput(nonStrict)).rejects.toThrow();
  });

  it("rejects excessive identifier and template lengths", () => {
    const longId = validInput("https://app.example.com/objects/{{OBJECT_ID}}");
    longId.cases[0].accountAObject.id = "a".repeat(257);
    expect(() =>
      planObjectPairTesting(longId, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow();

    const longTemplate = validInput(`https://app.example.com/${"a".repeat(2050)}/{{OBJECT_ID}}`);
    expect(() =>
      planObjectPairTesting(longTemplate, {
        target: "https://app.example.com/",
        scope: exampleScope,
        authProfileSet: profileSet()
      })
    ).toThrow();
  });
});

function validInput(url: string): ObjectPairInput {
  return {
    schemaVersion: 1,
    maxPairs: 5,
    principals: { accountA: {}, accountB: {} },
    cases: [
      {
        id: "documents",
        objectType: "document",
        expectedVisibility: "PRIVATE_TO_OWNER",
        template: { id: "doc-read", method: "GET", url, headers: {} },
        accountAObject: {
          id: "obj-a",
          source: "fixture",
          confirmedSafeToTest: true,
          readOnly: true,
          expectedSafeMarkers: ["owner-a"],
          expectedPrivateFields: ["private"]
        },
        accountBObject: {
          id: "obj-b",
          source: "fixture",
          confirmedSafeToTest: true,
          readOnly: true,
          expectedSafeMarkers: ["owner-b"],
          expectedPrivateFields: ["private"]
        }
      }
    ]
  };
}

function profileSet(): AuthProfileSet {
  return {
    accountA: { label: "account-a", safeAlias: "Account A", principalId: "principal-a", tenantId: "tenant-one", role: "member", headers: { Cookie: "session=account-a-secret" }, cookies: [], notes: [] },
    accountB: { label: "account-b", safeAlias: "Account B", principalId: "principal-b", tenantId: "tenant-two", role: "member", headers: { Cookie: "session=account-b-secret" }, cookies: [], notes: [] }
  };
}
