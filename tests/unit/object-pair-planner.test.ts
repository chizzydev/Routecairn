import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { planObjectPairTesting, type ObjectPairInput } from "../../src/modules/objectPairTesting/ObjectPairPlanner.js";
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
    accountA: { label: "account-a", headers: { Cookie: "session=account-a-secret" }, cookies: [], notes: [] },
    accountB: { label: "account-b", headers: { Cookie: "session=account-b-secret" }, cookies: [], notes: [] }
  };
}
