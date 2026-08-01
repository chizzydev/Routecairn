import { describe, expect, it } from "vitest";
import { summarizeAuthProfileSet } from "../../src/core/auth/AuthProfileSet.js";

describe("auth profile sets", () => {
  it("summarizes account A and account B without exposing values", () => {
    const summary = summarizeAuthProfileSet({
      accountA: {
        label: "account-a",
        role: "buyer",
        headers: { Cookie: "session=account-a-secret" },
        cookies: [],
        notes: []
      },
      accountB: {
        label: "account-b",
        role: "buyer",
        headers: { Authorization: "Bearer account-b-secret" },
        cookies: [],
        notes: []
      }
    });

    expect(summary.enabled).toBe(true);
    expect(summary.redactionApplied).toBe(true);
    expect(summary.accountA?.headerNames).toEqual(["Cookie"]);
    expect(summary.accountB?.headerNames).toEqual(["Authorization"]);
    expect(JSON.stringify(summary)).not.toContain("account-a-secret");
    expect(JSON.stringify(summary)).not.toContain("account-b-secret");
  });
});
