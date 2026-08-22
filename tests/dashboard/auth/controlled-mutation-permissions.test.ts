import { describe, expect, it } from "vitest";
import { hasPermission } from "../../../src/dashboard/auth/Permissions.js";

describe("controlled mutation dashboard permissions", () => {
  it("does not infer mutation authority from ordinary scan or finding permissions", () => {
    expect(hasPermission("ANALYST", "scans.create")).toBe(true);
    expect(hasPermission("ANALYST", "findings.assign")).toBe(true);
    expect(hasPermission("ANALYST", "controlledMutation.approve")).toBe(false);
    expect(hasPermission("ANALYST", "controlledMutation.recover")).toBe(false);
  });

  it("limits approval and recovery to the owner role", () => {
    expect(hasPermission("OWNER", "controlledMutation.approve")).toBe(true);
    expect(hasPermission("OWNER", "controlledMutation.recover")).toBe(true);
    expect(hasPermission("VIEWER", "controlledMutation.approve")).toBe(false);
    expect(hasPermission("VIEWER", "controlledMutation.recover")).toBe(false);
  });
});
