import { describe, expect, it } from "vitest";
import { capabilityParityManifest, validateCapabilityParityManifest } from "../../../src/dashboard/admin/CapabilityParityManifest.js";

describe("administration capability parity manifest", () => {
  it("contains no partial required workflows and fully documents intentional CLI-only work", () => {
    expect(validateCapabilityParityManifest()).toEqual([]);
    expect(capabilityParityManifest.some((entry) => (entry.status as string) === "PARTIAL")).toBe(false);
    for (const entry of capabilityParityManifest.filter((item) => item.status === "INTENTIONAL_CLI_ONLY")) {
      expect(entry.reason).toBeTruthy(); expect(entry.owner).toBeTruthy(); expect(entry.safety).toBeTruthy();
    }
  });
});
