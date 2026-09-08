import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { resolveRecoveryBundlePath } from "../../src/core/offensive/MutationRecoveryPath.js";

describe("canonical recovery bundle containment", () => {
  it("accepts native paths and rejects outside roots, wrong cases and traversal", () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-recovery-path-"));
    try {
      const root = join(directory, "journal"); mkdirSync(root);
      const path = join(root, "case-1.recovery.enc"); writeFileSync(path, "fixture");
      const outside = join(directory, "case-1.recovery.enc"); writeFileSync(outside, "fixture");
      expect(resolveRecoveryBundlePath(root, path, "case-1")).toBe(realpathSync(path));
      expect(() => resolveRecoveryBundlePath(root, outside, "case-1")).toThrow("RECOVERY_PATH_INVALID");
      expect(() => resolveRecoveryBundlePath(root, path, "wrong-case")).toThrow("RECOVERY_PATH_INVALID");
      expect(() => resolveRecoveryBundlePath(root, `${root}/../case-1.recovery.enc`, "case-1")).toThrow("RECOVERY_PATH_INVALID");
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
});
