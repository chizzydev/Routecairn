import { OwnedTemporaryResource } from "../../src/core/storage/OwnedTemporaryResource.js";
import { describe, it, expect } from "vitest";
import { readFile, readdir, link, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
describe("managed recovery encrypted evidence retention", () => {
  it("keeps verified recovery evidence and each previous checkpoint byte-identically", async () => {
    const root = createOwnedTestDirectory("recovery-vault-retention-");
    try {
      const vault = new MutationRecoveryVault(root, true);
      const path = await vault.seal({ caseId: "fixture", stage: "before" });
      const before = await readFile(path);
      await vault.seal({ caseId: "fixture", stage: "after" });
      const archived = await readdir(join(root, "retained-recovery-evidence"));
      expect(archived).toHaveLength(1);
      expect(await readFile(join(root, "retained-recovery-evidence", archived[0]!))).toEqual(before);
      await vault.remove(path);
      expect(await vault.open(path, "fixture")).toMatchObject({ stage: "after" });
    } finally {
      retainOwnedTestDirectory(root);
    }
  });
  it("refuses an aliased working checkpoint without replacing either name", async () => {
    const resource = OwnedTemporaryResource.create(process.env.ROUTECAIRN_WORKER_LAB!, {
        purpose: "retention-alias-negative-control"
      }),
      root = resource.root;
    try {
      const v = new MutationRecoveryVault(root, true),
        p = await v.seal({ caseId: "fixture" }),
        before = await readFile(p);
      await link(p, join(root, "alias.enc"));
      await expect(v.seal({ caseId: "fixture", changed: true })).rejects.toThrow("SOURCE_REFUSED");
      expect(await readFile(p)).toEqual(before);
    } finally {
      expect(resource.retain("EXPECTED_ALIAS_REFUSAL").state).toBe("UNKNOWN_RETAINED");
    }
  });
  it("blocks checkpoint replacement when retained evidence collides", async () => {
    const root = createOwnedTestDirectory("recovery-vault-collision-");
    try {
      const v = new MutationRecoveryVault(root, true),
        p = await v.seal({ caseId: "fixture" }),
        before = await readFile(p),
        a = join(root, "retained-recovery-evidence");
      await mkdir(a);
      await mkdir(
        join(
          a,
          createHash("sha256").update("fixture").digest("hex") +
            "." +
            createHash("sha256").update(before).digest("hex") +
            ".enc"
        )
      );
      await expect(v.seal({ caseId: "fixture", changed: true })).rejects.toThrow("COLLISION");
      expect(await readFile(p)).toEqual(before);
    } finally {
      retainOwnedTestDirectory(root);
    }
  });
});
