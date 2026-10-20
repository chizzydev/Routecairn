import { it, expect, vi } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { GlobalMutationLock, MutationJournal } from "../../src/core/offensive/MutationJournal.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { workflowRecoveryFixture, closeRecoveryFixtures } from "../helpers/workflow-recovery-fixture.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
it("releases the real native lease and context when owned checkpoint setup fails", async () => {
  const root = createOwnedTestDirectory("workflow-fixture-error"),
    active = new Set<GlobalMutationLock>();
  const acquire = GlobalMutationLock.prototype.acquire,
    release = GlobalMutationLock.prototype.release;
  const a = vi.spyOn(GlobalMutationLock.prototype, "acquire").mockImplementation(async function (
    this: GlobalMutationLock,
    ...args: Parameters<typeof acquire>
  ) {
    await acquire.apply(this, args);
    active.add(this);
  });
  const r = vi.spyOn(GlobalMutationLock.prototype, "release").mockImplementation(async function (
    this: GlobalMutationLock
  ) {
    try {
      await release.call(this);
    } finally {
      active.delete(this);
    }
  });
  const d = vi.spyOn(ScanContext.prototype, "dispose"),
    j = vi.spyOn(MutationJournal.prototype, "append").mockRejectedValueOnce(Error("OWNED_SETUP_APPEND_FAILURE"));
  try {
    await expect(workflowRecoveryFixture("authenticationLifecycle")).rejects.toThrow("OWNED_SETUP_APPEND_FAILURE");
    writeFileSync(
      join(root, "NATIVE_ERROR_CUSTODY_RECEIPT.json"),
      JSON.stringify({
        acquired: a.mock.calls.length,
        released: r.mock.calls.length,
        disposed: d.mock.calls.length,
        heldNativeLeases: active.size,
        rescueAfterAssertionsOnly: true
      }),
      { flag: "wx" }
    );
    expect(a).toHaveBeenCalledTimes(1);
    expect(r).toHaveBeenCalledTimes(1);
    expect(d).toHaveBeenCalledTimes(1);
    expect(active.size).toBe(0);
  } finally {
    j.mockRestore();
    for (const lock of active) await release.call(lock);
    await closeRecoveryFixtures();
    a.mockRestore();
    r.mockRestore();
    d.mockRestore();
    retainOwnedTestDirectory(root);
  }
});
