import { it, expect, vi } from "vitest";
import { authorizationWorkbenchFixture } from "../helpers/authorization-workbench-fixture.js";
it("retrieves an acknowledged native dispatch after review expiry without late dispatch or reauthorization", async () => {
  const f = await authorizationWorkbenchFixture();
  try {
    const done = await f.service.create(f.org, f.input, "operator"),
      fresh = await f.service.create(f.org, f.input, "operator");
    const first = await f.service.execute(f.org, done.revisionId, done.digest, "operator");
    await f.wait(first.scanId!);
    await f.execution.shutdown();
    const count = f.wire.length;
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 600001);
      expect(await f.service.execute(f.org, done.revisionId, done.digest, "operator")).toMatchObject({
        status: "ALREADY_RECORDED",
        scanId: first.scanId,
        replayed: false
      });
      await expect(f.service.execute(f.org, fresh.revisionId, fresh.digest, "operator")).rejects.toThrow(
        "STALE_REVIEW"
      );
      await expect(f.service.execute(f.org, done.revisionId, "0".repeat(64), "operator")).rejects.toThrow(
        "STALE_REVIEW"
      );
      await expect(f.service.execute(f.org, done.revisionId, done.digest, "other-operator")).rejects.toThrow(
        "CONSUMED_BY_ANOTHER_OPERATOR"
      );
      expect(f.wire).toHaveLength(count);
      f.capture("ACK_AFTER_EXPIRY_NO_REPLAY");
    } finally {
      vi.useRealTimers();
    }
  } finally {
    await f.close();
  }
});
it("retains consumed unacknowledged uncertainty after expiry without acquiring new execution authority", async () => {
  const f = await authorizationWorkbenchFixture();
  try {
    await f.execution.shutdown();
    const r = await f.service.create(f.org, f.input, "operator"),
      count = f.wire.length;
    f.database.db
      .prepare("INSERT INTO authorization_workbench_dispatches VALUES(?,?,?)")
      .run(r.revisionId, "operator", new Date().toISOString());
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 600001);
      expect(await f.service.execute(f.org, r.revisionId, r.digest, "operator")).toMatchObject({
        status: "UNKNOWN",
        scanId: null,
        replayed: false
      });
      expect(f.wire).toHaveLength(count);
      f.capture("UNKNOWN_AFTER_EXPIRY_NO_REPLAY");
    } finally {
      vi.useRealTimers();
    }
  } finally {
    await f.close();
  }
});
