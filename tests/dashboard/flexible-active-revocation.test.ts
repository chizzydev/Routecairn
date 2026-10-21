import { it as platformTest, expect } from "vitest";
const it = platformTest.skipIf(process.platform !== "win32");
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
it("vault revocation after native runtime activation cancels custody before private credential transmission", async () => {
  const f = await flexibleDashboardFixture(1, true);
  try {
    const pending = f.run().then(
      (value) => ({ value, error: undefined }),
      (error) => ({ value: undefined, error: String(error) })
    );
    const end = Date.now() + 15000;
    let scan: { id: string; status: string } | undefined;
    while (Date.now() < end) {
      scan = f.database.db.prepare("SELECT id,status FROM scans ORDER BY created_at DESC LIMIT 1").get() as typeof scan;
      if (scan?.status === "RUNNING" && f.wire.some((w) => w.path === "/" && w.actor === "anonymous")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(scan?.status).toBe("RUNNING");
    expect(f.wire.some((w) => w.path === "/" && w.actor === "anonymous")).toBe(true);
    expect(f.wire.some((w) => w.actor === "actor0")).toBe(false);
    const wireBeforeRevocation = f.wire.slice(),
      verifiedPlan = f.database.db
        .prepare("SELECT worker_verified_binding,worker_verified_at FROM scan_executable_plans WHERE scan_id=?")
        .get(scan!.id);
    expect(verifiedPlan).toMatchObject({
      worker_verified_binding: expect.any(String),
      worker_verified_at: expect.any(String)
    });
    const profileId = f.actors[0]!.credentialProfileId,
      impact = f.vault.dependencies(profileId);
    f.vault.setEnabled(profileId, false, impact.impactDigest);
    const disabledAt = new Date().toISOString(),
      result = await pending,
      row = f.database.db.prepare("SELECT id,status,error_summary FROM scans WHERE id=?").get(scan!.id) as {
        id: string;
        status: string;
        error_summary: string | null;
      };
    f.capture("ACTIVE_REVOCATION_NATIVE_RECEIPT", {
      disabledAt,
      wireBeforeRevocation,
      verifiedPlan,
      row,
      wire: f.wire,
      promiseOutcome: result.error ?? "COMPLETED",
      impact,
      integrity: f.database.db.pragma("integrity_check"),
      foreignKeys: f.database.db.pragma("foreign_key_check")
    });
    expect(row.status).toBe("CANCELLED");
    expect(f.wire.some((w) => w.actor === "actor0")).toBe(false);
  } finally {
    await f.close();
  }
});
