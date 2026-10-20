import { it, expect } from "vitest";
import { heldOutApplicationFixture } from "../helpers/heldout-application-fixture.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { mappingObservation } from "../../src/dashboard/execution/ApplicationMappingEvidence.js";
import { ApplicationDiscoveryService } from "../../src/dashboard/execution/ApplicationDiscoveryService.js";
it("keeps a durable dispatch-without-ack UNKNOWN across SQLite reopen and refuses to use it for discovery", async () => {
  const f = await heldOutApplicationFixture("clinic");
  try {
    const native = await f.acquire(f.seedInput);
    expect(native.result.status).toBe("COMPLETED");
    const r = await f.mapping.create(f.org, f.seedInput, "operator");
    f.database.db
      .prepare("INSERT INTO application_mapping_dispatches VALUES(?,?,?)")
      .run(r.revisionId, "owned-fault-injection", new Date().toISOString());
    await f.execution.shutdown();
    const reopened = new DashboardDatabase(f.paths.databasePath);
    try {
      reopened.migrate();
      const before = f.wire.length,
        o = mappingObservation(reopened, f.org, r.revisionId);
      expect(o.status).toBe("UNKNOWN");
      expect(o.report).toBeUndefined();
      expect(() =>
        new ApplicationDiscoveryService(reopened).preview(f.org, {
          mapRevisionId: r.revisionId,
          allowedPathPrefixes: [f.prefix],
          maxRoutes: 8,
          maxRequests: 36,
          scopeConfirmed: true
        })
      ).toThrow("COMPLETE_NATIVE_SOURCE");
      expect(() =>
        reopened.db
          .prepare("UPDATE application_mapping_dispatches SET requested_by=? WHERE revision_id=?")
          .run("replay", r.revisionId)
      ).toThrow("IMMUTABLE_MAPPING_DISPATCH");
      expect(f.wire.length).toBe(before);
      f.capture("RESTART_UNKNOWN_SOURCE_REFUSAL", {
        fault: "SYNTHETIC_DURABLE_DISPATCH_GAP_NOT_A_CLAIM_OF_REAL_PROCESS_CRASH",
        status: o.status,
        nativeSource: native.result.sourceHash,
        integrity: reopened.db.pragma("integrity_check"),
        quarantineClearanceAttempted: false,
        requestsAfterRestart: 0
      });
    } finally {
      reopened.close();
    }
  } finally {
    await f.close();
  }
});
