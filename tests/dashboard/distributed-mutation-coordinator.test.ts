import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { DistributedMutationCoordinatorService } from "../../src/dashboard/operations/DistributedMutationCoordinatorService.js";

describe("distributed mutation coordinator operations", () => {
  it("never reassigns an expired lease automatically and requires orphan recovery", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-coordinator-service-")); const database = new DashboardDatabase(join(directory, "dashboard.sqlite")); database.migrate();
    try {
      const service = new DistributedMutationCoordinatorService(database, "coordinator-service-secret-01234567890123456789");
      const lease = service.acquire({ namespace: "staging", caseId: "case-stale", holderId: "worker-a", recovery: false });
      database.db.prepare("UPDATE distributed_mutation_leases SET expires_at=? WHERE id=?").run("2020-01-01T00:00:00.000Z", lease.leaseId);
      expect(service.status("staging").activeLease).toMatchObject({ caseId: "case-stale", stale: true });
      expect(() => service.acquire({ namespace: "staging", caseId: "case-other", holderId: "worker-b", recovery: false })).toThrow("MUTATION_LOCK_STALE_OPERATOR_ACTION_REQUIRED");
      expect(service.orphan({ namespace: "staging", confirmation: "MARK_STALE_LEASE_STATE_UNCERTAIN" })).toMatchObject({ caseId: "case-stale" });
      expect(() => service.acquire({ namespace: "staging", caseId: "case-other", holderId: "worker-b", recovery: false })).toThrow("UNRESOLVED_PRIOR_CLEANUP");
      const recovery = service.acquire({ namespace: "staging", caseId: "case-stale", holderId: "recovery-worker", recovery: true });
      service.release({ namespace: "staging", leaseId: recovery.leaseId, leaseToken: recovery.leaseToken, holderId: "recovery-worker", cleanup: { state: "CLEAN" } });
      expect(service.status("staging")).toMatchObject({ activeLease: null, obligations: [] });
    } finally { database.close(); }
  });

  it("requires the exact operator attestation before clearing an independently verified obligation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-coordinator-resolution-")); const database = new DashboardDatabase(join(directory, "dashboard.sqlite")); database.migrate();
    try {
      const service = new DistributedMutationCoordinatorService(database, "coordinator-service-secret-01234567890123456789");
      const lease = service.acquire({ namespace: "sandbox", caseId: "case-review", holderId: "worker-a", recovery: false });
      service.release({ namespace: "sandbox", leaseId: lease.leaseId, leaseToken: lease.leaseToken, holderId: "worker-a", cleanup: { state: "UNKNOWN", stage: "MUTATION_STATE_UNCERTAIN" } });
      expect(() => service.resolve({ namespace: "sandbox", caseId: "case-review", confirmation: "wrong" })).toThrow("MUTATION_COORDINATOR_CONFIRMATION_REQUIRED");
      expect(service.resolve({ namespace: "sandbox", caseId: "case-review", confirmation: "I_VERIFIED_NO_MUTATION_WAS_TRANSMITTED_OR_TARGET_STATE_IS_RESTORED" })).toMatchObject({ resolved: true, caseId: "case-review" });
      expect(service.status("sandbox").obligations).toEqual([]);
    } finally { database.close(); }
  });
});
