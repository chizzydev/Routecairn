import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { RecoveryCenterService } from "../../src/dashboard/recovery/RecoveryCenterService.js";
import { recoveryCenterFixture } from "../helpers/recovery-center-fixture.js";
describe("adversarial uncertainty evidence bindings", () => {
  it("invalidates a review when a comparison child coverage row changes", async () => {
    const f = recoveryCenterFixture();
    try {
      const i = (await f.service.snapshot(f.scope, "NORMAL", { kind: "COMPARISON" })).issues[0]!;
      f.database.db
        .prepare(
          "INSERT INTO scan_comparison_module_coverage(comparison_id,module_id,older_state,newer_state,comparable,reason_code,safe_reason) VALUES(?,'fixture','COMPLETED','FAILED',0,'FIXTURE','Synthetic incomplete evidence')"
        )
        .run(i.subjectId);
      await expect(
        f.service.review(f.scope, {
          kind: i.kind,
          subjectId: i.subjectId,
          snapshotDigest: i.snapshotDigest,
          decision: "ACKNOWLEDGED",
          reason: "EVIDENCE_INCOMPLETE",
          confirmation: "I_REVIEWED_EVIDENCE_WITHOUT_RESOLVING_UNCERTAINTY"
        })
      ).rejects.toThrow("changed");
    } finally {
      f.close();
    }
  });
  it("refuses reuse of comparison request identity by a different actor", async () => {
    const f = recoveryCenterFixture();
    try {
      const i = (await f.service.snapshot(f.scope, "NORMAL", { kind: "COMPARISON" })).issues[0]!,
        input = {
          subjectId: i.subjectId,
          snapshotDigest: i.snapshotDigest,
          requestId: randomUUID(),
          confirmation: "I_AUTHORIZE_COMPARISON_ONLY_NO_SCAN_OR_GATE_CHANGE"
        };
      await f.service.recompute(f.scope, input);
      await expect(f.service.recompute({ ...f.scope, actor: "different-reviewer" }, input)).rejects.toThrow(
        "identity changed"
      );
      expect(f.database.db.prepare("SELECT COUNT(*) n FROM operator_comparison_attempts").get()).toEqual({ n: 1 });
    } finally {
      f.close();
    }
  });
  it("surfaces an unreadable scoped checkpoint without enabling cleanup", async () => {
    const f = recoveryCenterFixture();
    try {
      const service = new RecoveryCenterService(f.database, {
          inventory: async () => ({
            cases: [
              {
                caseId: "unreadable-checkpoint",
                journalId: "a".repeat(16),
                targetOrigin: "http://127.0.0.1:47999",
                stage: "CLEANUP_REQUIRED",
                recoveryKind: "UNAVAILABLE",
                recoveryBundleAvailable: false
              }
            ],
            jobs: [],
            globalMutationActive: false,
            cleanupRequired: 1,
            modes: {}
          })
        } as never),
        view = await service.snapshot(f.scope, "NORMAL", { kind: "CLEANUP" });
      expect(view.issues).toHaveLength(1);
      expect(view.issues[0]!.actions).toMatchObject({ review: true, cleanup: false });
    } finally {
      f.close();
    }
  });
  it("does not project live resources as lost custody or infer a clean state beyond the current page", async () => {
    const f = recoveryCenterFixture();
    try {
      f.database.db.prepare("UPDATE worker_resources SET state='RUNNING'").run();
      expect(
        (await f.service.snapshot(f.scope, "NORMAL", { kind: "CUSTODY", ownedResourceIds: [f.resourceId] })).issues
      ).toHaveLength(0);
      expect(
        (await f.service.snapshot(f.scope, "UNKNOWN", { kind: "CUSTODY", ownedResourceIds: [] })).issues[0]!.state
      ).toBe("RUNNING");
      expect((await f.service.snapshot(f.scope, "UNKNOWN", { page: 2, pageSize: 1 })).issues).toHaveLength(0);
    } finally {
      f.close();
    }
  });
  it("keeps the latest committed human review when timestamps tie", async () => {
    const f = recoveryCenterFixture();
    try {
      const i = (await f.service.snapshot(f.scope, "QUARANTINED", { kind: "CUSTODY" })).issues[0]!,
        input = {
          kind: i.kind,
          subjectId: i.subjectId,
          snapshotDigest: i.snapshotDigest,
          reason: "OWNER_INVESTIGATION",
          confirmation: "I_REVIEWED_EVIDENCE_WITHOUT_RESOLVING_UNCERTAINTY"
        };
      await f.service.review(f.scope, { ...input, decision: "ACKNOWLEDGED" });
      await f.service.review(f.scope, { ...input, decision: "ESCALATED" });
      f.database.db.prepare("UPDATE operator_uncertainty_reviews SET created_at='2026-01-01T00:00:00.000Z'").run();
      expect((await f.service.snapshot(f.scope, "QUARANTINED", { kind: "CUSTODY" })).issues[0]!.review?.decision).toBe(
        "ESCALATED"
      );
    } finally {
      f.close();
    }
  });
});
