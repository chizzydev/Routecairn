import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { exampleScope } from "../../src/config/defaults.js";
import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { recoveryCenterFixture } from "../helpers/recovery-center-fixture.js";
import { RecoveryCenterService } from "../../src/dashboard/recovery/RecoveryCenterService.js";
const confirmation = "I_REVIEWED_EVIDENCE_WITHOUT_RESOLVING_UNCERTAINTY";
describe("durable real SQLite operator uncertainty workflows", () => {
  it("projects custody, unknown assurance, orphan deployment and failed comparisons without raw secrets", async () => {
    const f = recoveryCenterFixture();
    try {
      const view = await f.service.snapshot(f.scope, "QUARANTINED");
      expect(view.issues.map((i) => i.kind)).toEqual(
        expect.arrayContaining(["CUSTODY", "ASSURANCE", "DEPLOYMENT", "COMPARISON"])
      );
      expect(view.issues.find((i) => i.kind === "ASSURANCE")?.state).toBe("UNKNOWN");
      expect(JSON.stringify(view)).not.toContain("RAW_");
      expect(view.automaticReplay).toBe(false);
    } finally {
      f.close();
    }
  });
  it("records idempotent review while preserving all custody and assurance blockers", async () => {
    const f = recoveryCenterFixture();
    try {
      const issue = (await f.service.snapshot(f.scope, "QUARANTINED")).issues.find((i) => i.kind === "CUSTODY")!;
      const input = {
        ...{ kind: issue.kind, subjectId: issue.subjectId, snapshotDigest: issue.snapshotDigest },
        decision: "ACKNOWLEDGED",
        reason: "EVIDENCE_INCOMPLETE",
        confirmation
      };
      const a = await f.service.review(f.scope, input),
        b = await f.service.review(f.scope, input);
      expect(a).toEqual(b);
      expect(a.uncertaintyResolved).toBe(false);
      expect(f.database.db.prepare("SELECT state FROM worker_resources").get()).toEqual({ state: "UNKNOWN_RETAINED" });
      expect(f.database.db.prepare("SELECT gate_status FROM continuous_assurance_runs").get()).toEqual({
        gate_status: "INCONCLUSIVE"
      });
      const fresh = new RecoveryCenterService(f.database, f.emptyWorkflow as never);
      expect(
        (await fresh.snapshot(f.scope, "QUARANTINED")).issues.find((i) => i.kind === "CUSTODY")?.review?.current
      ).toBe(true);
    } finally {
      f.close();
    }
  });
  it("rejects stale evidence and marks earlier reviews stale", async () => {
    const f = recoveryCenterFixture();
    try {
      const issue = (await f.service.snapshot(f.scope, "QUARANTINED")).issues[0]!;
      const input = {
        kind: issue.kind,
        subjectId: issue.subjectId,
        snapshotDigest: issue.snapshotDigest,
        decision: "ACKNOWLEDGED",
        reason: "EVIDENCE_INCOMPLETE",
        confirmation
      };
      await f.service.review(f.scope, input);
      f.database.db.prepare("UPDATE worker_resources SET evidence_json='{}'").run();
      await expect(f.service.review(f.scope, input)).rejects.toThrow("changed");
      expect((await f.service.snapshot(f.scope, "QUARANTINED")).issues[0]?.review?.current).toBe(false);
    } finally {
      f.close();
    }
  });
  it("does not allow a reviewer to invent a resolved outcome or clearance", async () => {
    const f = recoveryCenterFixture();
    try {
      await expect(
        f.service.review(f.scope, {
          kind: "CUSTODY",
          subjectId: f.resourceId,
          snapshotDigest: "a".repeat(64),
          decision: "RESOLVED",
          reason: "EVIDENCE_INCOMPLETE",
          confirmation,
          clearQuarantine: true
        })
      ).rejects.toThrow();
    } finally {
      f.close();
    }
  });
  it("enforces organization and action permissions on direct service calls", async () => {
    const f = recoveryCenterFixture();
    try {
      expect((await f.service.snapshot({ ...f.scope, organizationId: f.other }, "QUARANTINED")).issues).toEqual([]);
      const i = (await f.service.snapshot(f.scope, "QUARANTINED")).issues[0]!;
      const input = {
        kind: i.kind,
        subjectId: i.subjectId,
        snapshotDigest: i.snapshotDigest,
        decision: "ESCALATED",
        reason: "OWNER_INVESTIGATION",
        confirmation
      };
      await expect(f.service.review({ ...f.scope, canManageWorkers: false }, input)).rejects.toThrow("Permission");
      await expect(f.service.review({ ...f.scope, organizationId: f.other }, input)).rejects.toThrow("not available");
      await expect(
        f.service.recompute(
          { ...f.scope, canRecompute: false },
          {
            subjectId: f.comparisonId,
            snapshotDigest: "a".repeat(64),
            requestId: randomUUID(),
            confirmation: "I_AUTHORIZE_COMPARISON_ONLY_NO_SCAN_OR_GATE_CHANGE"
          }
        )
      ).rejects.toThrow("permission");
    } finally {
      f.close();
    }
  });
  it("retains new offline comparison attempts and idempotency without erasing original FAILED evidence", async () => {
    const f = recoveryCenterFixture();
    try {
      const issue = (await f.service.snapshot(f.scope, "NORMAL")).issues.find((i) => i.kind === "COMPARISON")!,
        input = {
          subjectId: issue.subjectId,
          snapshotDigest: issue.snapshotDigest,
          requestId: randomUUID(),
          confirmation: "I_AUTHORIZE_COMPARISON_ONLY_NO_SCAN_OR_GATE_CHANGE"
        };
      const result = await f.service.recompute(f.scope, input);
      expect(result.comparisonId).not.toBe(f.comparisonId);
      expect(f.database.db.prepare("SELECT state FROM scan_comparisons WHERE id=?").get(f.comparisonId)).toEqual({
        state: "FAILED"
      });
      expect(await f.service.recompute(f.scope, input)).toEqual(result);
      expect(f.database.db.prepare("SELECT COUNT(*) n FROM operator_comparison_attempts").get()).toEqual({ n: 1 });
      expect(f.database.db.prepare("SELECT gate_status FROM continuous_assurance_runs").get()).toEqual({
        gate_status: "INCONCLUSIVE"
      });
      f.capture("OFFLINE_RECOMPUTE");
    } finally {
      f.close();
    }
  });
  it("retains failed recomputation evidence", async () => {
    const f = recoveryCenterFixture();
    try {
      const issue = (await f.service.snapshot(f.scope, "NORMAL")).issues.find((i) => i.kind === "COMPARISON")!;
      f.database.db.exec(
        "CREATE TRIGGER fixture_comparison_failure BEFORE UPDATE OF state ON scan_comparisons WHEN NEW.state IN ('COMPLETED','PARTIAL') BEGIN SELECT RAISE(ABORT,'FIXTURE_ANALYSIS_FAILURE'); END;"
      );
      const result = await f.service.recompute(f.scope, {
        subjectId: issue.subjectId,
        snapshotDigest: issue.snapshotDigest,
        requestId: randomUUID(),
        confirmation: "I_AUTHORIZE_COMPARISON_ONLY_NO_SCAN_OR_GATE_CHANGE"
      });
      expect(result.status).toBe("FAILED");
      expect(f.database.db.prepare("SELECT status FROM operator_comparison_attempts").get()).toEqual({
        status: "FAILED"
      });
    } finally {
      f.close();
    }
  });
  it("requires fresh digest when comparison coverage evidence changes", async () => {
    const f = recoveryCenterFixture();
    try {
      const issue = (await f.service.snapshot(f.scope, "NORMAL")).issues.find((i) => i.kind === "COMPARISON")!;
      f.database.db
        .prepare("UPDATE scan_comparisons SET coverage_summary_json=? WHERE id=?")
        .run('{"changed":true}', f.comparisonId);
      await expect(
        f.service.recompute(f.scope, {
          subjectId: issue.subjectId,
          snapshotDigest: issue.snapshotDigest,
          requestId: randomUUID(),
          confirmation: "I_AUTHORIZE_COMPARISON_ONLY_NO_SCAN_OR_GATE_CHANGE"
        })
      ).rejects.toThrow("changed");
    } finally {
      f.close();
    }
  });
  it("can review opaque deployment reservations without exposing trigger identifiers or clearing them", async () => {
    const f = recoveryCenterFixture();
    try {
      const i = (await f.service.snapshot(f.scope, "NORMAL")).issues.find((i) => i.kind === "DEPLOYMENT")!;
      await f.service.review(f.scope, {
        kind: i.kind,
        subjectId: i.subjectId,
        snapshotDigest: i.snapshotDigest,
        decision: "ESCALATED",
        reason: "OWNER_INVESTIGATION",
        confirmation
      });
      expect(f.database.db.prepare("SELECT run_id FROM continuous_assurance_deployments").get()).toEqual({
        run_id: null
      });
    } finally {
      f.close();
    }
  });
  it("reports unavailable inventory and pagination instead of a clean-state claim", async () => {
    const f = recoveryCenterFixture();
    try {
      const service = new RecoveryCenterService(f.database, {
        inventory: async () => {
          throw Error("PRIVATE_SECRET");
        }
      });
      const view = await service.snapshot(f.scope, "UNKNOWN", { pageSize: 1 });
      expect(view.inventoryWarnings.length).toBe(1);
      expect(JSON.stringify(view)).not.toContain("PRIVATE_SECRET");
      await expect(service.snapshot(f.scope, "UNKNOWN", { page: 0 })).rejects.toThrow("page");
    } finally {
      f.close();
    }
  });
  it("refuses ambiguous cleanup origin attribution", () => {
    const f = recoveryCenterFixture();
    try {
      expect(f.service.originOwned("http://127.0.0.1:47999", f.scope.organizationId)).toBe(true);
      new TargetRepository(f.database).create({
        organizationId: f.other,
        displayName: "Ambiguous-origin fixture",
        baseOrigin: "http://127.0.0.1:47999",
        tags: [],
        classification: "LOCAL",
        authorizationType: "OWNED",
        authorizationSummary: "Synthetic ownership ambiguity",
        approvedScope: exampleScope
      });
      expect(f.service.originOwned("http://127.0.0.1:47999", f.scope.organizationId)).toBe(false);
    } finally {
      f.close();
    }
  });
});
