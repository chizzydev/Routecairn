import type { ChildProcess } from "node:child_process";
import { describe, it, expect } from "vitest";
import { workerFixture } from "../helpers/worker-lifecycle-fixture.js";
import { RecoveryCenterService } from "../../src/dashboard/recovery/RecoveryCenterService.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
describe.skipIf(process.platform !== "win32")("real worker loss to operator recovery projection", () => {
  it("retains durable UNKNOWN and dispatch fencing after human review", async () => {
    const f = await workerFixture(true);
    let injected = false;
    try {
      const id = await f.execution.enqueue(f.request);
      await f.seen();
      const root = f.child(id)!,
        helper = (
          f.workers as unknown as { custody: Map<ChildProcess, { job: { helper: ChildProcess } }> }
        ).custody.get(root)!.job.helper;
      const closed = new Promise<void>((r) => helper.once("close", () => r()));
      helper.kill("SIGKILL");
      injected = true;
      await closed;
      const service = new RecoveryCenterService(f.database, {
          inventory: async () => ({ cases: [], jobs: [], globalMutationActive: false, cleanupRequired: 0, modes: {} })
        } as never),
        scope = {
          organizationId: new OrganizationService(f.database).defaultOrganizationId(),
          actor: "local-operator",
          canReview: true,
          canManageWorkers: true,
          canRecover: false,
          canRecompute: false
        };
      const issue = (await service.snapshot(scope, f.workers.diagnostics().dispatchState)).issues.find(
        (i) => i.kind === "CUSTODY"
      )!;
      expect(issue.state).toBe("UNKNOWN_RETAINED");
      expect(issue.actions.cleanup).toBe(false);
      await service.review(scope, {
        kind: issue.kind,
        subjectId: issue.subjectId,
        snapshotDigest: issue.snapshotDigest,
        decision: "ESCALATED",
        reason: "OWNER_INVESTIGATION",
        confirmation: "I_REVIEWED_EVIDENCE_WITHOUT_RESOLVING_UNCERTAINTY"
      });
      expect(() => f.workers.releaseFleet()).toThrow("WORKER_CUSTODY_REVIEW_REQUIRED");
      expect(f.workers.diagnostics().dispatchState).toBe("QUARANTINED");
      f.capture("OPERATOR_REVIEW_NATIVE_CUSTODY_UNKNOWN");
    } finally {
      f.release();
      if (injected) await expect(f.close()).rejects.toThrow("WORKER_RETENTION_UNKNOWN");
      else await f.close();
    }
  });
});
