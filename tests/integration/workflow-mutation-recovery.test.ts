import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { MutationJournal, GlobalMutationLock } from "../../src/core/offensive/MutationJournal.js";
import { recoverWorkflow } from "../../src/core/offensive/WorkflowRecoveryExecutor.js";
import { workflowKeys } from "../../src/core/offensive/WorkflowMutationCoordinator.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { workflowRecoveryFixture as fixture, closeRecoveryFixtures } from "../helpers/workflow-recovery-fixture.js";
afterEach(closeRecoveryFixtures);

describe("shared workflow mutation coordination and restart recovery", () => {
  it.each(workflowKeys)("recovers %s from encrypted state without replaying its attack", async (workflow) => {
    const { context, checkpoint, path, received } = await fixture(workflow);
    expect(await readFile(path, "utf8")).not.toContain("captured-restoration-sentinel");
    expect(await readFile(context.mutations.journal.path, "utf8")).not.toContain("captured-restoration-sentinel");
    const another = new GlobalMutationLock(join(context.mutations.directory, "global-mutation.lock"));
    await expect(another.acquire("different-engine-case")).rejects.toThrow("UNRESOLVED_PRIOR_CLEANUP");
    const result = await recoverWorkflow(checkpoint, { mutationJournalDir: context.mutations.directory });
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
    expect(received).toEqual(["POST /fixture/cleanup", "GET /state"]);
    expect(await new MutationJournal(context.mutations.journal.path).unresolvedCaseIds()).toEqual([]);
    await expect(readFile(path)).rejects.toMatchObject({ code: "ENOENT" });
    await another.acquire("next-engine-case"); await another.release();
  });
  it("retains the obligation and sends nothing when current scope forbids cleanup", async () => {
    const { context, checkpoint, path, received, scope } = await fixture("authenticationLifecycle");
    const result = await recoverWorkflow(checkpoint, { mutationJournalDir: context.mutations.directory, recoveryScope: { ...scope, disallowedPaths: ["/fixture", "/state"] } });
    expect(result.cleanupOutcome).toBe("CLEANUP_FAILED"); expect(received).toEqual([]);
    expect((await readFile(path)).length).toBeGreaterThan(0);
    expect(await context.mutations.journal.unresolvedCaseIds()).toContain(checkpoint.caseId);
  });
  it("serializes concurrent journal writers without dropping obligations", async () => {
    const path = join(process.env.ROUTECAIRN_MUTATION_DIR!, "mutation-journal.json");
    await Promise.all(Array.from({ length: 8 }, (_, index) => new MutationJournal(path).append({ caseId: `case-${index}`, stage: "MUTATION_ARMED" })));
    const journal = new MutationJournal(path); expect(await journal.unresolvedCaseIds()).toHaveLength(8);
    expect((await journal.read()).map((entry) => entry.sequence)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });
  it("rejects a checkpoint replaced between inspection and acquiring the mutation lease", async () => {
    const { context, checkpoint, received } = await fixture("authenticationLifecycle");
    await new MutationRecoveryVault(context.mutations.directory).seal({ ...checkpoint, revision: "a-new-revision" });
    const result = await recoverWorkflow(checkpoint, { mutationJournalDir: context.mutations.directory });
    expect(result.cleanupOutcome).toBe("CLEANUP_FAILED"); expect(received).toEqual([]);
    expect(await context.mutations.journal.unresolvedCaseIds()).toContain(checkpoint.caseId);
  });
  it("rejects fresh credentials for a different principal before any cleanup request", async () => {
    const { context, checkpoint, received } = await fixture("authenticationLifecycle", { authProfile: authProfileSchema.parse({ principalId: "owner", headers: { authorization: "Bearer original" } }) });
    await expect(recoverWorkflow(checkpoint, { mutationJournalDir: context.mutations.directory, authProfile: authProfileSchema.parse({ principalId: "different-owner", headers: { authorization: "Bearer fresh" } }) })).rejects.toThrow("RECOVERY_ACTOR_MISMATCH");
    expect(received).toEqual([]);
    expect(await context.mutations.journal.unresolvedCaseIds()).toContain(checkpoint.caseId);
  });
});
