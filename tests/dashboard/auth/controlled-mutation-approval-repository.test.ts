import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../../src/dashboard/db/DashboardDatabase.js";
import { ControlledMutationApprovalRepository } from "../../../src/dashboard/db/ControlledMutationApprovalRepository.js";
import { TargetRepository } from "../../../src/dashboard/db/DashboardRepositories.js";

describe("controlled mutation approval repository", () => {
  it("persists safe approval metadata and requires preview state before approval", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const repository = new ControlledMutationApprovalRepository(database);
    const targetId = new TargetRepository(database).create({ displayName: "Test target", baseOrigin: "https://example.test", tags: [], classification: "LOCAL", authorizationType: "OWNED", authorizationSummary: "Owned staging target for security testing", approvedScope: {} });
    const id = repository.create({ caseId: "case-1", targetId, targetOrigin: "https://example.test", targetIdentityFingerprint: "b".repeat(64), scopeDigest: "c".repeat(64), planIdentity: "a".repeat(64), authorizationSummary: "Owned staging target", expiresAt: "2099-01-01T00:00:00.000Z" });
    expect(repository.get(id)?.status).toBe("PREVIEWED");
    expect(repository.approve(id, "owner")?.status).toBe("APPROVED");
    expect(repository.beginRecovery(id)?.status).toBe("EXECUTING");
    expect(() => repository.beginRecovery(id)).toThrow();
  });
});
