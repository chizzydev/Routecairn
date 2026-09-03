import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../../src/dashboard/db/DashboardDatabase.js";
import { ControlledMutationApprovalRepository } from "../../../src/dashboard/db/ControlledMutationApprovalRepository.js";
import { ScanRepository, TargetRepository } from "../../../src/dashboard/db/DashboardRepositories.js";

describe("controlled mutation approval repository", () => {
  it("persists safe approval metadata and requires preview state before approval", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const repository = new ControlledMutationApprovalRepository(database);
    const targetId = new TargetRepository(database).create({ displayName: "Test target", baseOrigin: "https://example.test", tags: [], classification: "LOCAL", authorizationType: "OWNED", authorizationSummary: "Owned staging target for security testing", approvedScope: {} });
    const id = repository.create({ caseId: "case-1", targetId, targetOrigin: "https://example.test", targetIdentityFingerprint: "b".repeat(64), scopeDigest: "c".repeat(64), planIdentity: "a".repeat(64), authorizationSummary: "Owned staging target", expiresAt: "2099-01-01T00:00:00.000Z" });
    expect(repository.get(id)?.status).toBe("PREVIEWED");
    expect(repository.approve(id, "owner")?.status).toBe("APPROVED");
    expect(repository.beginRecovery(id, "00000000-0000-4000-8000-000000000002")?.recoveryJobId).toBe("00000000-0000-4000-8000-000000000002");
    repository.updateStatus(id, "CLEANUP_FAILED", "worker timeout");
    expect(repository.get(id)?.status).toBe("CLEANUP_FAILED");
    expect(repository.get(id)?.recoveryErrorSummary).toBe("worker timeout");
    expect(repository.get(id)?.recoveryCompletedAt).toBeTruthy();
    repository.beginRecovery(id, "00000000-0000-4000-8000-000000000003");
    expect(() => repository.beginRecovery(id, "00000000-0000-4000-8000-000000000004")).toThrow("MUTATION_RECOVERY_UNAVAILABLE");
    database.close();
  });
  it("consumes execution approval once and preserves interrupted cleanup obligations", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    try {
      const repository = new ControlledMutationApprovalRepository(database);
      const targetId = new TargetRepository(database).create({ displayName: "Fixture", baseOrigin: "https://example.test", tags: [], classification: "LOCAL", authorizationType: "OWNED", authorizationSummary: "Owned fixture", approvedScope: {} });
      const id = repository.create({ caseId: "once", targetId, targetOrigin: "https://example.test", targetIdentityFingerprint: "a".repeat(64), scopeDigest: "b".repeat(64), planIdentity: "c".repeat(64), authorizationSummary: "Fixture only", expiresAt: "2099-01-01T00:00:00.000Z" });
      const scans = new ScanRepository(database);
      scans.create({ id: "execution", source: "DASHBOARD", status: "QUEUED", targetOrigin: "https://example.test", safeTargetLabel: "Fixture", profile: "quick", evidenceLevel: "strong", safeConfigurationSummary: {}, outputDirectory: "fixture" });
      repository.approve(id, "fixture");
      repository.beginExecution(id, "execution");
      expect(() => repository.beginExecution(id, "execution")).toThrow("MUTATION_EXECUTION_UNAVAILABLE");
      scans.updateStatus("execution", "INTERRUPTED");
      repository.recoverInterruptedExecutions();
      expect(repository.get(id)?.status).toBe("CLEANUP_REQUIRED");
      expect(() => repository.beginExecution(id, "execution")).toThrow("MUTATION_EXECUTION_UNAVAILABLE");
    } finally { database.close(); }
  });
});
