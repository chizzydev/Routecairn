import { it, expect } from "vitest";
import { continuousAssurancePolicyInputSchema as schema } from "../../src/dashboard/contracts/ContinuousAssuranceSchemas.js";
const id = "00000000-0000-4000-8000-000000000001",
  value = () => ({
    schemaVersion: 1,
    name: "Manual observed-state contract",
    targetId: id,
    authorization: {
      proofReference: "fixture://owned-manual",
      proofDigest: "a".repeat(64),
      validFrom: "2026-10-18T00:00:00.000Z",
      expiresAt: "2026-10-19T00:00:00.000Z"
    },
    triggers: { scheduleEnabled: false, intervalMinutes: 15, deploymentEnabled: false, quietWhenHealthy: true },
    observedStatePolicyVersionId: id,
    adapterProfileIds: [],
    baselines: [],
    requiredCases: [],
    gates: {
      failOnRegression: true,
      failOnNewFinding: true,
      failOnOpenDrift: true,
      requireExactCases: true,
      requireCleanupResolved: true
    },
    evidence: { retentionDays: 90, autoExportOn: [], preserveFailures: true, preserveCleanupEvidence: true }
  });
it("allows explicitly reviewed manual observation analysis without granting any automatic trigger", () => {
  expect(schema.parse(value()).triggers).toMatchObject({ scheduleEnabled: false, deploymentEnabled: false });
});
it("still refuses triggerless or unbound executable-adapter policies", () => {
  const { observedStatePolicyVersionId, ...legacy } = value();
  expect(observedStatePolicyVersionId).toBe(id);
  expect(schema.safeParse(legacy).success).toBe(false);
  expect(schema.safeParse({ ...legacy, triggers: { ...legacy.triggers, scheduleEnabled: true } }).success).toBe(false);
});
it("refuses mixing an observation-only review with executable adapters or promised auto-exports", () => {
  expect(schema.safeParse({ ...value(), adapterProfileIds: [id] }).success).toBe(false);
  expect(
    schema.safeParse({ ...value(), evidence: { ...value().evidence, autoExportOn: ["REGRESSION"] } }).success
  ).toBe(false);
});
