import { describe, expect, it } from "vitest";
import { planSnapshot, safePlanIdentity } from "../../src/dashboard/execution/ScanExecutionShared.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { testPlan } from "../helpers/plan.js";

describe("durable target policy binding", () => {
  it("binds approval identity to raw policy even when generic dashboard redaction hides its key", () => {
    const request = { target: "https://app.test", profile: "quick" as const };
    const authorization = targetAuthorizationSchema.parse({ schemaVersion: 1, mode: "INTERNAL_STAGING", targetOrigin: request.target, proof: { reference: "fixture authorization", sha256: "a".repeat(64) } });
    const plan = { ...testPlan("quick"), targetAuthorization: authorization };
    const changedProof = { ...plan, targetAuthorization: { ...authorization, proof: { ...authorization.proof, sha256: "b".repeat(64) } } };
    expect(safePlanIdentity(request, plan)).not.toBe(safePlanIdentity(request, changedProof));
    expect(planSnapshot(plan, exampleScope).scopeSummary.targetPolicyFingerprint).toBe(planSnapshot(changedProof, exampleScope).scopeSummary.targetPolicyFingerprint);
    const changedMode = { ...plan, targetAuthorization: { ...authorization, mode: "OWNED_PRODUCTION" as const } };
    expect(planSnapshot(plan, exampleScope).scopeSummary.targetPolicyFingerprint).not.toBe(planSnapshot(changedMode, exampleScope).scopeSummary.targetPolicyFingerprint);
  });
  it("requires an explicit pre-handover mode instead of inferring authority from a profile", () => {
    expect(() => new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "pre-handover", config: defaultConfig, scope: exampleScope })).toThrow("PRE_HANDOVER_MANIFEST_REQUIRED");
  });
});
