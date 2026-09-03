import { describe, expect, it } from "vitest";
import { planPreHandover } from "../../src/modules/preHandover/PreHandoverPlanner.js";
import { preHandoverReadiness } from "../../src/modules/preHandover/PreHandoverRuntime.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import type { AssistedReviewCase } from "../../src/modules/assistedReview/AssistedReviewTypes.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PluginRegistry } from "../../src/core/plugins/PluginRegistry.js";
import { ModuleRunner } from "../../src/core/plugins/ModuleRunner.js";
import { moduleCatalog } from "../../src/core/planning/ModuleCatalog.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { AssistedReviewModule } from "../../src/modules/assistedReview/AssistedReviewModule.js";
import { lifecycleResult } from "../helpers/assisted-review.js";
import { testPlan } from "../helpers/plan.js";
import { securityContractFingerprint } from "../../src/core/comparisons/SecurityContractFingerprint.js";

function manifest() {
  const ref = { workflowId: "authentication-lifecycle", caseId: "logout" };
  return { schemaVersion: 1, assaultId: "handover", revision: "build-123", environment: "STAGING", targetOrigin: "https://app.test", environmentVerification: { path: "/environment", field: "environment", expected: "STAGING" }, setup: { mode: "SUPPLIED_DISPOSABLE_ACCOUNTS", accountA: { path: "/me", disposableField: "disposable" }, accountB: { path: "/me", disposableField: "disposable" } }, objects: [{ id: "session-a", owner: "accountA", path: "/object", disposableField: "disposable", ownerField: "ownerId", identityField: "id", identityFingerprint: "a".repeat(64), cases: [ref] }], invariants: [], races: [], sequence: ["authentication-lifecycle"], criticalCases: [ref], regressions: [{ ...ref, previousFindingId: "finding-old", fixReference: "fix-123", comparisonFingerprint: "b".repeat(64) }], review: { schemaVersion: 1, reviewId: "handover-review", title: "Release review", focus: ["AUTH_LIFECYCLE"], requiredLanes: ["AUTH_LIFECYCLE"], cases: [{ ...ref, lane: "AUTH_LIFECYCLE" }], authentication: { requireVerifiedIdentity: true, requireAccountPair: true }, completionGate: { requireNoBlocked: true, requireNoInconclusive: true, requireHumanReviewForFindings: true } } };
}
const passed: AssistedReviewCase = { workflowId: "authentication-lifecycle", caseId: "logout", lane: "AUTH_LIFECYCLE", label: "logout", assessmentOutcome: "PROVEN", conclusion: "NO_FINDING", cleanupFailed: false, comparisonFingerprint: "b".repeat(64), evidenceRefs: [], proofPackRefs: [] };

describe("pre-handover orchestration contracts", () => {
  it("stops later engines after unresolved cleanup but still emits the completion report", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-handover-sequence-"));
    try {
      let laterRuns = 0;
      const registry = new PluginRegistry();
      registry.register({ name: "authentication-lifecycle", description: "fixture", phase: "analysis", run: async () => lifecycleResult("PASS", "CLEANUP_FAILED") }, moduleCatalog["authentication-lifecycle"]);
      registry.register({ name: "business-invariant", description: "fixture", phase: "analysis", run: async () => { laterRuns++; return { pluginName: "business-invariant" }; } }, moduleCatalog["business-invariant"]);
      registry.register(new AssistedReviewModule(), moduleCatalog["assisted-review"]);
      const preHandover = planPreHandover(manifest());
      const plan = { ...testPlan("quick"), preHandover, assistedReview: preHandover.review, modules: (["authentication-lifecycle", "business-invariant", "assisted-review"] as const).map((id) => ({ id, phase: "analysis" as const, settings: {}, limits: {}, includedBecause: ["test"] })) };
      const context = new ScanContext({ target: "https://app.test", scope: exampleScope, config: defaultConfig, plan, outputDir: directory });
      const results = await new ModuleRunner(registry).runPlan(context, plan);
      expect(laterRuns).toBe(0);
      expect(results.at(-1)?.assistedReview?.completionGate.blockers).toContain("CLEANUP_UNRESOLVED");
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
  it("requires a manifest for its dedicated profile before any work", () => {
    expect(() => new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "pre-handover", scope: exampleScope, config: defaultConfig })).toThrow("PRE_HANDOVER_MANIFEST_REQUIRED");
  });
  it("requires a non-production environment, distinct verified actors and strict review", () => {
    const input = manifest();
    expect(() => planPreHandover({ ...input, environment: "PRODUCTION" })).toThrow();
    expect(() => planPreHandover({ ...input, environmentVerification: { ...input.environmentVerification, expected: "TEST" } })).toThrow("ENVIRONMENT_MISMATCH");
    expect(() => planPreHandover({ ...input, review: { ...input.review, authentication: { requireAccountPair: false } } })).toThrow("STRICT_REVIEW_REQUIRED");
  });
  it("rejects dangling references, duplicate objects, unsafe paths and incomplete sequences", () => {
    const input = manifest();
    expect(() => planPreHandover({ ...input, criticalCases: [{ workflowId: "authentication-lifecycle", caseId: "unknown" }] })).toThrow("UNTRACKED_CASE");
    expect(() => planPreHandover({ ...input, objects: [...input.objects, ...input.objects] })).toThrow("DUPLICATE_REGISTRY_ENTRY");
    expect(() => planPreHandover({ ...input, sequence: ["business-invariant"] })).toThrow("SEQUENCE_INCOMPLETE");
    expect(() => planPreHandover({ ...input, objects: [{ ...input.objects[0], path: "//evil.test" }] })).toThrow();
  });
  it("requires exact proven-clean critical cases and fingerprint-matched fix regressions", () => {
    const plan = planPreHandover(manifest());
    expect(preHandoverReadiness(plan, [passed]).blockers).toEqual([]);
    for (const assessmentOutcome of ["INCONCLUSIVE", "BLOCKED", "NOT_ASSESSED"] as const) expect(preHandoverReadiness(plan, [{ ...passed, assessmentOutcome }]).blockers).toContain("PRE_HANDOVER_CRITICAL_WORKFLOW_UNPROVEN");
    expect(preHandoverReadiness(plan, [{ ...passed, conclusion: "FINDING" }]).blockers).toContain("PRE_HANDOVER_CRITICAL_WORKFLOW_UNPROVEN");
    expect(preHandoverReadiness(plan, [{ ...passed, comparisonFingerprint: "c".repeat(64) }]).blockers).toContain("PRE_HANDOVER_REGRESSION_UNPROVEN");
    expect(preHandoverReadiness(plan, [{ ...passed, cleanupFailed: true }]).blockers).toContain("CLEANUP_UNRESOLVED");
    expect(preHandoverReadiness(plan, []).blockers).not.toHaveLength(0);
  });
  it("does not accept a weakened assertion as remediation evidence", () => {
    const original = securityContractFingerprint("authentication-lifecycle", { assertion: { kind: "JSON_EQUALS", path: "active", expected: true } });
    const weakened = securityContractFingerprint("authentication-lifecycle", { assertion: { kind: "JSON_EQUALS", path: "active", expected: false } });
    const input = manifest(); input.regressions[0]!.comparisonFingerprint = original;
    const plan = planPreHandover(input);
    expect(preHandoverReadiness(plan, [{ ...passed, comparisonFingerprint: weakened }]).blockers).toContain("PRE_HANDOVER_REGRESSION_UNPROVEN");
  });
});
