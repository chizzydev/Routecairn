import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { AssistedReviewModule } from "../../src/modules/assistedReview/AssistedReviewModule.js";
import { planAssistedReview } from "../../src/modules/assistedReview/AssistedReviewPlanner.js";
import { PluginRegistry } from "../../src/core/plugins/PluginRegistry.js";
import { ModuleRunner } from "../../src/core/plugins/ModuleRunner.js";
import { moduleCatalog } from "../../src/core/planning/ModuleCatalog.js";
import { resolveDashboardScanPlan } from "../../src/dashboard/execution/ScanExecutionShared.js";
import { testPlan } from "../helpers/plan.js";
import { assistedFinding, lifecycleResult, reviewManifest } from "../helpers/assisted-review.js";

const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });

async function context(manifest = reviewManifest()) {
  const outputDir = await mkdtemp(join(tmpdir(), "routecairn-assisted-review-")); directories.push(outputDir);
  return new ScanContext({ target: "https://app.test", scope: exampleScope, config: defaultConfig, outputDir, plan: { ...testPlan("quick"), assistedReview: planAssistedReview(manifest) } });
}

describe("assisted review orchestration", () => {
  it("round-trips the inline dashboard manifest and appends orchestration after the selected modules", async () => {
    const ctx = await context(); const scopeFile = join(ctx.options.outputDir, "scope.json");
    await writeFile(scopeFile, JSON.stringify(exampleScope));
    const { plan } = await resolveDashboardScanPlan({ target: "https://example.com", profile: "quick", scopeFile, includeModules: ["baseline"], assistedReview: reviewManifest() });
    expect(plan.modules.map((item) => item.id)).toEqual(["baseline", "assisted-review"]);
    expect(plan.assistedReview).toMatchObject({ reviewId: "review-test", requireHumanReviewForFindings: true });
    const requiringIdentity = reviewManifest(); requiringIdentity.authentication.requireVerifiedIdentity = true;
    await expect(resolveDashboardScanPlan({ target: "https://example.com", profile: "quick", scopeFile, includeModules: ["baseline"], assistedReview: requiringIdentity })).rejects.toThrow(/authenticat|identity/i);
  });

  it("runs accepted findings through the module runner and produces a coverage-only customer draft", async () => {
    const ctx = await context();
    const registry = new PluginRegistry();
    registry.register({ name: "authentication-lifecycle", description: "fixture", phase: "analysis", async run() { return { ...lifecycleResult(), findings: [assistedFinding()] }; } }, moduleCatalog["authentication-lifecycle"]);
    registry.register(new AssistedReviewModule(), moduleCatalog["assisted-review"]);
    const plan = { ...ctx.options.plan, modules: ["authentication-lifecycle", "assisted-review"].map((id) => ({ id, phase: "analysis", settings: {}, limits: {}, includedBecause: ["fixture"] })) } as typeof ctx.options.plan;
    await new ModuleRunner(registry).runPlan(ctx, plan);
    const report = ctx.state.getAssistedReview()!;
    expect(report.completionGate).toMatchObject({ state: "AWAITING_HUMAN_REVIEW", blockers: [] });
    expect(report.humanReviewQueue).toHaveLength(1);
    expect(report.cases[0]).toMatchObject({ assessmentOutcome: "PROVEN", conclusion: "FINDING", cleanupFailed: false });
    const draft = JSON.parse(await readFile(report.customerSafeReport.artifactPath, "utf8"));
    expect(draft).toMatchObject({ status: "DRAFT_PENDING_HUMAN_REVIEW", findings: [], pendingHumanReview: 1, operatorEvidenceIncluded: false });
    expect(await readFile(report.customerSafeReport.artifactPath, "utf8")).not.toContain("bodyHash");
    const evidence = JSON.parse(await readFile(report.evidencePackage.artifactPath, "utf8"));
    expect(evidence.findings[0].workflow.caseId).toBe("logout");
  });

  it.each([["PASS", "READY", "PROVEN"], ["INCONCLUSIVE", "BLOCKED", "INCONCLUSIVE"], ["BLOCKED_BY_SAFETY", "BLOCKED", "BLOCKED"]])("retains the %s assessment", async (outcome, state, assessmentOutcome) => {
    const ctx = await context(); ctx.state.recordModuleResult(lifecycleResult(outcome));
    const report = (await new AssistedReviewModule().run(ctx)).assistedReview!;
    expect(report.completionGate.state).toBe(state);
    expect(report.cases[0]!.assessmentOutcome).toBe(assessmentOutcome);
  });

  it("records absent explicit cases as NOT_ASSESSED and blocks completion", async () => {
    const report = (await new AssistedReviewModule().run(await context())).assistedReview!;
    expect(report.cases[0]).toMatchObject({ assessmentOutcome: "NOT_ASSESSED", conclusion: "NOT_RUN" });
    expect(report.completionGate.blockers).toContain("AUTH_LIFECYCLE:NOT_ASSESSED");
  });

  it("blocks unaccepted findings and cleanup outside the selected case", async () => {
    const ctx = await context();
    ctx.state.recordModuleResult(lifecycleResult("FAIL"));
    ctx.state.recordModuleResult(lifecycleResult("PASS", "CLEANUP_FAILED", "unselected-case"));
    const report = (await new AssistedReviewModule().run(ctx)).assistedReview!;
    expect(report.completionGate.blockers).toEqual(expect.arrayContaining(["FINDING_ACCEPTANCE_MISSING", "CLEANUP_UNRESOLVED"]));
  });

  it("preserves safe cleanup results when finding acceptance rejects an incomplete module result", async () => {
    const ctx = await context(); const registry = new PluginRegistry();
    const finding = assistedFinding(); delete finding.workflowCase;
    registry.register({ name: "authentication-lifecycle", description: "fixture", phase: "analysis", async run() { return { ...lifecycleResult("FAIL", "CLEANUP_FAILED"), findings: [finding] }; } }, moduleCatalog["authentication-lifecycle"]);
    const plan = { ...ctx.options.plan, modules: [{ id: "authentication-lifecycle", phase: "analysis", settings: {}, limits: {}, includedBecause: ["fixture"] }] } as typeof ctx.options.plan;
    await expect(new ModuleRunner(registry).runPlan(ctx, plan)).rejects.toThrow("ASSISTED_FINDING_CASE_LINK_REQUIRED");
    expect(ctx.state.getModuleResults()[0]!.authenticationLifecycle!.observations[0]!.cleanupOutcome).toBe("CLEANUP_FAILED");
    expect(ctx.state.getFindings()).toHaveLength(0);
  });

  it("enforces identity checks at execution time", async () => {
    const manifest = reviewManifest(); manifest.authentication.requireVerifiedIdentity = true;
    const ctx = await context(manifest); ctx.state.recordModuleResult(lifecycleResult("PASS"));
    const report = (await new AssistedReviewModule().run(ctx)).assistedReview!;
    expect(report.completionGate.blockers).toContain("AUTHENTICATED_IDENTITY_NOT_VERIFIED");
  });

  it("rejects unknown workflows, incompatible lanes, duplicate cases and disabled human-review gates", () => {
    const manifest = reviewManifest();
    expect(() => planAssistedReview({ ...manifest, cases: [...manifest.cases, ...manifest.cases] })).toThrow(/Duplicate/);
    expect(() => planAssistedReview({ ...manifest, cases: [{ ...manifest.cases[0], workflowId: "unknown-engine" }] })).toThrow(/Unknown/);
    expect(() => planAssistedReview({ ...manifest, focus: ["API"], requiredLanes: ["API"], cases: [{ ...manifest.cases[0], lane: "API" }] })).toThrow(/does not support/);
    expect(() => planAssistedReview({ ...manifest, completionGate: { requireHumanReviewForFindings: false } })).toThrow();
  });
});
