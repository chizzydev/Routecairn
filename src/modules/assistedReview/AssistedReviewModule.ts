import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Finding, AssistedAssessmentOutcome } from "../../core/findings/Finding.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { AssistedReviewReport } from "../../reports/AssistedReviewReport.js";
import { assistedReviewLanes, type AssistedReviewCase, type AssistedReviewPlan } from "./AssistedReviewTypes.js";
import { collectAssistedCases } from "./AssistedCaseCollector.js";
import { preHandoverReadiness } from "../preHandover/PreHandoverRuntime.js";

export class AssistedReviewModule implements RouteCairnPlugin {
  public readonly name = "assisted-review";
  public readonly description = "Explicit review coverage, human acceptance, evidence packaging, and completion gates.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const plan = context.options.plan.assistedReview;
    if (!plan) throw new Error("ASSISTED_REVIEW_PLAN_REQUIRED");
    const findings = context.state.getFindings();
    const observed = context.state.getModuleResults().flatMap((result) => collectAssistedCases(result, findings));
    const cases = plan.cases.map((expected): AssistedReviewCase => {
      const matches = observed.filter((item) => item.workflowId === expected.workflowId && item.caseId === expected.caseId);
      if (matches.length === 1 && matches[0]!.lane === expected.lane) return matches[0]!;
      return { ...expected, label: expected.caseId, assessmentOutcome: matches.length ? "INCONCLUSIVE" : "NOT_ASSESSED", conclusion: matches.length ? "UNRESOLVED" : "NOT_RUN", cleanupFailed: matches.some((item) => item.cleanupFailed), evidenceRefs: [], proofPackRefs: [] };
    });
    const report = await buildReport(context, plan, cases, findings, observed.some((item) => item.cleanupFailed));
    await context.eventSink.emit({ type: "OBSERVATION_RECORDED", moduleId: "assisted-review", message: `Assisted review gate: ${report.completionGate.state}.`, metadata: { reviewId: plan.reviewId, cases: cases.length, pendingHumanReview: report.humanReviewQueue.length, blockers: report.completionGate.blockers } });
    return { pluginName: this.name, assistedReview: report, notes: [...report.notes] };
  }
}

async function buildReport(context: ScanContext, plan: AssistedReviewPlan, cases: AssistedReviewCase[], findings: Finding[], anyCleanupUnresolved: boolean): Promise<AssistedReviewReport> {
  const selectedCases = new Set(cases.map((item) => `${item.workflowId}/${item.caseId}`));
  const accepted = findings.filter((finding) => finding.workflow && selectedCases.has(`${finding.workflow.workflowId}/${finding.workflow.caseId}`));
  const coverageMatrix = Object.fromEntries(assistedReviewLanes.map((lane) => {
    const laneCases = cases.filter((item) => item.lane === lane);
    return [lane, {
      selected: plan.focus.includes(lane), required: plan.requiredLanes.includes(lane), total: laneCases.length,
      outcomes: Object.fromEntries(["PROVEN", "INCONCLUSIVE", "NOT_ASSESSED", "BLOCKED"].map((outcome) => [outcome, laneCases.filter((item) => item.assessmentOutcome === outcome).length])) as Record<AssistedAssessmentOutcome, number>,
      cleanupFailures: laneCases.filter((item) => item.cleanupFailed).length
    }];
  })) as AssistedReviewReport["coverageMatrix"];
  const humanReviewQueue = accepted.map((finding) => ({ findingId: finding.id, workflowId: finding.workflow!.workflowId, caseId: finding.workflow!.caseId, severity: finding.severity, evidenceRef: finding.workflow!.evidenceRef, proofPackRefs: finding.workflow!.proofPackRefs, state: "PENDING_HUMAN_REVIEW" as const }));
  const blockers: string[] = [];
  const preHandover = context.options.plan.preHandover ? preHandoverReadiness(context.options.plan.preHandover, cases) : undefined;
  if (preHandover) blockers.push(...preHandover.blockers);
  if (cases.some((item) => item.conclusion === "FINDING" && !accepted.some((finding) => finding.workflow?.workflowId === item.workflowId && finding.workflow.caseId === item.caseId))) blockers.push("FINDING_ACCEPTANCE_MISSING");
  for (const lane of plan.requiredLanes) {
    const coverage = coverageMatrix[lane];
    if (coverage.outcomes.NOT_ASSESSED > 0) blockers.push(`${lane}:NOT_ASSESSED`);
    if (plan.requireNoBlocked && coverage.outcomes.BLOCKED > 0) blockers.push(`${lane}:BLOCKED`);
    if (plan.requireNoInconclusive && coverage.outcomes.INCONCLUSIVE > 0) blockers.push(`${lane}:INCONCLUSIVE`);
  }
  if (anyCleanupUnresolved) blockers.push("CLEANUP_UNRESOLVED");
  const identity = context.state.getIdentityVerification();
  if (plan.requireVerifiedIdentity && !(identity?.primary?.verified || identity?.accountA?.verified)) blockers.push("AUTHENTICATED_IDENTITY_NOT_VERIFIED");
  if (plan.requireAccountPair && !identity?.distinctVerifiedPrincipals) blockers.push("ACCOUNT_PAIR_NOT_VERIFIED");
  await mkdir(context.options.outputDir, { recursive: true });
  const evidencePath = join(context.options.outputDir, "assisted-review.evidence.json");
  const customerPath = join(context.options.outputDir, "assisted-review.customer.json");
  const remediationRoadmap = [...accepted].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)).map((finding, index) => ({ priority: index + 1, findingId: finding.id, title: finding.title, severity: finding.severity, customerSafeRemediation: finding.customerSafeRemediation ?? finding.recommendation }));
  await writeFile(evidencePath, `${JSON.stringify({ schemaVersion: 1, reviewId: plan.reviewId, cases, findings: accepted, findingLinks: humanReviewQueue, redaction: { rawSecretsStored: false, operatorAuthorizationStored: false } }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  // Scanner output is only a coverage draft. A dashboard human acceptance gate publishes findings.
  await writeFile(customerPath, `${JSON.stringify({ schemaVersion: 1, reviewId: plan.reviewId, title: plan.title, ...(plan.customerName ? { customerName: plan.customerName } : {}), status: accepted.length ? "DRAFT_PENDING_HUMAN_REVIEW" : "COVERAGE_ONLY", coverage: coverageMatrix, findings: [], pendingHumanReview: accepted.length, limitations: blockers, operatorEvidenceIncluded: false }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  const gateState = blockers.length > 0 ? "BLOCKED" as const : humanReviewQueue.length > 0 ? "AWAITING_HUMAN_REVIEW" as const : "READY" as const;
  return {
    ...(preHandover ? { preHandover } : {}),
    ...(context.options.plan.targetAuthorization ? { targetMode: context.options.plan.targetAuthorization.mode } : {}),
    enabled: true, schemaVersion: 1, reviewId: plan.reviewId, title: plan.title, focus: plan.focus, cases, coverageMatrix, humanReviewQueue,
    timeline: cases.map((item, index) => ({ sequence: index + 1, lane: item.lane, workflowId: item.workflowId, caseId: item.caseId, outcome: item.assessmentOutcome })),
    evidencePackage: { artifactPath: evidencePath, caseCount: cases.length, findingCount: accepted.length, rawSecretsStored: false },
    customerSafeReport: { artifactPath: customerPath, findingCount: 0, operatorEvidenceIncluded: false }, remediationRoadmap,
    completionGate: { state: gateState, blockers, humanReviewRequired: true }, notes: plan.notes
  };
}

function severityRank(value: string): number { return ({ Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 } as Record<string, number>)[value] ?? 0; }
