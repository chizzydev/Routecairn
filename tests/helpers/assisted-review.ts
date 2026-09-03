import type { Finding } from "../../src/core/findings/Finding.js";
import type { ModuleResult } from "../../src/core/plugins/Plugin.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { acceptAssistedWorkflowFindings } from "../../src/core/findings/AssistedWorkflowFindingAcceptance.js";

export function assistedFinding(module = "authentication-lifecycle", caseId = "logout"): Finding {
  return { id: `${module}-${caseId}`, title: "Session remains valid", type: "Authentication Lifecycle Issue", severity: "High", confidence: "High", url: "https://app.test/session", method: "POST", sourceModule: module, evidence: { url: "https://app.test/session", method: "POST", statusCode: 200, bodyHash: "a".repeat(64), source: "fixture" }, impact: "The old session retains access.", recommendation: "Invalidate old sessions on logout.", manualTestingSuggestions: [], tags: [], riskScore: 0, falsePositiveStatus: "likely-valid", timestamp: new Date(0).toISOString(), workflowCase: { id: caseId, comparisonFingerprint: "a".repeat(64), cleanupOutcome: "ROLLBACK_VERIFIED" } };
}

export function acceptedFinding(module = "authentication-lifecycle", caseId = "logout"): Finding {
  return acceptAssistedWorkflowFindings({ pluginName: module, findings: [assistedFinding(module, caseId)] }).findings![0]!;
}

export function lifecycleResult(outcome = "FAIL", cleanup = "ROLLBACK_VERIFIED", caseId = "logout"): ModuleResult {
  // Only fields consumed by the collector are needed in this bounded report fixture.
  return { pluginName: "authentication-lifecycle", authenticationLifecycle: { enabled: true, observations: [{ caseId, label: caseId, outcome, cleanupOutcome: cleanup, comparisonFingerprint: "a".repeat(64) }] } } as ModuleResult;
}

export function reportFixture(findings: Finding[] = []): RouteCairnReport {
  return { routeCairnVersion: "0.1.0", target: "https://app.test", mode: "full", program: "disposable fixture", scope: { allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false }, metadata: { startedAt: new Date(0).toISOString(), completedAt: new Date(1).toISOString(), durationMs: 1, totalRequests: 1, failedRequests: 0 }, scopeDecisions: [], requestAudit: [], responses: [], technologies: [], discoveredUrls: [], findings };
}

export function reviewManifest() {
  return { schemaVersion: 1, reviewId: "review-test", title: "Disposable account security review", focus: ["AUTH_LIFECYCLE"], requiredLanes: ["AUTH_LIFECYCLE"], cases: [{ workflowId: "authentication-lifecycle", caseId: "logout", lane: "AUTH_LIFECYCLE" }], authentication: { requireVerifiedIdentity: false }, completionGate: { requireHumanReviewForFindings: true } };
}
