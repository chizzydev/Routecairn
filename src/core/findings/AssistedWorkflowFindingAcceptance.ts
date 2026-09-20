import { createHash } from "node:crypto";
import { evidenceFromAssistedWorkflow } from "../evidence/EvidenceBuilder.js";
import type { Finding } from "./Finding.js";
import { RiskScorer } from "./RiskScorer.js";
import type { ModuleResult } from "../plugins/Plugin.js";

export const assistedFindingModules = new Set([
  "object-pair-testing", "field-exposure-testing", "authorization-matrix-testing",
  "equivalent-route-testing", "collection-authorization-testing", "bulk-authorization-testing",
  "file-authorization-testing", "privilege-mutation-testing", "supabase-authorization",
  "authentication-lifecycle", "business-invariant", "controlled-race",
  "api-graphql-authorization", "link-portal-export-security",
  "operational-endpoint-security", "billing-entitlement-security", "secret-boundary",
  "active-vulnerability-validation"
]);

export const contractBoundAssistedModules = new Set([
  "supabase-authorization", "authentication-lifecycle", "business-invariant",
  "controlled-race", "api-graphql-authorization", "link-portal-export-security",
  "operational-endpoint-security", "billing-entitlement-security",
  "active-vulnerability-validation"
]);

/** All assisted findings cross one typed acceptance boundary before storage. */
export function acceptAssistedWorkflowFindings(result: ModuleResult): ModuleResult {
  if (!result.findings?.length) return result;
  return {
    ...result,
    findings: result.findings.map((finding) => {
      if (!assistedFindingModules.has(result.pluginName) && !finding.workflowCase) return finding;
      if (!finding.workflowCase) throw new Error("ASSISTED_FINDING_CASE_LINK_REQUIRED");
      return acceptFinding(result.pluginName, finding);
    })
  };
}

function acceptFinding(workflowId: string, finding: Finding): Finding {
  if (finding.sourceModule !== workflowId) throw new Error("ASSISTED_FINDING_MODULE_LINK_INVALID");
  const { workflowCase, ...rest } = finding;
  if (!workflowCase?.id || !/^[a-zA-Z0-9_.:/-]{1,240}$/.test(workflowCase.id)) throw new Error("ASSISTED_FINDING_CASE_LINK_INVALID");
  const caseId = workflowCase.id;
  if (contractBoundAssistedModules.has(workflowId) && !workflowCase.comparisonFingerprint) throw new Error("ASSISTED_FINDING_CONTRACT_FINGERPRINT_REQUIRED");
  if (contractBoundAssistedModules.has(workflowId) && workflowCase.comparisonFingerprint && !/^[a-f0-9]{64}$/.test(workflowCase.comparisonFingerprint)) throw new Error("ASSISTED_FINDING_CONTRACT_FINGERPRINT_INVALID");
  const comparisonFingerprint = workflowCase.comparisonFingerprint ?? fingerprint(`${workflowId}:${caseId}:${finding.type}`);
  const cleanupOutcome = workflowCase.cleanupOutcome;
  const severity = normalizeSeverity(finding.severity);
  const confidence = normalizeConfidence(finding.confidence);
  const tags = [...new Set([...finding.tags, `workflow-case:${caseId}`, "human-review-required", "assisted-finding-accepted"])];
  const evidence = evidenceFromAssistedWorkflow(finding.evidence, {
    source: finding.evidence.source ?? workflowId, severity,
    confidence, tags, workflowId, caseId
  });
  const base: Finding = {
    ...rest, url: evidence.url, severity, confidence, evidence, tags,
    workflow: {
      workflowId, caseId,
      evidenceRef: `evidence://${workflowId}/${caseId}/${fingerprint(JSON.stringify(evidence))}`,
      proofPackRefs: [],
      proofPackReadiness: "REQUIRES_HUMAN_REVIEW",
      comparisonFingerprint,
      assessmentOutcome: "PROVEN",
      humanReviewState: "REQUIRED",
      ...(cleanupOutcome ? { cleanupOutcome } : {}),
      cleanupFailed: cleanupOutcome !== undefined && !["NOT_REQUIRED", "ROLLBACK_VERIFIED", "CLEANUP_NOT_REACHED"].includes(cleanupOutcome)
    },
    customerSafeRemediation: finding.recommendation
  };
  return { ...base, riskScore: new RiskScorer().score(base) };
}

function fingerprint(value: string): string { return createHash("sha256").update(value).digest("hex"); }

function normalizeSeverity(value: string): Finding["severity"] {
  const normalized = ({ critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Informational", info: "Informational" } as Record<string, Finding["severity"]>)[value.toLowerCase()];
  if (!normalized) throw new Error("ASSISTED_FINDING_SEVERITY_INVALID");
  return normalized;
}
function normalizeConfidence(value: string): Finding["confidence"] {
  const normalized = ({ confirmed: "High", high: "High", medium: "Medium", low: "Low" } as Record<string, Finding["confidence"]>)[value.toLowerCase()];
  if (!normalized) throw new Error("ASSISTED_FINDING_CONFIDENCE_INVALID");
  return normalized;
}
