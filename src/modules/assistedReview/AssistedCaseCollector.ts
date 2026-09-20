import { createHash } from "node:crypto";
import type { ModuleResult } from "../../core/plugins/Plugin.js";
import type { Finding } from "../../core/findings/Finding.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import type { AssistedReviewCase, AssistedReviewLane } from "./AssistedReviewTypes.js";

interface CaseInput {
  id: string;
  label?: string;
  outcome?: string;
  matched?: boolean;
  finding?: boolean;
  inconclusive?: boolean;
  cleanup?: string;
  fingerprint?: string;
}

/** Explicit adapters: absent or unrecognized evidence never becomes a proven pass. */
export function collectAssistedCases(result: ModuleResult, findings: readonly Finding[] = result.findings ?? []): AssistedReviewCase[] {
  const cases: AssistedReviewCase[] = [];
  const add = (lane: AssistedReviewLane, input: CaseInput): void => {
    const linked = findings.filter((finding) => finding.workflow?.workflowId === result.pluginName && finding.workflow.caseId === input.id);
    const outcome = classifyAssessment(input, linked.length > 0);
    const ref = `evidence://${result.pluginName}/${input.id}/${createHash("sha256").update(JSON.stringify({ workflow: result.pluginName, id: input.id, outcome, fingerprint: input.fingerprint })).digest("hex")}`;
    cases.push({ lane, workflowId: result.pluginName, caseId: input.id, label: input.label ?? input.id, ...outcome,
      ...(input.cleanup ? { cleanupOutcome: input.cleanup } : {}), cleanupFailed: cleanupUnresolved(input.cleanup),
      ...(input.fingerprint ? { comparisonFingerprint: input.fingerprint } : {}),
      evidenceRefs: linked.length ? linked.map((finding) => finding.workflow!.evidenceRef) : [ref],
      proofPackRefs: linked.flatMap((finding) => finding.workflow!.proofPackRefs)
    });
  };
  for (const value of result.authenticationLifecycle?.observations ?? []) add("AUTH_LIFECYCLE", { id: value.caseId, label: value.label, outcome: value.outcome, cleanup: value.cleanupOutcome, fingerprint: value.comparisonFingerprint });
  for (const value of result.apiGraphql?.checks ?? []) add("API", { id: value.checkId, label: value.label, outcome: value.outcome, fingerprint: value.comparisonFingerprint });
  for (const value of result.apiGraphql?.schemaComparisons ?? []) add("API", { id: `schema/${value.routeId}`, label: value.routeAlias, outcome: value.outcome, ...(value.comparisonFingerprint ? { fingerprint: value.comparisonFingerprint } : {}) });
  for (const value of result.businessInvariant?.observations ?? []) add("AUTHORIZATION", { id: value.caseId, label: value.label, outcome: value.outcome, cleanup: value.cleanupOutcome, fingerprint: value.comparisonFingerprint });
  for (const value of result.controlledRace?.observations ?? []) add("AUTHORIZATION", { id: value.caseId, label: value.label, outcome: value.outcome, cleanup: value.cleanupOutcome, fingerprint: value.comparisonFingerprint });
  for (const value of result.linkPortalSecurity?.observations ?? []) add("AUTHORIZATION", { id: value.caseId, label: value.label, outcome: value.outcome, cleanup: value.cleanupOutcome, fingerprint: value.comparisonFingerprint });
  for (const value of result.operationalEndpointSecurity?.observations ?? []) add("API", { id: value.caseId, label: value.label, outcome: value.outcome, cleanup: value.cleanupOutcome, fingerprint: value.comparisonFingerprint });
  for (const value of result.billingEntitlement?.observations ?? []) add("PAYMENT_ENTITLEMENT", { id: value.caseId, label: value.label, outcome: value.outcome, cleanup: value.cleanupOutcome, fingerprint: value.comparisonFingerprint });
  for (const value of result.privilegeMutation?.observations ?? []) add("AUTHORIZATION", { id: value.caseId, outcome: value.securityOutcome, cleanup: value.cleanupOutcome, fingerprint: value.comparisonIdentity });
  for (const value of result.supabaseAuthorization?.observations ?? []) add("AUTHORIZATION", { id: value.caseId, outcome: value.observedDecision, matched: value.matchedExpectation, finding: Boolean(value.findingCategory), fingerprint: value.comparisonFingerprint, ...(value.cleanupOutcome ? { cleanup: value.cleanupOutcome } : {}) });
  for (const value of result.supabaseAuthorization?.staticRisks ?? []) add("AUTHORIZATION", { id: value.id, finding: ["High", "Critical"].includes(value.severity), fingerprint: value.comparisonFingerprint });
  for (const value of result.objectPairTesting?.cases ?? []) add("AUTHORIZATION", { id: value.caseId, matched: value.confirmedIssues.length === 0, finding: value.confirmedIssues.length > 0, inconclusive: value.inconclusive });
  for (const value of result.fieldExposureTesting?.cases ?? []) add("AUTHORIZATION", { id: value.caseId, matched: value.confirmedIssues.length === 0, finding: value.confirmedIssues.length > 0, inconclusive: value.inconclusive });
  for (const value of result.authorizationMatrix?.cases ?? []) add("AUTHORIZATION", { id: `${value.matrixId}/${value.caseId}`, outcome: value.observedDecision, matched: value.matchedExpectation, finding: Boolean(value.findingCategory) });
  for (const value of result.equivalentRouteTesting?.observations ?? []) add("AUTHORIZATION", { id: `${value.routeSetId}/${value.cellId}`, outcome: value.observedDecision, matched: value.matchedExpectation, finding: Boolean(value.findingCategory) });
  for (const value of result.collectionAuthorization?.observations ?? []) add("AUTHORIZATION", { id: `${value.collectionId}/${value.caseId}`, outcome: value.observedDecision, matched: value.matchedExpectation, finding: Boolean(value.findingCategory) });
  for (const value of result.bulkAuthorization?.observations ?? []) add("AUTHORIZATION", { id: `${value.definitionId}/${value.caseId}`, outcome: value.observedDecision, matched: ["BULK_POLICY_SATISFIED", "BULK_ALLOWED_CONFIRMED", "BULK_DENIED_CONFIRMED", "ATOMIC_REJECTION_CONFIRMED", "UNAUTHORIZED_OBJECT_FILTERED", "PER_OBJECT_DECISIONS_CONFIRMED"].includes(value.observedDecision), finding: Boolean(value.findingCategory) });
  for (const value of result.fileAuthorization?.observations ?? []) add("AUTHORIZATION", { id: `${value.definitionId}/${value.caseId}`, outcome: value.observedDecision, matched: fileExpectationMatched(value.expectedDecision, value.observedDecision, value.identityConfirmed), finding: Boolean(value.findingCategory) });
  for (const value of result.secretBoundary?.observations ?? []) add(value.surface.startsWith("BROWSER_") || value.surface === "COOKIE" ? "BROWSER" : "API", { id: value.comparisonFingerprint, outcome: value.outcome === "NEEDS_REVIEW" ? "INCONCLUSIVE" : "PASS", fingerprint: value.comparisonFingerprint });
  for (const value of result.activeVulnerability?.cases ?? []) add(value.vulnerabilityClass === "REFLECTED_XSS" ? "BROWSER" : "API", { id: value.caseId, label: value.label, outcome: value.outcome, fingerprint: value.comparisonFingerprint });
  if (result.browserCrawl?.authentication) add("BROWSER", { id: "authenticated-browser-bootstrap", label: "Authenticated browser bootstrap", outcome: result.browserCrawl.authentication.bootstrapSucceeded ? "PASS" : "BLOCKED" });
  return cases;
}

export function cleanupUnresolved(value: string | undefined): boolean {
  return value !== undefined && !["NOT_REQUIRED", "ROLLBACK_VERIFIED", "CLEANUP_NOT_REACHED"].includes(value);
}

export function collectReportAssistedCases(report: Partial<RouteCairnReport>): AssistedReviewCase[] {
  const modules = {
    objectPairTesting: "object-pair-testing", fieldExposureTesting: "field-exposure-testing",
    authorizationMatrix: "authorization-matrix-testing", equivalentRouteTesting: "equivalent-route-testing",
    collectionAuthorization: "collection-authorization-testing", bulkAuthorization: "bulk-authorization-testing",
    fileAuthorization: "file-authorization-testing", privilegeMutation: "privilege-mutation-testing",
    supabaseAuthorization: "supabase-authorization", authenticationLifecycle: "authentication-lifecycle",
    businessInvariant: "business-invariant", controlledRace: "controlled-race", apiGraphql: "api-graphql-authorization",
    linkPortalSecurity: "link-portal-export-security", operationalEndpointSecurity: "operational-endpoint-security",
    billingEntitlement: "billing-entitlement-security", secretBoundary: "secret-boundary", activeVulnerability: "active-vulnerability-validation", browserCrawl: "browser-crawler"
  } as const;
  return Object.entries(modules).flatMap(([key, pluginName]) => collectAssistedCases({ pluginName, [key]: report[key as keyof typeof modules] }, report.findings));
}

function classifyAssessment(input: CaseInput, linkedFinding: boolean): Pick<AssistedReviewCase, "assessmentOutcome" | "conclusion"> {
  const outcome = input.outcome ?? "";
  if (/BLOCKED|CREDENTIAL_UNAVAILABLE|IDENTITY_UNVERIFIED|IDENTITY_REQUIREMENT_UNSATISFIED|BUDGET_EXHAUSTED|RATE_LIMITED/.test(outcome)) return { assessmentOutcome: "BLOCKED", conclusion: "UNRESOLVED" };
  if (input.inconclusive || /INCONCLUSIVE|UNAVAILABLE|UNPARSEABLE|NOT_PARSEABLE|ERROR|UNVERIFIED|NOT_VERIFIED|OBSERVE_ONLY/.test(outcome)) return { assessmentOutcome: "INCONCLUSIVE", conclusion: "UNRESOLVED" };
  if (linkedFinding || input.finding || outcome === "FAIL" || outcome.endsWith("_PROVEN")) return { assessmentOutcome: "PROVEN", conclusion: "FINDING" };
  if (outcome === "PASS" || outcome === "SECURE_FOR_CASE" || outcome === "MUTATION_REJECTED" || input.matched === true) return { assessmentOutcome: "PROVEN", conclusion: "NO_FINDING" };
  return { assessmentOutcome: "INCONCLUSIVE", conclusion: "UNRESOLVED" };
}

function fileExpectationMatched(expected: string, observed: string, identityConfirmed: boolean): boolean {
  const denied = ["ACCESS_DENIED_CONFIRMED", "AUTHENTICATION_REQUIRED", "FILE_NOT_FOUND", "SIGNED_URL_DOWNLOAD_DENIED"];
  if (["MUST_DENY_METADATA", "MUST_DENY_CONTENT", "MUST_NOT_RECEIVE_SIGNED_URL"].includes(expected)) return denied.includes(observed);
  if (expected === "MUST_REQUIRE_AUTHENTICATION") return observed === "AUTHENTICATION_REQUIRED";
  if (expected === "MUST_RETURN_NOT_FOUND") return observed === "FILE_NOT_FOUND";
  if (!identityConfirmed) return false;
  return ({ MUST_ALLOW_METADATA: "METADATA_ACCESS_CONFIRMED", MUST_ALLOW_CONTENT: "CONTENT_ACCESS_CONFIRMED", MUST_ALLOW_PREVIEW_ONLY: "PREVIEW_ACCESS_CONFIRMED" } as Record<string, string>)[expected] === observed;
}
