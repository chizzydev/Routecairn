import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { AuthorizationMatrixCasePlan, AuthorizationMatrixPlan } from "../../core/planning/ScanPlan.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type {
  AuthorizationMatrixCaseResult,
  AuthorizationMatrixConfidence,
  AuthorizationMatrixDecisionCategory,
  AuthorizationMatrixFindingCategory,
  AuthorizationMatrixReport
} from "../../reports/ReportTypes.js";
import { parseSafeFieldPath, valueAtSafePath } from "../fieldExposureTesting/SafeFieldPath.js";

export class AuthorizationMatrixModule implements RouteCairnPlugin {
  public readonly name = "authorization-matrix-testing";
  public readonly description = "Runs fixed role, tenant, account-state, and object-state authorization matrix checks.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeAuthorizationMatrix(context);
    return {
      pluginName: this.name,
      authorizationMatrix: report,
      findings: findingsFromReport(report, context),
      notes: report.notes
    };
  }
}

async function executeAuthorizationMatrix(context: ScanContext): Promise<AuthorizationMatrixReport> {
  const plan = context.options.plan.authorizationMatrixTesting;
  if (!plan) {
    return {
      enabled: false,
      plannedMatrices: 0,
      plannedCases: 0,
      plannedRequests: 0,
      executedRequests: 0,
      confirmedIssues: 0,
      cases: [],
      notes: ["Authorization matrix testing skipped because no resolved matrix plan was supplied."]
    };
  }

  const results: AuthorizationMatrixCaseResult[] = [];
  let executedRequests = 0;
  for (const matrix of plan.matrices) {
    for (const casePlan of matrix.cases) {
      const blockReason = identityBlockReason(context, casePlan);
      if (blockReason) {
        results.push(blockedCase(matrix, casePlan, blockReason));
        continue;
      }
      const result = await sendAndClassify(context, matrix, casePlan);
      executedRequests += 1;
      results.push(result);
    }
  }

  const refined = applyReferenceExpectations(results);
  const confirmedIssues = refined.filter((result) => result.findingCategory).length;
  return {
    enabled: true,
    plannedMatrices: plan.matrices.length,
    plannedCases: plan.requestMatrix.length,
    plannedRequests: plan.requestMatrix.length,
    executedRequests,
    confirmedIssues,
    cases: refined,
    notes: [
      "Authorization matrix testing executed only matrix cells resolved before scan execution.",
      "Only GET requests were used; no roles, tenants, states, endpoints, or objects were discovered or mutated.",
      "A 200 response is treated as allowed only when configured object identity and state are confirmed."
    ]
  };
}

async function sendAndClassify(context: ScanContext, matrix: AuthorizationMatrixPlan, casePlan: AuthorizationMatrixCasePlan): Promise<AuthorizationMatrixCaseResult> {
  const response = await context.createHttpClient().send({ url: casePlan.url, method: "GET", headers: { ...matrix.template.headers, ...headersForCase(context, casePlan) } });
  return classifyResponse(context, matrix, casePlan, response);
}

function headersForCase(context: ScanContext, casePlan: AuthorizationMatrixCasePlan): Record<string, string> {
  if (!casePlan.authSlot) return {};
  const profileSet = context.options.authProfileSet;
  if (!profileSet) return {};
  return casePlan.authSlot === "account_a" ? authHeadersForProfile(profileSet.accountA) : authHeadersForProfile(profileSet.accountB);
}

function classifyResponse(context: ScanContext, matrix: AuthorizationMatrixPlan, casePlan: AuthorizationMatrixCasePlan, response: HttpResponse): AuthorizationMatrixCaseResult {
  const base = resultBase(matrix, casePlan, response);
  const safety = safetyCategoryFor(response);
  if (safety) return finalize({ ...base, observedDecision: safety, matchedExpectation: matchesExpectation(casePlan.expectedDecision, safety), notes: ["Request was blocked or failed before comparable access could be established."] });
  if (response.statusCode === 429) return finalize({ ...base, observedDecision: "RATE_LIMITED", matchedExpectation: false, notes: ["Rate limiting is not treated as denial."] });
  if (response.statusCode === 401) return finalize({ ...base, observedDecision: "AUTHENTICATION_REQUIRED", matchedExpectation: matchesExpectation(casePlan.expectedDecision, "AUTHENTICATION_REQUIRED"), notes: ["Response required authentication."] });
  if (response.statusCode === 403) return finalize({ ...base, observedDecision: "ACCESS_DENIED_CONFIRMED", matchedExpectation: matchesExpectation(casePlan.expectedDecision, "ACCESS_DENIED_CONFIRMED"), notes: ["Response denied access."] });
  if (response.statusCode === 404) return finalize({ ...base, observedDecision: "OBJECT_NOT_FOUND", matchedExpectation: matchesExpectation(casePlan.expectedDecision, "OBJECT_NOT_FOUND"), notes: ["Response returned not found."] });
  if (!isSuccessful(response)) return finalize({ ...base, observedDecision: "INCONCLUSIVE", matchedExpectation: false, notes: ["Unexpected status code could not establish access decision."] });
  if ((response.contentLength ?? 0) > context.options.plan.authorizationMatrixTesting!.maxResponseBytes) return finalize({ ...base, observedDecision: "RESPONSE_TOO_LARGE", matchedExpectation: false, notes: ["Response exceeded configured authorization-matrix size limit."] });
  const analysisBody = bodyPreviewForAnalysis(response) ?? "";
  if (/login|sign in|required to log in/i.test(analysisBody)) return finalize({ ...base, observedDecision: "SOFT_DENIAL", matchedExpectation: false, notes: ["Response body looked like a login or denial page."] });
  if (!response.contentType?.toLowerCase().includes("json")) return finalize({ ...base, observedDecision: "RESPONSE_NOT_PARSEABLE", matchedExpectation: false, notes: ["Response was not JSON and could not confirm object identity."] });

  const parsed = parseJsonObject(analysisBody);
  if (!parsed) return finalize({ ...base, observedDecision: "RESPONSE_NOT_PARSEABLE", matchedExpectation: false, notes: ["Response body was not a JSON object."] });
  const objectId = scalarAtPath(parsed, matrix.objectIdentityField);
  if (!objectId || objectId !== casePlan.objectId) return finalize({ ...base, observedDecision: "OBJECT_IDENTITY_MISMATCH", objectIdentityConfirmed: false, matchedExpectation: false, notes: ["Configured object identity field did not match the supplied object ID."] });
  if (casePlan.expectedObjectState && matrix.objectStateField) {
    const objectState = scalarAtPath(parsed, matrix.objectStateField);
    if (!objectState || objectState !== casePlan.expectedObjectState) {
      return finalize({ ...base, observedDecision: "OBJECT_STATE_MISMATCH", objectIdentityConfirmed: true, objectStateConfirmed: false, matchedExpectation: false, notes: ["Configured object state field did not match the expected object state."] });
    }
  }

  const findingCategory = findingCategoryFor(casePlan);
  return finalize({
    ...base,
    observedDecision: "ACCESS_ALLOWED_CONFIRMED",
    objectIdentityConfirmed: true,
    ...(casePlan.expectedObjectState ? { objectStateConfirmed: true } : {}),
    matchedExpectation: matchesExpectation(casePlan.expectedDecision, "ACCESS_ALLOWED_CONFIRMED"),
    ...(findingCategory ? { findingCategory } : {}),
    notes: ["Configured object identity and state were confirmed before access was classified as allowed."]
  });
}

function resultBase(matrix: AuthorizationMatrixPlan, casePlan: AuthorizationMatrixCasePlan, response?: HttpResponse): AuthorizationMatrixCaseResult {
  return {
    matrixId: matrix.id,
    caseId: casePlan.id,
    actorId: casePlan.actorId,
    actorRelationship: casePlan.relationship,
    ...(casePlan.authSlot ? { authSlot: casePlan.authSlot } : {}),
    ...(casePlan.referenceCaseId ? { referenceCaseId: casePlan.referenceCaseId } : {}),
    objectType: matrix.objectType,
    objectIdHash: casePlan.objectIdHash,
    method: "GET",
    url: redactObjectId(response?.finalUrl || casePlan.url, casePlan.objectId, casePlan.objectIdHash),
    expectedDecision: casePlan.expectedDecision,
    observedDecision: "INCONCLUSIVE",
    matchedExpectation: false,
    objectIdentityConfirmed: false,
    ...(typeof response?.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response?.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response?.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response?.bodyHash ? { bodyHash: response.bodyHash } : {}),
    confidence: "INCONCLUSIVE",
    ...(response?.error ? { error: response.error.message } : {}),
    notes: []
  };
}

function blockedCase(matrix: AuthorizationMatrixPlan, casePlan: AuthorizationMatrixCasePlan, reason: string): AuthorizationMatrixCaseResult {
  return {
    ...resultBase(matrix, casePlan),
    observedDecision: "IDENTITY_REQUIREMENT_UNSATISFIED",
    matchedExpectation: false,
    notes: [`Authorization matrix case blocked before execution: ${reason}`, "Verified identity requirements were not downgraded to declared-only metadata."]
  };
}

function identityBlockReason(context: ScanContext, casePlan: AuthorizationMatrixCasePlan): string | undefined {
  if (!casePlan.requireVerifiedIdentity || !casePlan.authSlot) return undefined;
  const report = context.state.getIdentityVerification();
  const result = casePlan.authSlot === "account_a" ? report?.accountA : report?.accountB;
  if (!result?.verified) return `${casePlan.authSlot} required verified identity but result was ${result?.category ?? "missing"}.`;
  if (casePlan.expectedTenantHash && !result.tenantHash) return `${casePlan.authSlot} required verified tenant metadata.`;
  if (casePlan.expectedRoleHash && !result.roleHash) return `${casePlan.authSlot} required verified role metadata.`;
  if (casePlan.expectedAccountStateHash && !result.accountStateHash) return `${casePlan.authSlot} required verified account-state metadata.`;
  if (report?.accountA?.verified && report.accountB?.verified && report.accountA.principalHash === report.accountB.principalHash) return "Account A and Account B resolved to the same verified principal.";
  return undefined;
}

function applyReferenceExpectations(results: AuthorizationMatrixCaseResult[]): AuthorizationMatrixCaseResult[] {
  const byId = new Map(results.map((result) => [`${result.matrixId}:${result.caseId}`, result]));
  return results.map((result) => {
    if (result.expectedDecision !== "MUST_MATCH_REFERENCE_DECISION" && result.expectedDecision !== "MUST_NOT_EXCEED_REFERENCE_ACCESS") return result;
    const reference = result.referenceCaseId ? byId.get(`${result.matrixId}:${result.referenceCaseId}`) : undefined;
    if (!reference) return { ...result, matchedExpectation: false, confidence: "INCONCLUSIVE" as const, notes: [...result.notes, "Reference case result was unavailable."] };
    const matched = result.expectedDecision === "MUST_MATCH_REFERENCE_DECISION" ? result.observedDecision === reference.observedDecision : !isAllowed(result.observedDecision) || isAllowed(reference.observedDecision);
    return { ...result, matchedExpectation: matched, confidence: matched ? "HIGH" : "MEDIUM", notes: [...result.notes, `Compared with reference case ${reference.caseId}.`] };
  });
}

function finalize(result: AuthorizationMatrixCaseResult): AuthorizationMatrixCaseResult {
  if (!result.findingCategory || result.observedDecision === "ACCESS_ALLOWED_CONFIRMED") {
    return { ...result, confidence: confidenceFor(result) };
  }
  const { findingCategory: _findingCategory, ...withoutFinding } = result;
  return { ...withoutFinding, confidence: confidenceFor(withoutFinding) };
}

function matchesExpectation(expected: AuthorizationMatrixCaseResult["expectedDecision"], observed: AuthorizationMatrixDecisionCategory): boolean {
  if (expected === "MUST_ALLOW") return observed === "ACCESS_ALLOWED_CONFIRMED" || observed === "PUBLIC_REPRESENTATION";
  if (expected === "MUST_DENY") return observed === "ACCESS_DENIED_CONFIRMED" || observed === "AUTHENTICATION_REQUIRED" || observed === "OBJECT_NOT_FOUND" || observed === "SOFT_DENIAL";
  if (expected === "MUST_REQUIRE_AUTHENTICATION") return observed === "AUTHENTICATION_REQUIRED" || observed === "LOGIN_REDIRECT";
  if (expected === "MUST_RETURN_NOT_FOUND") return observed === "OBJECT_NOT_FOUND";
  if (expected === "OBSERVE_ONLY") return true;
  return false;
}

function findingCategoryFor(casePlan: AuthorizationMatrixCasePlan): AuthorizationMatrixFindingCategory | undefined {
  if (casePlan.expectedDecision !== "MUST_DENY") return undefined;
  if (casePlan.relationship.includes("CROSS_TENANT")) return "CROSS_TENANT_ACCESS_CONFIRMED";
  if (casePlan.expectedAccountStateHash) {
    if (/SUSPENDED/i.test(casePlan.actorId)) return "SUSPENDED_PRINCIPAL_ACCESS_CONFIRMED";
    if (/DEACTIVATED/i.test(casePlan.actorId)) return "DEACTIVATED_PRINCIPAL_ACCESS_CONFIRMED";
    return "ACCOUNT_STATE_RESTRICTION_BYPASS";
  }
  if (casePlan.expectedObjectStateHash) {
    if (/ARCHIVED|DELETED/i.test(casePlan.expectedObjectState ?? "")) return "ARCHIVED_OR_DELETED_OBJECT_ACCESS_CONFIRMED";
    if (/DRAFT|PRIVATE|PENDING|UNPUBLISHED/i.test(casePlan.expectedObjectState ?? "")) return "UNPUBLISHED_OBJECT_ACCESS_CONFIRMED";
    return "OBJECT_STATE_RESTRICTION_BYPASS";
  }
  if (casePlan.expectedRoleHash) return "ROLE_RESTRICTION_BYPASS";
  return "VERTICAL_AUTHORIZATION_BYPASS";
}

function confidenceFor(result: AuthorizationMatrixCaseResult): AuthorizationMatrixConfidence {
  if (result.findingCategory && result.objectIdentityConfirmed && (result.objectStateConfirmed !== false)) return "CONFIRMED";
  if (result.matchedExpectation) return "HIGH";
  if (result.observedDecision === "ACCESS_ALLOWED_CONFIRMED") return "HIGH";
  if (result.observedDecision === "INCONCLUSIVE") return "INCONCLUSIVE";
  return "MEDIUM";
}

function findingsFromReport(report: AuthorizationMatrixReport, context: ScanContext): Finding[] {
  const riskScorer = new RiskScorer();
  return report.cases
    .filter(hasFindingCategory)
    .map((result) => ({
      id: `authorization-matrix-${result.matrixId}-${result.caseId}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(),
      title: `Controlled authorization matrix issue: ${result.findingCategory}`,
      type: "Authorization Matrix Issue" as const,
      severity: "High" as const,
      confidence: "High" as const,
      url: result.url,
      method: "GET",
      ...(result.statusCode ? { statusCode: result.statusCode } : {}),
      evidence: {
        url: result.url,
        method: "GET",
        ...(result.statusCode ? { statusCode: result.statusCode } : {}),
        ...(result.bodyHash ? { bodyHash: result.bodyHash } : {}),
        ...(result.contentType ? { contentType: result.contentType } : {}),
        ...(typeof result.contentLength === "number" ? { contentLength: result.contentLength } : {}),
        curlCommand: redactedCurlCommand(result.url, authProfileForResult(context, result)),
        source: `Authorization matrix ${result.matrixId}/${result.caseId}; expected=${result.expectedDecision}; observed=${result.observedDecision}; objectHash=${result.objectIdHash}; auth material redacted.`,
        severityReason: "A configured denial boundary was bypassed after object identity and required state were confirmed.",
        reproductionNotes: [
          "Use only the supplied matrix actor, endpoint, object, and state.",
          "Confirm the actor's intended tenant, role, and account-state policy with the application owner.",
          "Repeat the redacted request with the same actor authorization context."
        ]
      },
      impact: "A principal may access a protected object despite a configured role, tenant, account-state, or object-state denial policy.",
      recommendation: "Enforce authorization server-side using trusted principal, tenant, role, account state, object owner, and object state before returning protected objects.",
      manualTestingSuggestions: ["Verify the configured policy is correct.", "Check whether sharing or public visibility intentionally permits this access.", "Add negative authorization tests for this exact matrix cell."],
      tags: ["authorization-matrix", "access-control", "needs-manual-verification", result.findingCategory.toLowerCase().replace(/_/g, "-")],
      riskScore: riskScorer.score({ severity: "High", confidence: "High", falsePositiveStatus: "likely-valid", tags: ["authorization-matrix", "access-control"] }),
      sourceModule: "authorization-matrix-testing",
      falsePositiveStatus: "likely-valid" as const,
      timestamp: new Date().toISOString()
    }));
}

function hasFindingCategory(result: AuthorizationMatrixCaseResult): result is AuthorizationMatrixCaseResult & { findingCategory: AuthorizationMatrixFindingCategory } {
  return Boolean(result.findingCategory);
}

function authProfileForResult(context: ScanContext, result: AuthorizationMatrixCaseResult) {
  if (!result.authSlot || !context.options.authProfileSet) return undefined;
  return result.authSlot === "account_a" ? context.options.authProfileSet.accountA : context.options.authProfileSet.accountB;
}

function safetyCategoryFor(response: HttpResponse): AuthorizationMatrixDecisionCategory | undefined {
  if (response.error?.name === "RequestBudgetExceeded") return "BUDGET_EXHAUSTED";
  if (response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") return "TEST_BLOCKED_BY_SAFETY_POLICY";
  if (response.error) return "EXECUTION_ERROR";
  return undefined;
}

function parseJsonObject(body: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(body) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function scalarAtPath(source: Record<string, unknown>, path: string): string | undefined {
  const extracted = valueAtSafePath(source, parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "AUTHORIZATION_MATRIX_OBJECT_FIELD_INVALID" }));
  if (typeof extracted.value === "string" || typeof extracted.value === "number") return String(extracted.value);
  return undefined;
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 300;
}

function isAllowed(decision: AuthorizationMatrixDecisionCategory): boolean {
  return decision === "ACCESS_ALLOWED_CONFIRMED" || decision === "PUBLIC_REPRESENTATION";
}

function redactObjectId(url: string, objectId: string, objectIdHash: string): string {
  return url.split(encodeURIComponent(objectId)).join(`<object:${objectIdHash}>`).split(objectId).join(`<object:${objectIdHash}>`);
}
