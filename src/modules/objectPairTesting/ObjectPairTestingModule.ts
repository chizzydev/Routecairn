import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import { objectPairIdentityBlockReason } from "../../core/auth/IdentityVerification.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { ObjectPairCasePlan, ObjectPairRequestPlan } from "../../core/planning/ScanPlan.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type {
  ObjectPairBusinessPolicyReviewStatus,
  ObjectPairCaseResult,
  ObjectPairFinalClassification,
  ObjectPairRequestEvidence,
  ObjectPairResultCategory,
  ObjectPairTechnicalAccessResult,
  ObjectPairTestingReport
} from "../../reports/ReportTypes.js";

export class ObjectPairTestingModule implements RouteCairnPlugin {
  public readonly name = "object-pair-testing";
  public readonly description = "Runs fixed Account A/Account B object-pair authorization checks using explicitly supplied identifiers.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeObjectPairTesting(context);
    return {
      pluginName: this.name,
      objectPairTesting: report,
      findings: findingsFromObjectPairReport(report, context),
      notes: report.notes
    };
  }
}

async function executeObjectPairTesting(context: ScanContext): Promise<ObjectPairTestingReport> {
  const plan = context.options.plan.objectPairTesting;
  const profileSet = context.options.authProfileSet;
  if (!plan || !profileSet) {
    return {
      enabled: false,
      plannedCases: 0,
      plannedRequests: 0,
      executedRequests: 0,
      confirmedIssues: 0,
      cases: [],
      notes: ["Object pair testing skipped because no resolved object-pair plan and Account A/B auth context were supplied."]
    };
  }

  const identityBlockReason = objectPairIdentityBlockReason(context.state.getIdentityVerification());
  if (identityBlockReason) {
    return {
      enabled: false,
      plannedCases: plan.cases.length,
      plannedRequests: plan.requestMatrix.length,
      executedRequests: 0,
      confirmedIssues: 0,
      cases: [],
      notes: [
        `Object pair testing blocked before execution: ${identityBlockReason}`,
        "The verified-principal requirement was not downgraded to declared-only identity."
      ]
    };
  }

  const headersByPrincipal = {
    account_a: authHeadersForProfile(profileSet.accountA),
    account_b: authHeadersForProfile(profileSet.accountB)
  };
  const results = new Map<string, ObjectPairRequestEvidence>();
  let executedRequests = 0;

  for (const casePlan of plan.cases) {
    const baselineAPlan = requiredRequestPlan(casePlan, "A_TO_A");
    const baselineBPlan = requiredRequestPlan(casePlan, "B_TO_B");
    const aToBPlan = requiredRequestPlan(casePlan, "A_TO_B");
    const bToAPlan = requiredRequestPlan(casePlan, "B_TO_A");

    const baselineA = await sendPlannedRequest(context, baselineAPlan, casePlan, headersByPrincipal);
    executedRequests += 1;
    results.set(baselineAPlan.id, baselineA);

    const baselineB = await sendPlannedRequest(context, baselineBPlan, casePlan, headersByPrincipal);
    executedRequests += 1;
    results.set(baselineBPlan.id, baselineB);

    if (baselineA.category === "AUTHORIZED_BASELINE_CONFIRMED" && baselineB.category === "AUTHORIZED_BASELINE_CONFIRMED") {
      const aToB = await sendPlannedRequest(context, aToBPlan, casePlan, headersByPrincipal);
      executedRequests += 1;
      results.set(aToBPlan.id, aToB);

      const bToA = await sendPlannedRequest(context, bToAPlan, casePlan, headersByPrincipal);
      executedRequests += 1;
      results.set(bToAPlan.id, bToA);
    } else {
      results.set(aToBPlan.id, skippedCrossAccountEvidence(aToBPlan, casePlan, "Account B owner baseline was not confirmed."));
      results.set(bToAPlan.id, skippedCrossAccountEvidence(bToAPlan, casePlan, "Account A owner baseline was not confirmed."));
    }
  }

  const cases = plan.cases.map((casePlan) => caseResult(casePlan, results));
  const confirmedIssues = cases.reduce((total, item) => total + item.confirmedIssues.length, 0);

  return {
    enabled: true,
    plannedCases: plan.cases.length,
    plannedRequests: plan.requestMatrix.length,
    executedRequests,
    confirmedIssues,
    cases,
    notes: [
      "Object pair testing executed only the fixed request matrix resolved before scan execution.",
      "No object identifiers were guessed, mutated, discovered, extracted, or expanded from runtime responses.",
      "A 200 response alone is not considered proof of IDOR/BOLA; owner baselines and foreign-object evidence are required."
    ]
  };
}

async function sendPlannedRequest(
  context: ScanContext,
  requestPlan: ObjectPairRequestPlan,
  casePlan: ObjectPairCasePlan,
  headersByPrincipal: Record<ObjectPairRequestPlan["requestingPrincipal"], Record<string, string>>
): Promise<ObjectPairRequestEvidence> {
  const client = context.createHttpClient();
  const response = await client.send({
    url: requestPlan.url,
    method: requestPlan.method,
    headers: { ...casePlan.template.headers, ...headersByPrincipal[requestPlan.requestingPrincipal] }
  });
  return evidenceForResponse(requestPlan, casePlan, response);
}

function evidenceForResponse(requestPlan: ObjectPairRequestPlan, casePlan: ObjectPairCasePlan, response: HttpResponse): ObjectPairRequestEvidence {
  const assertion = requestPlan.targetOwner === "account_a" ? casePlan.accountAObject : casePlan.accountBObject;
  const body = bodyPreviewForAnalysis(response) ?? "";
  const parsedBody = parseJsonObject(body);
  const containsExpectedObjectId = hasObjectIdentityEvidence(assertion, response, body, parsedBody);
  const containsExpectedOwnerEvidence = hasOwnershipEvidence(assertion, response, body, parsedBody);
  const containsPrivateFieldEvidence = hasPrivateContentEvidence(assertion, response, body, parsedBody);
  const denialMarker = denialMarkerFor(response, body);
  const category = classify(requestPlan, response, containsExpectedObjectId, containsExpectedOwnerEvidence, containsPrivateFieldEvidence, denialMarker);
  const semantics = semanticsFor(category, requestPlan);
  const safeUrl = redactObjectId(response.finalUrl || requestPlan.url, assertion.objectId, assertion.objectIdHash);

  return {
    matrixId: requestPlan.id,
    caseId: requestPlan.caseId,
    direction: requestPlan.direction,
    purpose: requestPlan.purpose,
    requestingPrincipal: requestPlan.requestingPrincipal,
    targetOwner: requestPlan.targetOwner,
    objectType: requestPlan.objectType,
    objectIdHash: requestPlan.targetObjectIdHash,
    method: requestPlan.method,
    url: safeUrl,
    authMaterialRedacted: true,
    category,
    confidence: confidenceFor(category),
    technicalAccessResult: semantics.technicalAccessResult,
    businessPolicyReviewStatus: semantics.businessPolicyReviewStatus,
    finalClassification: semantics.finalClassification,
    response: {
      ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
      ...(response.finalUrl ? { finalUrl: safeUrl } : {}),
      ...(response.contentType ? { contentType: response.contentType } : {}),
      ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
      ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
      objectIdHash: requestPlan.targetObjectIdHash,
      containsExpectedObjectId,
      containsExpectedOwnerEvidence,
      containsPrivateFieldEvidence,
      ...(denialMarker ? { denialMarker } : {}),
      ...(response.error ? { error: response.error.message } : {})
    },
    notes: notesFor(category, requestPlan)
  };
}

function skippedCrossAccountEvidence(requestPlan: ObjectPairRequestPlan, casePlan: ObjectPairCasePlan, reason: string): ObjectPairRequestEvidence {
  const assertion = requestPlan.targetOwner === "account_a" ? casePlan.accountAObject : casePlan.accountBObject;
  return {
    matrixId: requestPlan.id,
    caseId: requestPlan.caseId,
    direction: requestPlan.direction,
    purpose: requestPlan.purpose,
    requestingPrincipal: requestPlan.requestingPrincipal,
    targetOwner: requestPlan.targetOwner,
    objectType: requestPlan.objectType,
    objectIdHash: requestPlan.targetObjectIdHash,
    method: requestPlan.method,
    url: redactObjectId(requestPlan.url, assertion.objectId, assertion.objectIdHash),
    authMaterialRedacted: true,
    category: "OWNERSHIP_NOT_CONFIRMED",
    confidence: "INCONCLUSIVE",
    technicalAccessResult: "NOT_CONFIRMED",
    businessPolicyReviewStatus: "NOT_APPLICABLE",
    finalClassification: "INCONCLUSIVE",
    response: {
      objectIdHash: requestPlan.targetObjectIdHash,
      containsExpectedObjectId: false,
      containsExpectedOwnerEvidence: false,
      containsPrivateFieldEvidence: false
    },
    notes: [
      `${requestPlan.direction} used only the supplied object identifier hash ${requestPlan.targetObjectIdHash}.`,
      `Cross-account request was not sent because ${reason}`,
      "Owner baseline confirmation is required before cross-account access can be interpreted."
    ]
  };
}

function redactObjectId(url: string, objectId: string, objectIdHash: string): string {
  return url.split(encodeURIComponent(objectId)).join(`<object:${objectIdHash}>`).split(objectId).join(`<object:${objectIdHash}>`);
}

function caseResult(casePlan: ObjectPairCasePlan, results: Map<string, ObjectPairRequestEvidence>): ObjectPairCaseResult {
  const baselineA = requiredResult(results, `${casePlan.id}:A_TO_A`);
  const baselineB = requiredResult(results, `${casePlan.id}:B_TO_B`);
  const aToB = requiredResult(results, `${casePlan.id}:A_TO_B`);
  const bToA = requiredResult(results, `${casePlan.id}:B_TO_A`);
  const confirmedIssues = [aToB, bToA].filter((result) => result.finalClassification === "CONFIRMED_VULNERABILITY");

  return {
    caseId: casePlan.id,
    objectType: casePlan.objectType,
    expectedVisibility: casePlan.accountAObject.expectedVisibility,
    baselineA,
    baselineB,
    aToB,
    bToA,
    confirmedIssues,
    inconclusive: [baselineA, baselineB, aToB, bToA].some((result) => result.category === "INCONCLUSIVE" || result.category === "OWNERSHIP_NOT_CONFIRMED"),
    notes: [
      "This result applies only to the supplied object pair and endpoint template.",
      "No conclusion is made about unrelated objects, tenants, users, or endpoints."
    ]
  };
}

function classify(
  requestPlan: ObjectPairRequestPlan,
  response: HttpResponse,
  containsExpectedObjectId: boolean,
  containsExpectedOwnerEvidence: boolean,
  containsPrivateFieldEvidence: boolean,
  denialMarker: string | undefined
): ObjectPairResultCategory {
  if (response.error?.name === "RequestBudgetExceeded" || response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") {
    return "TEST_BLOCKED_BY_SAFETY_POLICY";
  }
  if (response.error) return "EXECUTION_ERROR";
  if (response.statusCode === 429) return "RATE_LIMITED";
  if (response.statusCode === 401) return "AUTHENTICATION_FAILED";
  if (response.statusCode === 403 || response.statusCode === 404 || denialMarker) return response.statusCode === 404 ? "OBJECT_NOT_FOUND" : "CROSS_ACCOUNT_ACCESS_DENIED";
  if (!isSuccessful(response)) return "INCONCLUSIVE";

  if (requestPlan.method === "HEAD" && requestPlan.purpose === "cross-account" && !containsExpectedObjectId) {
    return "RESPONSE_MISMATCH";
  }

  if (requestPlan.purpose === "owner-baseline") {
    return containsExpectedObjectId && containsExpectedOwnerEvidence ? "AUTHORIZED_BASELINE_CONFIRMED" : "OWNERSHIP_NOT_CONFIRMED";
  }

  if (requestPlan.expectedVisibility === "PUBLIC" || requestPlan.expectedVisibility === "SHARED_WITH_SPECIFIC_PRINCIPALS") {
    return "PUBLIC_OBJECT_ACCESS";
  }

  if (containsExpectedObjectId && containsExpectedOwnerEvidence && containsPrivateFieldEvidence) {
    return "CROSS_ACCOUNT_ACCESS_CONFIRMED";
  }

  if (containsExpectedObjectId && !containsPrivateFieldEvidence) {
    return "PUBLIC_OBJECT_ACCESS";
  }

  return "RESPONSE_MISMATCH";
}

function hasObjectIdentityEvidence(
  assertion: ObjectPairCasePlan["accountAObject"],
  response: HttpResponse,
  body: string,
  parsedBody: Record<string, unknown> | undefined
): boolean {
  if (assertion.expectedObjectIdHeader && headerValue(response, assertion.expectedObjectIdHeader) === assertion.objectId) {
    return true;
  }
  if (assertion.expectedObjectIdField) {
    return jsonPathValue(parsedBody, assertion.expectedObjectIdField) === assertion.objectId;
  }
  return response.method !== "HEAD" && body.includes(assertion.objectId);
}

function hasOwnershipEvidence(
  assertion: ObjectPairCasePlan["accountAObject"],
  response: HttpResponse,
  body: string,
  parsedBody: Record<string, unknown> | undefined
): boolean {
  if (assertion.expectedOwnerHeader && assertion.expectedOwnerValue && headerValue(response, assertion.expectedOwnerHeader) === assertion.expectedOwnerValue) {
    return true;
  }
  if (assertion.expectedOwnerField && assertion.expectedOwnerValue && jsonPathValue(parsedBody, assertion.expectedOwnerField) === assertion.expectedOwnerValue) {
    return true;
  }
  if (assertion.expectedTenantField && assertion.expectedTenantValue && jsonPathValue(parsedBody, assertion.expectedTenantField) === assertion.expectedTenantValue) {
    return true;
  }
  if (assertion.expectedSafeMarkers.some((marker) => body.includes(marker))) {
    return true;
  }
  return false;
}

function hasPrivateContentEvidence(
  assertion: ObjectPairCasePlan["accountAObject"],
  response: HttpResponse,
  body: string,
  parsedBody: Record<string, unknown> | undefined
): boolean {
  if (assertion.expectedPrivateHeaders.some((headerName) => typeof headerValue(response, headerName) === "string")) {
    return true;
  }
  return assertion.expectedPrivateFields.some((field) => jsonPathValue(parsedBody, field) !== undefined || body.includes(field));
}

function parseJsonObject(body: string): Record<string, unknown> | undefined {
  if (!body.trim().startsWith("{")) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(body) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function jsonPathValue(source: Record<string, unknown> | undefined, path: string): string | undefined {
  let value: unknown = source;
  for (const part of path.split(".")) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return undefined;
    }
    value = (value as Record<string, unknown>)[part];
  }
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : undefined;
}

function headerValue(response: HttpResponse, name: string): string | undefined {
  const found = Object.entries(headersForAnalysis(response)).find(([headerName]) => headerName.toLowerCase() === name.toLowerCase());
  if (!found) {
    return undefined;
  }
  return typeof found[1] === "string" ? found[1] : found[1].join(", ");
}

function semanticsFor(
  category: ObjectPairResultCategory,
  requestPlan: ObjectPairRequestPlan
): {
  technicalAccessResult: ObjectPairTechnicalAccessResult;
  businessPolicyReviewStatus: ObjectPairBusinessPolicyReviewStatus;
  finalClassification: ObjectPairFinalClassification;
} {
  if (category === "AUTHORIZED_BASELINE_CONFIRMED") {
    return { technicalAccessResult: "OWNER_BASELINE_CONFIRMED", businessPolicyReviewStatus: "NOT_APPLICABLE", finalClassification: "INCONCLUSIVE" };
  }
  if (category === "CROSS_ACCOUNT_ACCESS_CONFIRMED" && requestPlan.expectedVisibility === "PRIVATE_TO_OWNER") {
    return {
      technicalAccessResult: "FOREIGN_PRIVATE_ACCESS_CONFIRMED",
      businessPolicyReviewStatus: "DECLARED_PRIVATE_CONFIRMED",
      finalClassification: "CONFIRMED_VULNERABILITY"
    };
  }
  if (category === "CROSS_ACCOUNT_ACCESS_CONFIRMED") {
    return {
      technicalAccessResult: "FOREIGN_PRIVATE_ACCESS_CONFIRMED",
      businessPolicyReviewStatus: "POLICY_REVIEW_REQUIRED",
      finalClassification: "TECHNICAL_ACCESS_REQUIRES_POLICY_REVIEW"
    };
  }
  if (category === "PUBLIC_OBJECT_ACCESS") {
    return { technicalAccessResult: "PUBLIC_OR_SHARED_ACCESS", businessPolicyReviewStatus: "INTENDED_PUBLIC_OR_SHARED", finalClassification: "EXPECTED_ACCESS" };
  }
  if (category === "CROSS_ACCOUNT_ACCESS_DENIED" || category === "OBJECT_NOT_FOUND") {
    return { technicalAccessResult: category === "OBJECT_NOT_FOUND" ? "OBJECT_NOT_FOUND" : "ACCESS_DENIED", businessPolicyReviewStatus: "NOT_APPLICABLE", finalClassification: "PROTECTED" };
  }
  if (category === "AUTHENTICATION_FAILED") {
    return { technicalAccessResult: "AUTHENTICATION_FAILED", businessPolicyReviewStatus: "NOT_APPLICABLE", finalClassification: "ERROR" };
  }
  if (category === "TEST_BLOCKED_BY_SAFETY_POLICY") {
    return { technicalAccessResult: "BLOCKED_BY_SAFETY_POLICY", businessPolicyReviewStatus: "NOT_APPLICABLE", finalClassification: "BLOCKED" };
  }
  if (category === "EXECUTION_ERROR") {
    return { technicalAccessResult: "EXECUTION_ERROR", businessPolicyReviewStatus: "NOT_APPLICABLE", finalClassification: "ERROR" };
  }
  return { technicalAccessResult: "NOT_CONFIRMED", businessPolicyReviewStatus: "NOT_APPLICABLE", finalClassification: "INCONCLUSIVE" };
}

function denialMarkerFor(response: HttpResponse, body: string): string | undefined {
  if (response.redirectLocation && /login|signin|auth/i.test(response.redirectLocation)) return "login-redirect";
  if (/login required|sign in|required to log in|not authorized|forbidden|access denied/i.test(body)) return "denial-body-marker";
  return undefined;
}

function requiredRequestPlan(casePlan: ObjectPairCasePlan, direction: ObjectPairRequestPlan["direction"]): ObjectPairRequestPlan {
  const requestPlan = casePlan.requestMatrix.find((candidate) => candidate.direction === direction);
  if (!requestPlan) {
    throw new Error(`Missing object-pair matrix request ${casePlan.id}:${direction}`);
  }
  return requestPlan;
}

function requiredResult(results: Map<string, ObjectPairRequestEvidence>, id: string): ObjectPairRequestEvidence {
  const result = results.get(id);
  if (!result) {
    throw new Error(`Missing object-pair matrix result ${id}`);
  }
  return result;
}

function confidenceFor(category: ObjectPairResultCategory): ObjectPairRequestEvidence["confidence"] {
  if (category === "CROSS_ACCOUNT_ACCESS_CONFIRMED" || category === "AUTHORIZED_BASELINE_CONFIRMED") return "CONFIRMED";
  if (category === "CROSS_ACCOUNT_ACCESS_DENIED" || category === "OBJECT_NOT_FOUND" || category === "PUBLIC_OBJECT_ACCESS") return "HIGH";
  if (category === "RESPONSE_MISMATCH") return "MEDIUM";
  return "INCONCLUSIVE";
}

function notesFor(category: ObjectPairResultCategory, requestPlan: ObjectPairRequestPlan): string[] {
  return [
    `${requestPlan.direction} used only the supplied object identifier hash ${requestPlan.targetObjectIdHash}.`,
    category === "CROSS_ACCOUNT_ACCESS_CONFIRMED"
      ? "Controlled evidence indicates the requesting account received the foreign object's private representation."
      : "Result requires review in the application's intended authorization model."
  ];
}

function findingsFromObjectPairReport(report: ObjectPairTestingReport, context: ScanContext): Finding[] {
  const riskScorer = new RiskScorer();
  return report.cases.flatMap((testCase) =>
    testCase.confirmedIssues.map((issue) => ({
      id: `object-pair-${issue.matrixId.replace(/[^a-z0-9_-]/gi, "-").toLowerCase()}`,
      title: `Controlled object-level authorization issue: ${testCase.objectType} ${issue.direction}`,
      type: "Object Authorization Issue" as const,
      severity: "High" as const,
      confidence: "High" as const,
      url: issue.url,
      method: issue.method,
      ...(issue.response.statusCode ? { statusCode: issue.response.statusCode } : {}),
      evidence: {
        url: issue.url,
        method: issue.method,
        ...(issue.response.statusCode ? { statusCode: issue.response.statusCode } : {}),
        ...(issue.response.bodyHash ? { bodyHash: issue.response.bodyHash } : {}),
        ...(issue.response.contentType ? { contentType: issue.response.contentType } : {}),
        ...(typeof issue.response.contentLength === "number" ? { contentLength: issue.response.contentLength } : {}),
        curlCommand: redactedCurlCommand(issue.url, issue.requestingPrincipal === "account_a" ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB),
        source: `Object pair ${testCase.caseId} ${issue.direction}; objectIdHash=${issue.objectIdHash}; auth material redacted.`,
        severityReason: "A supplied foreign-owned object returned private-field evidence to the other authenticated account after owner baseline confirmation.",
        reproductionNotes: [
          "Use only the supplied controlled object pair.",
          "Confirm Account A and Account B ownership in the application.",
          "Repeat the redacted request with the requesting principal's own authorization context."
        ]
      },
      impact: "A user may be able to access another user's private object representation for the tested endpoint.",
      recommendation:
        "Derive the authenticated principal from trusted session state, load the target object, and verify owner, tenant, sharing, or role permission before returning private fields.",
      manualTestingSuggestions: [
        "Verify the object is not intentionally public or shared.",
        "Check the opposite direction independently.",
        "Add negative cross-account authorization tests for this endpoint."
      ],
      tags: ["idor", "bola", "object-authorization", "needs-manual-verification"],
      riskScore: riskScorer.score({ severity: "High", confidence: "High", falsePositiveStatus: "likely-valid", tags: ["idor", "bola", "object-authorization"] }),
      sourceModule: "object-pair-testing",
      falsePositiveStatus: "likely-valid" as const,
      timestamp: new Date().toISOString()
    }))
  );
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 400;
}
