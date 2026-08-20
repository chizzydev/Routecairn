import { createHash, randomBytes } from "node:crypto";
import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { FieldExposureCasePlan, FieldExposureExpectationPlan, FieldExposureRequestPlan } from "../../core/planning/ScanPlan.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type {
  FieldExposureActorResult,
  FieldExposureClassification,
  FieldExposureConfidence,
  FieldExposureObservation,
  FieldExposurePresenceState,
  FieldExposureTestingReport
} from "../../reports/ReportTypes.js";
import { parseSafeFieldPath, valueAtSafePath } from "./SafeFieldPath.js";

export class FieldExposureTestingModule implements RouteCairnPlugin {
  public readonly name = "field-exposure-testing";
  public readonly description = "Runs fixed field-level exposure checks across explicitly supplied principals and object identifiers.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeFieldExposureTesting(context);
    return {
      pluginName: this.name,
      fieldExposureTesting: report,
      findings: findingsFromReport(report, context),
      notes: report.notes
    };
  }
}

async function executeFieldExposureTesting(context: ScanContext): Promise<FieldExposureTestingReport> {
  const plan = context.options.plan.fieldExposureTesting;
  if (!plan) {
    return {
      enabled: false,
      plannedCases: 0,
      plannedRequests: 0,
      executedRequests: 0,
      confirmedIssues: 0,
      cases: [],
      notes: ["Field exposure testing skipped because no resolved field-exposure plan was supplied."]
    };
  }

  const salt = randomBytes(16);
  const cases = [];
  let executedRequests = 0;
  for (const casePlan of plan.cases) {
    const identityBlockReason = identityBlockReasonForCase(context, casePlan);
    if (identityBlockReason) {
      cases.push(blockedCase(casePlan, identityBlockReason));
      continue;
    }

    const results = new Map<string, FieldExposureActorResult>();
    for (const requestPlan of casePlan.requestMatrix) {
      const result = await sendAndProject(context, casePlan, requestPlan, salt);
      executedRequests += 1;
      results.set(requestPlan.actorId, result);
    }
    cases.push(caseResult(casePlan, results));
  }

  const confirmedIssues = cases.reduce((total, testCase) => total + testCase.confirmedIssues.length, 0);
  return {
    enabled: true,
    plannedCases: plan.cases.length,
    plannedRequests: plan.requestMatrix.length,
    executedRequests,
    confirmedIssues,
    cases,
    notes: [
      "Field exposure testing executed only the request matrix resolved before scan execution.",
      "Only explicitly configured field paths were projected from JSON responses.",
      "Raw field values, credentials, principal IDs, tenant IDs, and full response bodies are not retained."
    ]
  };
}

async function sendAndProject(context: ScanContext, casePlan: FieldExposureCasePlan, requestPlan: FieldExposureRequestPlan, salt: Buffer): Promise<FieldExposureActorResult> {
  const headers = { ...casePlan.template.headers, ...headersForRequest(context, requestPlan) };
  const response = await context.createHttpClient().send({ url: requestPlan.url, method: requestPlan.method, headers });
  return actorResultForResponse(context, casePlan, requestPlan, response, salt);
}

function headersForRequest(context: ScanContext, requestPlan: FieldExposureRequestPlan): Record<string, string> {
  if (!requestPlan.authSlot) return {};
  const profileSet = context.options.authProfileSet;
  if (!profileSet) return {};
  return authHeadersForProfile(requestPlan.authSlot === "account_a" ? profileSet.accountA : profileSet.accountB);
}

function actorResultForResponse(context: ScanContext, casePlan: FieldExposureCasePlan, requestPlan: FieldExposureRequestPlan, response: HttpResponse, salt: Buffer): FieldExposureActorResult {
  const safeUrl = redactObjectId(response.finalUrl || requestPlan.url, casePlan.objectId, casePlan.objectIdHash);
  const base = {
    actorId: requestPlan.actorId,
    actorType: requestPlan.actorType,
    requestId: requestPlan.id,
    method: requestPlan.method,
    url: safeUrl,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response.bodyHash ? { bodyHash: response.bodyHash } : {})
  };

  const safetyCategory = safetyCategoryFor(response);
  if (safetyCategory) {
    return { ...base, objectConfirmed: false, objectIdentity: "RESPONSE_NOT_COMPARABLE", category: safetyCategory, observations: notEvaluated(casePlan, requestPlan, safetyCategory), ...(response.error ? { error: response.error.message } : {}), notes: ["Request did not produce a comparable object response."] };
  }
  if (!isSuccessful(response)) {
    const category = response.statusCode === 401 || response.statusCode === 403 || response.statusCode === 404 ? "OBJECT_ACCESS_DENIED" : "INCONCLUSIVE";
    return { ...base, objectConfirmed: false, objectIdentity: "RESPONSE_NOT_COMPARABLE", category, observations: notEvaluated(casePlan, requestPlan, category), notes: ["Response status did not allow field-level comparison."] };
  }
  if (requestPlan.method === "HEAD") {
    return { ...base, objectConfirmed: false, objectIdentity: "RESPONSE_NOT_COMPARABLE", category: "RESPONSE_NOT_COMPARABLE", observations: notEvaluated(casePlan, requestPlan, "RESPONSE_NOT_COMPARABLE"), notes: ["HEAD responses do not contain JSON bodies for field projection."] };
  }
  if ((response.contentLength ?? 0) > context.options.plan.fieldExposureTesting!.maxResponseBytes) {
    return { ...base, objectConfirmed: false, objectIdentity: "RESPONSE_NOT_COMPARABLE", category: "RESPONSE_TOO_LARGE", observations: notEvaluated(casePlan, requestPlan, "RESPONSE_TOO_LARGE"), notes: ["Response exceeded the configured field-exposure size limit."] };
  }

  const parsed = parseJsonObject(bodyPreviewForAnalysis(response) ?? "");
  if (!parsed) {
    return { ...base, objectConfirmed: false, objectIdentity: "RESPONSE_NOT_COMPARABLE", category: "RESPONSE_NOT_COMPARABLE", observations: notEvaluated(casePlan, requestPlan, "RESPONSE_NOT_COMPARABLE"), notes: ["Response was not a supported JSON object."] };
  }

  const objectIdentity = objectIdentityFor(casePlan, parsed);
  if (objectIdentity !== "OBJECT_CONFIRMED") {
    return { ...base, objectConfirmed: false, objectIdentity, category: objectIdentity, observations: notEvaluated(casePlan, requestPlan, objectIdentity), notes: ["Configured object identity evidence did not match the response."] };
  }

  const observations = casePlan.fieldExpectations.map((expectation) => observeField(context, casePlan, requestPlan, expectation, parsed, salt));
  const issueCount = observations.filter((observation) => isConfirmedIssue(observation.classification)).length;
  return {
    ...base,
    objectConfirmed: true,
    objectIdentity: "OBJECT_CONFIRMED",
    category: issueCount > 0 ? "UNAUTHORIZED_FIELD_PRESENT" : "FIELD_POLICY_SATISFIED",
    observations,
    notes: ["Object identity was confirmed before field expectations were evaluated."]
  };
}

function observeField(
  context: ScanContext,
  casePlan: FieldExposureCasePlan,
  requestPlan: FieldExposureRequestPlan,
  expectation: FieldExposureExpectationPlan,
  parsed: Record<string, unknown>,
  salt: Buffer
): FieldExposureObservation {
  const extracted = valueAtSafePath(parsed, parseSafeFieldPath(expectation.path, { maxDepth: 8, maxArrayIndex: 50, code: "FIELD_EXPOSURE_FIELD_PATH_INVALID" }));
  const safeType = safeTypeOf(extracted.value);
  const length = valueLength(extracted.value);
  const redactionMatched = expectation.redactionPattern && typeof extracted.value === "string" ? new RegExp(expectation.redactionPattern).test(extracted.value) : undefined;
  const classification = classifyObservation(casePlan, requestPlan.actorId, expectation, extracted.state as FieldExposurePresenceState, redactionMatched);
  return {
    fieldId: expectation.id,
    fieldLabel: safeLabel(expectation.label),
    fieldPathRef: safeFieldPathRef(expectation),
    actorId: requestPlan.actorId,
    actorType: requestPlan.actorType,
    presence: extracted.state as FieldExposurePresenceState,
    safeType,
    ...(typeof length === "number" ? { length } : {}),
    ...(shouldFingerprint(expectation, extracted.value) ? { valueFingerprint: fingerprintValue(extracted.value, salt) } : {}),
    ...(previewAllowed(context, expectation, extracted.value) ? { preview: safePreview(String(extracted.value), context.options.plan.fieldExposureTesting!.maxPreviewLength) } : {}),
    ...(typeof redactionMatched === "boolean" ? { redactionMatched } : {}),
    classification,
    confidence: confidenceFor(classification, casePlan.requireVerifiedIdentity),
    expectedPolicy: expectation.expectation
  };
}

function classifyObservation(
  casePlan: FieldExposureCasePlan,
  actorId: string,
  expectation: FieldExposureExpectationPlan,
  presence: FieldExposurePresenceState,
  redactionMatched: boolean | undefined
): FieldExposureClassification {
  if (expectation.allowedActors.includes(actorId)) {
    if (presence === "TYPE_MISMATCH") return "FIELD_TYPE_MISMATCH";
    if (expectation.expectation === "MUST_BE_PRESENT" && isAbsentLike(presence)) return "FIELD_UNEXPECTEDLY_ABSENT";
    return "FIELD_POLICY_SATISFIED";
  }
  const prohibited = expectation.prohibitedActors.includes(actorId) || (expectation.expectation === "OWNER_ONLY_VALUE" && actorId !== casePlan.ownerActorId);
  if (!prohibited) {
    if (presence === "TYPE_MISMATCH") return "FIELD_TYPE_MISMATCH";
    if (expectation.expectation === "MUST_BE_PRESENT" && isAbsentLike(presence)) return "FIELD_UNEXPECTEDLY_ABSENT";
    return "FIELD_POLICY_SATISFIED";
  }

  if (presence === "TYPE_MISMATCH") return "FIELD_TYPE_MISMATCH";
  if (expectation.expectation === "MUST_BE_ABSENT") return isAbsentLike(presence) ? "FIELD_POLICY_SATISFIED" : "UNAUTHORIZED_FIELD_PRESENT";
  if (expectation.expectation === "MUST_BE_NULL") return presence === "PRESENT_NULL" ? "FIELD_POLICY_SATISFIED" : "UNAUTHORIZED_FIELD_PRESENT";
  if (expectation.expectation === "MUST_BE_REDACTED") return redactionMatched ? "FIELD_POLICY_SATISFIED" : "EXPECTED_REDACTION_MISSING";
  if (expectation.expectation === "MASKED_VALUE") return redactionMatched ? "FIELD_POLICY_SATISFIED" : "MASKING_POLICY_VIOLATION";
  if (expectation.expectation === "OWNER_ONLY_VALUE") return isAbsentLike(presence) || presence === "PRESENT_REDACTED" || presence === "PRESENT_NULL" ? "FIELD_POLICY_SATISFIED" : "UNAUTHORIZED_PRIVATE_VALUE_EXPOSED";
  return "FIELD_POLICY_SATISFIED";
}

function caseResult(casePlan: FieldExposureCasePlan, results: Map<string, FieldExposureActorResult>) {
  const projectedActors = casePlan.requestMatrix.map((request) => {
    const result = results.get(request.actorId);
    if (!result) throw new Error(`Missing field-exposure request result ${request.id}`);
    return result;
  });
  const actors = refineBaselineComparisons(casePlan, projectedActors);
  const confirmedIssues = actors.flatMap((actor) => actor.observations).filter((observation) => isConfirmedIssue(observation.classification));
  return {
    caseId: casePlan.id,
    objectType: casePlan.objectType,
    objectIdHash: casePlan.objectIdHash,
    expectedVisibility: casePlan.expectedVisibility,
    plannedRequests: casePlan.requestMatrix.length,
    executedRequests: actors.length,
    actors,
    confirmedIssues,
    inconclusive: actors.some((actor) => actor.category !== "FIELD_POLICY_SATISFIED" && actor.category !== "UNAUTHORIZED_FIELD_PRESENT"),
    notes: ["This result applies only to the supplied object, actors, endpoint template, and configured field paths."]
  };
}

function refineBaselineComparisons(casePlan: FieldExposureCasePlan, actors: FieldExposureActorResult[]): FieldExposureActorResult[] {
  const owner = actors.find((actor) => actor.actorId === casePlan.ownerActorId);
  const publicActor = actors.find((actor) => actor.actorType === "PUBLIC");
  const sharedActor = actors.find((actor) => actor.actorType === "SHARED_PRINCIPAL");

  return actors.map((actor) => ({
    ...actor,
    observations: actor.observations.map((observation) => {
      const expectation = casePlan.fieldExpectations.find((candidate) => candidate.id === observation.fieldId);
      if (!expectation || observation.presence === "NOT_EVALUATED") return observation;
      if (expectation.expectation === "MUST_DIFFER_FROM_OWNER" && actor.actorId !== casePlan.ownerActorId) {
        const ownerObservation = owner?.observations.find((candidate) => candidate.fieldId === observation.fieldId);
        if (ownerObservation?.valueFingerprint && ownerObservation.valueFingerprint === observation.valueFingerprint) {
          return { ...observation, classification: "UNAUTHORIZED_PRIVATE_VALUE_EXPOSED" as const, confidence: confidenceFor("UNAUTHORIZED_PRIVATE_VALUE_EXPOSED", casePlan.requireVerifiedIdentity) };
        }
      }
      if (expectation.expectation === "MUST_MATCH_PUBLIC_BASELINE" && actor.actorType !== "PUBLIC") {
        const publicObservation = publicActor?.observations.find((candidate) => candidate.fieldId === observation.fieldId);
        if (!publicObservation || !publicActor?.objectConfirmed) {
          return { ...observation, classification: "PUBLIC_BASELINE_UNAVAILABLE" as const, confidence: "INCONCLUSIVE" as const };
        }
        if (!sameProjection(observation, publicObservation)) {
          return { ...observation, classification: "PUBLIC_BASELINE_MISMATCH" as const, confidence: "HIGH" as const };
        }
      }
      if (expectation.expectation === "MUST_MATCH_SHARED_BASELINE" && actor.actorType !== "SHARED_PRINCIPAL") {
        const sharedObservation = sharedActor?.observations.find((candidate) => candidate.fieldId === observation.fieldId);
        if (sharedObservation && !sameProjection(observation, sharedObservation)) {
          return { ...observation, classification: "SHARED_BASELINE_MISMATCH" as const, confidence: "HIGH" as const };
        }
      }
      return observation;
    })
  }));
}

function sameProjection(left: FieldExposureObservation, right: FieldExposureObservation): boolean {
  return left.presence === right.presence && left.safeType === right.safeType && left.length === right.length && left.valueFingerprint === right.valueFingerprint;
}

function blockedCase(casePlan: FieldExposureCasePlan, reason: string) {
  return {
    caseId: casePlan.id,
    objectType: casePlan.objectType,
    objectIdHash: casePlan.objectIdHash,
    expectedVisibility: casePlan.expectedVisibility,
    plannedRequests: casePlan.requestMatrix.length,
    executedRequests: 0,
    actors: [],
    confirmedIssues: [],
    inconclusive: true,
    notes: [`Field exposure case blocked before execution: ${reason}`, "Verified-principal requirements were not downgraded."]
  };
}

function identityBlockReasonForCase(context: ScanContext, casePlan: FieldExposureCasePlan): string | undefined {
  if (!casePlan.requireVerifiedIdentity) return undefined;
  const report = context.state.getIdentityVerification();
  const requiredSlots = new Set(casePlan.actors.map((actor) => actor.authSlot).filter(Boolean));
  for (const slot of requiredSlots) {
    const result = slot === "account_a" ? report?.accountA : report?.accountB;
    if (!result?.verified) return `${slot} required verified identity but result was ${result?.category ?? "missing"}.`;
  }
  if (report?.accountA?.verified && report.accountB?.verified && report.accountA.principalHash === report.accountB.principalHash) {
    return "Account A and Account B resolved to the same verified principal.";
  }
  return undefined;
}

function objectIdentityFor(casePlan: FieldExposureCasePlan, parsed: Record<string, unknown>): "OBJECT_CONFIRMED" | "OBJECT_IDENTITY_UNCONFIRMED" | "OBJECT_MISMATCH" {
  const field = valueAtSafePath(parsed, parseSafeFieldPath(casePlan.objectConfirmation.expectedObjectIdField, { maxDepth: 8, maxArrayIndex: 50, code: "FIELD_EXPOSURE_OBJECT_SELECTOR_INVALID" }));
  if (field.state === "ABSENT" || field.state === "PATH_PARENT_MISSING" || field.value === undefined || field.value === null) {
    return "OBJECT_IDENTITY_UNCONFIRMED";
  }
  return String(field.value) === casePlan.objectId ? "OBJECT_CONFIRMED" : "OBJECT_MISMATCH";
}

function notEvaluated(casePlan: FieldExposureCasePlan, requestPlan: FieldExposureRequestPlan, category: FieldExposureClassification): FieldExposureObservation[] {
  return casePlan.fieldExpectations.map((expectation) => ({
    fieldId: expectation.id,
    fieldLabel: safeLabel(expectation.label),
    fieldPathRef: safeFieldPathRef(expectation),
    actorId: requestPlan.actorId,
    actorType: requestPlan.actorType,
    presence: "NOT_EVALUATED",
    safeType: "unknown",
    classification: category,
    confidence: "INCONCLUSIVE",
    expectedPolicy: expectation.expectation
  }));
}

function findingsFromReport(report: FieldExposureTestingReport, context: ScanContext): Finding[] {
  const riskScorer = new RiskScorer();
  return report.cases.flatMap((testCase) =>
    testCase.actors.flatMap((actor) =>
      actor.observations
        .filter((observation) => isConfirmedIssue(observation.classification))
        .map((observation) => ({
          id: `field-exposure-${testCase.caseId}-${actor.actorId}-${observation.fieldId}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(),
          title: `Controlled field exposure: ${testCase.objectType} ${observation.fieldLabel}`,
          type: "Field Exposure Issue" as const,
          severity: "High" as const,
          confidence: observation.confidence === "CONFIRMED" ? ("High" as const) : ("Medium" as const),
          url: actor.url,
          method: actor.method,
          ...(actor.statusCode ? { statusCode: actor.statusCode } : {}),
          evidence: {
            url: actor.url,
            method: actor.method,
            ...(actor.statusCode ? { statusCode: actor.statusCode } : {}),
            ...(actor.bodyHash ? { bodyHash: actor.bodyHash } : {}),
            ...(actor.contentType ? { contentType: actor.contentType } : {}),
            ...(typeof actor.contentLength === "number" ? { contentLength: actor.contentLength } : {}),
            curlCommand: redactedCurlCommand(actor.url, actor.actorId === "public" ? undefined : actor.actorId.includes("a") ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB),
            source: `Field exposure ${testCase.caseId}; field=${observation.fieldPathRef}; actor=${actor.actorId}; objectHash=${testCase.objectIdHash}; auth material redacted.`,
            severityReason: "A configured prohibited field policy was violated after the supplied object identity was confirmed.",
            reproductionNotes: [
              "Use only the supplied controlled object and endpoint template.",
              "Repeat with the same declared actor authorization context.",
              "Manually verify the configured field policy against the product's intended authorization model."
            ]
          },
          impact: "A principal may receive field-level data that the supplied authorization policy says should be absent, redacted, masked, or owner-only.",
          recommendation: "Apply field-level authorization and response shaping after object access is authorized, using owner, tenant, role, and sharing policy before serializing sensitive fields.",
          manualTestingSuggestions: ["Confirm the field policy with the application owner.", "Check whether the object is intentionally shared.", "Add regression tests for the exact actor and object policy."],
          tags: ["field-exposure", "authorization", "needs-manual-verification"],
          riskScore: riskScorer.score({ severity: "High", confidence: "High", falsePositiveStatus: "likely-valid", tags: ["field-exposure", "authorization"] }),
          sourceModule: "field-exposure-testing",
          falsePositiveStatus: "likely-valid" as const,
          timestamp: new Date().toISOString()
        }))
    )
  );
}

function safetyCategoryFor(response: HttpResponse): FieldExposureClassification | undefined {
  if (response.error?.name === "RequestBudgetExceeded") return "BUDGET_EXHAUSTED";
  if (response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") return "TEST_BLOCKED_BY_SAFETY_POLICY";
  if (response.error) return "EXECUTION_ERROR";
  if (response.statusCode === 429) return "RATE_LIMITED";
  return undefined;
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 300;
}

function parseJsonObject(body: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(body) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function isAbsentLike(presence: FieldExposurePresenceState): boolean {
  return presence === "ABSENT" || presence === "PATH_PARENT_MISSING" || presence === "INDEX_OUT_OF_BOUNDS";
}

function isConfirmedIssue(category: FieldExposureClassification): boolean {
  return ["UNAUTHORIZED_FIELD_PRESENT", "UNAUTHORIZED_PRIVATE_VALUE_EXPOSED", "EXPECTED_REDACTION_MISSING", "MASKING_POLICY_VIOLATION"].includes(category);
}

function confidenceFor(category: FieldExposureClassification, verifiedRequired: boolean): FieldExposureConfidence {
  if (isConfirmedIssue(category)) return verifiedRequired ? "CONFIRMED" : "HIGH";
  if (category === "FIELD_POLICY_SATISFIED") return "HIGH";
  if (category === "FIELD_UNEXPECTEDLY_ABSENT") return "MEDIUM";
  return "INCONCLUSIVE";
}

function shouldFingerprint(expectation: FieldExposureExpectationPlan, value: unknown): boolean {
  return value !== undefined && value !== null && ["MUST_DIFFER_FROM_OWNER", "MUST_MATCH_PUBLIC_BASELINE", "MUST_MATCH_SHARED_BASELINE", "OWNER_ONLY_VALUE"].includes(expectation.expectation);
}

function fingerprintValue(value: unknown, salt: Buffer): string {
  return createHash("sha256").update("routecairn-field-value-v1").update("\0").update(salt).update("\0").update(JSON.stringify(value)).digest("hex").slice(0, 16);
}

function previewAllowed(context: ScanContext, expectation: FieldExposureExpectationPlan, value: unknown): boolean {
  return Boolean(context.options.plan.evidence.collectBodyPreview && expectation.allowPreview && expectation.sensitivity === "PUBLIC" && typeof value === "string");
}

function safePreview(value: string, limit: number): string {
  return value.slice(0, limit).replace(/(?:token|secret|password|api[_-]?key|session|cookie)=?[A-Za-z0-9._~+/=-]+/gi, "<redacted>");
}

function safeTypeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function valueLength(value: unknown): number | undefined {
  if (typeof value === "string" || Array.isArray(value)) return value.length;
  if (typeof value === "object" && value !== null) return Object.keys(value).length;
  return undefined;
}

function safeLabel(value: string): string {
  return value.replace(/(?:token|secret|password|api[_-]?key|session|cookie)[^.\s]*/gi, "<sensitive-label>").slice(0, 120);
}

function safeFieldPathRef(expectation: FieldExposureExpectationPlan): string {
  if (/token|secret|password|api[_-]?key|session|cookie/i.test(expectation.path)) {
    return `<field:${createHash("sha256").update(expectation.path).digest("hex").slice(0, 12)}>`;
  }
  return expectation.path;
}

function redactObjectId(url: string, objectId: string, objectIdHash: string): string {
  return url.split(encodeURIComponent(objectId)).join(`<object:${objectIdHash}>`).split(objectId).join(`<object:${objectIdHash}>`);
}
