import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { BulkAuthorizationCasePlan, BulkObjectPlan, BulkPostconditionCheckPlan, BulkSingleObjectBaselinePlan } from "../../core/planning/ScanPlan.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { BulkAuthorizationDecisionCategory, BulkAuthorizationFindingCategory, BulkAuthorizationObservation, BulkAuthorizationReport, BulkBaselineDecision, BulkObjectObservation, BulkPostconditionStatus } from "../../reports/ReportTypes.js";
import { parseSafeFieldPath, valueAtSafePath } from "../fieldExposureTesting/SafeFieldPath.js";

export class BulkAuthorizationModule implements RouteCairnPlugin {
  public readonly name = "bulk-authorization-testing";
  public readonly description = "Runs fixed non-mutating bulk authorization checks.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeBulkAuthorization(context);
    return { pluginName: this.name, bulkAuthorization: report, findings: findingsFromReport(report, context), notes: report.notes };
  }
}

async function executeBulkAuthorization(context: ScanContext): Promise<BulkAuthorizationReport> {
  const plan = context.options.plan.bulkAuthorizationTesting;
  if (!plan) {
    return { enabled: false, plannedDefinitions: 0, plannedCases: 0, plannedRequests: 0, executedRequests: 0, confirmedIssues: 0, observations: [], notes: ["Bulk authorization skipped because no resolved bulk plan was supplied."] };
  }
  const observations: BulkAuthorizationObservation[] = [];
  let executedRequests = 0;
  let stopPostCases = false;
  outer: for (const definition of plan.definitions) {
    for (const casePlan of definition.cases) {
      if (observations.length >= plan.maxRetainedObservations) break outer;
      const blockReason = identityBlockReason(context, casePlan);
      if (blockReason) {
        observations.push(baseObservation(casePlan, "IDENTITY_REQUIREMENT_UNSATISFIED", undefined, [`Bulk case blocked before execution: ${blockReason}`]));
        continue;
      }
      if (stopPostCases && casePlan.method === "POST") {
        observations.push(baseObservation(casePlan, "NON_MUTATING_CONTRACT_VIOLATED", undefined, ["Bulk POST case skipped because a prior configured postcondition check detected state change."]));
        continue;
      }
      const baselines = await runBaselines(context, casePlan);
      executedRequests += baselines.executedRequests;
      if (casePlan.postSafetyMode === "POSTCONDITION_VERIFIED_DRY_RUN") {
        const preconditions = await runPostconditionChecks(context, casePlan, "pre");
        executedRequests += preconditions.executedRequests;
        if (preconditions.status !== "VERIFIED_UNCHANGED") {
          observations.push(withBaselineSummary(baseObservation(casePlan, "NON_MUTATING_CONTRACT_UNCONFIRMED", undefined, [`Bulk POST case blocked before execution: ${preconditions.note}`]), baselines, preconditions.status));
          continue;
        }
        const response = await context.createHttpClient().send({ url: casePlan.url, method: casePlan.method, headers: { ...casePlan.headers, ...headersForCase(context, casePlan) }, ...(casePlan.body ? { body: casePlan.body } : {}) });
        executedRequests += 1;
        const postconditions = await runPostconditionChecks(context, casePlan, "post", preconditions.snapshots);
        executedRequests += postconditions.executedRequests;
        const observation = withBaselineSummary(classifyResponse(context, casePlan, response, baselines), baselines, postconditions.status);
        if (postconditions.status !== "VERIFIED_UNCHANGED") {
          stopPostCases = postconditions.status === "STATE_CHANGED" || postconditions.status === "OBJECT_DISAPPEARED" || postconditions.status === "OBJECT_IDENTITY_CHANGED";
          const { findingCategory: _findingCategory, ...withoutFinding } = observation;
          observations.push({
            ...withoutFinding,
            observedDecision: "NON_MUTATING_CONTRACT_VIOLATED",
            safetyContractSatisfied: false,
            confidence: "INCONCLUSIVE",
            notes: [...observation.notes, `Configured postcondition verification failed: ${postconditions.note}`]
          });
          continue;
        }
        observations.push(observation);
        continue;
      }
      const response = await context.createHttpClient().send({ url: casePlan.url, method: casePlan.method, headers: { ...casePlan.headers, ...headersForCase(context, casePlan) }, ...(casePlan.body ? { body: casePlan.body } : {}) });
      executedRequests += 1;
      observations.push(withBaselineSummary(classifyResponse(context, casePlan, response, baselines), baselines, casePlan.method === "POST" ? "OPERATOR_ATTESTED_NOT_INDEPENDENTLY_VERIFIED" : "NOT_APPLICABLE"));
    }
  }
  return {
    enabled: true,
    plannedDefinitions: plan.definitions.length,
    plannedCases: plan.requestMatrix.length,
    plannedRequests: plan.requestMatrix.length,
    executedRequests,
    confirmedIssues: observations.filter((observation) => observation.findingCategory).length,
    observations,
    notes: [
      "Bulk authorization executed only resolved non-mutating GET or controlled JSON POST cases.",
      "POST cases identify whether non-mutation was operator-attested or independently checked with configured pre/postcondition GETs.",
      "No object IDs, actors, endpoints, subsets, permutations, pagination, downloads, or job-status requests were generated at runtime.",
      "Unknown returned IDs were discarded and cannot create findings."
    ]
  };
}

interface BaselineSummary {
  executedRequests: number;
  decisions: ReadonlyMap<string, BulkBaselineDecision>;
}

interface PostconditionSnapshot {
  objectIdHash: string;
  values: ReadonlyMap<string, unknown>;
}

interface PostconditionResult {
  executedRequests: number;
  status: BulkPostconditionStatus;
  note: string;
  snapshots?: readonly PostconditionSnapshot[];
}

interface IdentityRequirement {
  authSlot?: "account_a" | "account_b";
  requireVerifiedIdentity: boolean;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  expectedAccountStateHash?: string;
}

async function runBaselines(context: ScanContext, casePlan: BulkAuthorizationCasePlan): Promise<BaselineSummary> {
  const decisions = new Map<string, BulkBaselineDecision>();
  let executedRequests = 0;
  for (const object of casePlan.objects) {
    if (!object.baseline) continue;
    const blockReason = identityBlockReason(context, identityRequirementFor(object.baseline));
    if (blockReason) {
      decisions.set(object.objectIdHash, "UNAVAILABLE");
      continue;
    }
    const response = await context.createHttpClient().send({ url: object.baseline.url, method: "GET", headers: { ...object.baseline.headers, ...headersForBaseline(context, object.baseline) } });
    executedRequests += 1;
    decisions.set(object.objectIdHash, classifyBaselineResponse(object, object.baseline, response));
  }
  return { executedRequests, decisions };
}

function classifyBaselineResponse(object: BulkObjectPlan, baseline: BulkSingleObjectBaselinePlan, response: HttpResponse): BulkBaselineDecision {
  const safety = safetyCategoryFor(response);
  if (safety || response.statusCode === 429) return "UNAVAILABLE";
  if (response.statusCode === 401) return "AUTHENTICATION_REQUIRED";
  if (response.statusCode === 403) return "DENIED_CONFIRMED";
  if (response.statusCode === 404) return "OBJECT_NOT_FOUND";
  if (!isSuccessful(response) || (response.contentLength ?? 0) > baseline.maxResponseBytes || !matchesContentType(response.contentType, "application/json")) return "INCONCLUSIVE";
  const parsed = parseJson(bodyPreviewForAnalysis(response) ?? "", baseline.maxJsonDepth);
  if (!parsed || !isRecord(parsed)) return "INCONCLUSIVE";
  const objectId = scalarAt(parsed, baseline.objectIdentityField);
  if (objectId !== object.objectId) return "OBJECT_IDENTITY_MISMATCH";
  if (baseline.expectedObjectState && baseline.objectStateField) {
    const state = scalarAt(parsed, baseline.objectStateField);
    if (state !== baseline.expectedObjectState) return "OBJECT_STATE_MISMATCH";
  }
  return "ALLOWED_CONFIRMED";
}

async function runPostconditionChecks(context: ScanContext, casePlan: BulkAuthorizationCasePlan, phase: "pre" | "post", previous: readonly PostconditionSnapshot[] = []): Promise<PostconditionResult> {
  const snapshots: PostconditionSnapshot[] = [];
  let executedRequests = 0;
  const previousByObject = new Map(previous.map((snapshot) => [snapshot.objectIdHash, snapshot]));
  for (const check of casePlan.postconditionChecks) {
    const blockReason = identityBlockReason(context, identityRequirementFor(check));
    if (blockReason) return { executedRequests, status: "VERIFICATION_BLOCKED", note: blockReason };
    const response = await context.createHttpClient().send({ url: check.url, method: "GET", headers: { ...check.headers, ...headersForPostcondition(context, check) }, skipCache: true });
    executedRequests += 1;
    const parsed = parsePostconditionResponse(check, response);
    if (parsed.status !== "VERIFIED_UNCHANGED") return { executedRequests, status: parsed.status, note: parsed.note };
    if (phase === "post") {
      const before = previousByObject.get(check.objectIdHash);
      if (!before) return { executedRequests, status: "STATE_RESPONSE_AMBIGUOUS", note: `Precondition snapshot for ${check.id} was unavailable.` };
      for (const [path, value] of parsed.snapshot.values) {
        if (!Object.is(value, before.values.get(path))) return { executedRequests, status: "STATE_CHANGED", note: `Configured postcondition field "${path}" changed for ${check.id}.` };
      }
    }
    snapshots.push(parsed.snapshot);
  }
  return { executedRequests, status: "VERIFIED_UNCHANGED", note: "Configured postcondition fields were unchanged.", snapshots };
}

function parsePostconditionResponse(check: BulkPostconditionCheckPlan, response: HttpResponse): { status: BulkPostconditionStatus; note: string; snapshot: PostconditionSnapshot } {
  const empty = { objectIdHash: check.objectIdHash, values: new Map<string, unknown>() };
  const safety = safetyCategoryFor(response);
  if (safety || response.statusCode === 429) return { status: "VERIFICATION_BLOCKED", note: `Postcondition request ${check.id} was blocked or unavailable.`, snapshot: empty };
  if (response.statusCode === 404) return { status: "OBJECT_DISAPPEARED", note: `Postcondition object disappeared for ${check.id}.`, snapshot: empty };
  if (!isSuccessful(response) || (response.contentLength ?? 0) > check.maxResponseBytes || !matchesContentType(response.contentType, "application/json")) return { status: "STATE_RESPONSE_UNAVAILABLE", note: `Postcondition response was unavailable for ${check.id}.`, snapshot: empty };
  const parsed = parseJson(bodyPreviewForAnalysis(response) ?? "", check.maxJsonDepth);
  if (!parsed || !isRecord(parsed)) return { status: "STATE_RESPONSE_AMBIGUOUS", note: `Postcondition response was not a bounded JSON object for ${check.id}.`, snapshot: empty };
  const objectId = scalarAt(parsed, check.objectIdentityField);
  if (objectId !== check.objectId) return { status: "OBJECT_IDENTITY_CHANGED", note: `Postcondition object identity changed for ${check.id}.`, snapshot: empty };
  const values = new Map<string, unknown>();
  for (const field of check.fields) {
    const value = valueAt(parsed, field.path);
    if (value === undefined || typeof value === "object") return { status: "STATE_RESPONSE_AMBIGUOUS", note: `Configured postcondition field "${field.path}" was unavailable or non-scalar for ${check.id}.`, snapshot: empty };
    if (field.expectedValue !== undefined && !Object.is(value, field.expectedValue)) return { status: "STATE_CHANGED", note: `Configured postcondition field "${field.path}" did not match expected value for ${check.id}.`, snapshot: empty };
    values.set(field.path, value);
  }
  return { status: "VERIFIED_UNCHANGED", note: "Postcondition check passed.", snapshot: { objectIdHash: check.objectIdHash, values } };
}

function classifyResponse(_context: ScanContext, casePlan: BulkAuthorizationCasePlan, response: HttpResponse, baselines: BaselineSummary): BulkAuthorizationObservation {
  const safety = safetyCategoryFor(response);
  if (safety) return baseObservation(casePlan, safety, response, ["Request was blocked or failed before bulk authorization could be evaluated."]);
  if (response.statusCode === 429) return baseObservation(casePlan, "RATE_LIMITED", response, ["Rate limiting is not treated as denial."]);
  if ((response.contentLength ?? 0) > casePlan.maxResponseBytes) return baseObservation(casePlan, "RESPONSE_TOO_LARGE", response, ["Response exceeded configured bulk response size limit."]);
  if (casePlan.safetyContract.disallowedStatusCodes.includes(response.statusCode ?? 0)) return baseObservation(casePlan, response.statusCode === 202 ? "ASYNCHRONOUS_OPERATION_DETECTED" : "NON_MUTATING_CONTRACT_VIOLATED", response, ["Response status violated the configured non-mutating safety contract."]);
  if (casePlan.safetyContract.prohibitDownloads && /attachment|octet-stream|zip|pdf|csv/i.test(`${headersForAnalysis(response)["content-disposition"] ?? ""} ${response.contentType ?? ""}`)) return baseObservation(casePlan, "DOWNLOAD_RESPONSE_BLOCKED", response, ["Download-like response was blocked for this preview workflow."]);
  if (!matchesContentType(response.contentType, "application/json")) return baseObservation(casePlan, "RESPONSE_NOT_PARSEABLE", response, ["Bulk response was not JSON."]);
  const parsed = parseJson(bodyPreviewForAnalysis(response) ?? "", casePlan.maxJsonDepth);
  if (!parsed || !isRecord(parsed)) return baseObservation(casePlan, "RESPONSE_NOT_PARSEABLE", response, ["Bulk response was not a bounded JSON object."]);
  const safetyContract = evaluateSafetyContract(casePlan, parsed);
  if (safetyContract) return baseObservation(casePlan, safetyContract, response, ["Bulk response did not satisfy the configured non-mutating safety contract."]);

  const projection = projectObjects(casePlan, parsed);
  const decision = classifyProjection(casePlan, projection, baselines);
  return {
    ...baseObservation(casePlan, decision.observedDecision, response, decision.notes),
    safetyContractSatisfied: true,
    matchedSuppliedObjects: projection.objects.filter((object) => object.included).length,
    unknownReturnedItemCount: projection.unknownReturnedItemCount,
    objects: projection.objects,
    ...(decision.findingCategory ? { findingCategory: decision.findingCategory } : {}),
    confidence: decision.findingCategory ? "CONFIRMED" : decision.observedDecision === "INCONCLUSIVE" ? "INCONCLUSIVE" : "HIGH"
  };
}

function evaluateSafetyContract(casePlan: BulkAuthorizationCasePlan, parsed: Record<string, unknown>): BulkAuthorizationDecisionCategory | undefined {
  const markerPath = casePlan.safetyContract.requiredResponseMarkerPath;
  if (markerPath && casePlan.safetyContract.requiredResponseMarkerValue !== undefined && valueAt(parsed, markerPath) !== casePlan.safetyContract.requiredResponseMarkerValue) return "NON_MUTATING_CONTRACT_UNCONFIRMED";
  for (const path of casePlan.safetyContract.disallowedResponsePaths) {
    const value = valueAt(parsed, path);
    if (value !== undefined && value !== null && value !== false) return /job|task|queue|async/i.test(path) ? "ASYNCHRONOUS_OPERATION_DETECTED" : "NON_MUTATING_CONTRACT_VIOLATED";
  }
  if (casePlan.safetyContract.prohibitAsync && (valueAt(parsed, "jobId") || valueAt(parsed, "taskId") || valueAt(parsed, "location"))) return "ASYNCHRONOUS_OPERATION_DETECTED";
  return undefined;
}

function projectObjects(casePlan: BulkAuthorizationCasePlan, parsed: Record<string, unknown>): { objects: BulkObjectObservation[]; unknownReturnedItemCount: number } {
  const supplied = new Map(casePlan.objects.map((object) => [object.objectId, object]));
  const objectObservations = new Map<string, BulkObjectObservation>();
  for (const object of casePlan.objects) {
    objectObservations.set(object.objectIdHash, { objectAlias: object.redactedAlias, objectIdHash: object.objectIdHash, expectedDecision: object.expectedDecision, included: false, duplicateCount: 0, metadataExposed: false });
  }
  let unknownReturnedItemCount = 0;
  const arrays = arraysForContract(casePlan, parsed);
  for (const entry of arrays.returned) {
    if (!isRecord(entry)) continue;
    const id = scalarAt(entry, casePlan.responseContract.resultObjectIdPath);
    if (!id) continue;
    const object = supplied.get(id);
    if (!object) {
      unknownReturnedItemCount += 1;
      continue;
    }
    const observation = objectObservations.get(object.objectIdHash);
    if (!observation) continue;
    observation.included = true;
    observation.duplicateCount += 1;
    observation.metadataExposed = hasConfiguredMetadata(casePlan, entry);
    const observedDecision = scalarAt(entry, casePlan.responseContract.perObjectDecisionPath);
    if (observedDecision) observation.observedDecision = observedDecision;
  }
  for (const entry of arrays.rejected) {
    if (!isRecord(entry)) continue;
    const id = scalarAt(entry, casePlan.responseContract.rejectedObjectIdPath);
    const object = id ? supplied.get(id) : undefined;
    if (!object) continue;
    const observation = objectObservations.get(object.objectIdHash);
    if (observation) observation.observedDecision = observation.observedDecision ?? "rejected";
  }
  return { objects: [...objectObservations.values()], unknownReturnedItemCount };
}

function classifyProjection(casePlan: BulkAuthorizationCasePlan, projection: { objects: BulkObjectObservation[] }, baselines: BaselineSummary): { observedDecision: BulkAuthorizationDecisionCategory; findingCategory?: BulkAuthorizationFindingCategory; notes: string[] } {
  for (const object of projection.objects) {
    const baselineDecision = baselines.decisions.get(object.objectIdHash);
    if (baselineDecision) {
      object.baselineDecision = baselineDecision;
      object.baselineCompatible = baselineDecision !== "UNAVAILABLE" && baselineDecision !== "INCONCLUSIVE" && baselineDecision !== "OBJECT_IDENTITY_MISMATCH" && baselineDecision !== "OBJECT_STATE_MISMATCH";
    }
  }
  const prohibited = projection.objects.filter((object) => ["DENY", "FILTER_OUT", "EXPLICIT_REJECTION", "REDACTED_METADATA_ONLY"].includes(object.expectedDecision));
  const exposed = prohibited.find((object) => object.included);
  const metadata = prohibited.find((object) => object.metadataExposed);
  if (exposed) {
    if (!hasTrustedObjectVerification(casePlan, exposed.objectIdHash)) return { observedDecision: "OBJECT_VERIFICATION_UNAVAILABLE", notes: ["A prohibited supplied object was matched, but its authorization-boundary metadata was declared-only and cannot support a confirmed finding."] };
    if (exposed.baselineDecision === "DENIED_CONFIRMED" || exposed.baselineDecision === "AUTHENTICATION_REQUIRED" || exposed.baselineDecision === "OBJECT_NOT_FOUND") {
      const category = findingCategoryFor(casePlan, true);
      exposed.findingCategory = category;
      return { observedDecision: decisionForFinding(category), findingCategory: category, notes: ["A compatible single-object baseline denied the exact supplied object, but the bulk response positively included it."] };
    }
    const category = findingCategoryFor(casePlan);
    exposed.findingCategory = category;
    return { observedDecision: decisionForFinding(category), findingCategory: category, notes: ["A prohibited supplied object was positively matched in the non-mutating bulk response."] };
  }
  if (metadata) {
    if (!hasTrustedObjectVerification(casePlan, metadata.objectIdHash)) return { observedDecision: "OBJECT_VERIFICATION_UNAVAILABLE", notes: ["Restricted metadata was observed for a prohibited supplied object, but declared-only object metadata cannot support a confirmed finding."] };
    if (metadata.baselineDecision === "DENIED_CONFIRMED" || metadata.baselineDecision === "AUTHENTICATION_REQUIRED" || metadata.baselineDecision === "OBJECT_NOT_FOUND") {
      const category = findingCategoryFor(casePlan, true);
      metadata.findingCategory = category;
      return { observedDecision: decisionForFinding(category), findingCategory: category, notes: ["A compatible single-object baseline denied the exact supplied object, but the bulk response exposed configured protected metadata for it."] };
    }
    metadata.findingCategory = "BULK_PREVIEW_METADATA_EXPOSURE";
    return { observedDecision: "UNAUTHORIZED_OBJECT_METADATA_EXPOSED", findingCategory: "BULK_PREVIEW_METADATA_EXPOSURE", notes: ["Configured restricted metadata was exposed for a prohibited supplied object."] };
  }
  const authorizedDropped = projection.objects.some((object) => object.expectedDecision === "ALLOW" && !object.included && casePlan.expectedBatchPolicy === "MUST_ALLOW_ENTIRE_BATCH");
  if (authorizedDropped) return { observedDecision: "AUTHORIZED_OBJECT_UNEXPECTEDLY_DROPPED", notes: ["An authorized supplied object was omitted; this is operational, not an authorization bypass."] };
  if (casePlan.expectedBatchPolicy === "MUST_REJECT_ENTIRE_BATCH" && projection.objects.every((object) => !object.included)) return { observedDecision: "ATOMIC_REJECTION_CONFIRMED", notes: ["The configured atomic rejection policy was satisfied."] };
  return { observedDecision: "BULK_POLICY_SATISFIED", notes: ["Bulk response satisfied the configured policy or did not expose prohibited supplied objects."] };
}

function hasTrustedObjectVerification(casePlan: BulkAuthorizationCasePlan, objectIdHash: string): boolean {
  return casePlan.objects.some((object) => object.objectIdHash === objectIdHash && object.verificationSource !== "DECLARED_ONLY");
}

function findingCategoryFor(casePlan: BulkAuthorizationCasePlan, baselineDiscrepancy = false): BulkAuthorizationFindingCategory {
  if (baselineDiscrepancy && casePlan.caseType === "REFERENCE_COMPARISON") return "BULK_SINGLE_OBJECT_AUTHORIZATION_INCONSISTENCY";
  if (casePlan.caseType === "MIXED_OWNERSHIP") return "MIXED_OWNERSHIP_BULK_BYPASS";
  if (casePlan.caseType === "MIXED_TENANT" || casePlan.actorRelationship.includes("CROSS_TENANT")) return "CROSS_TENANT_BULK_AUTHORIZATION_BYPASS";
  if (casePlan.caseType === "MIXED_ROLE_VISIBILITY" || casePlan.expectedRoleHash) return "ROLE_RESTRICTED_BULK_ACCESS";
  if (/SUSPENDED|DEACTIVATED/i.test(casePlan.actorRelationship)) return "ACCOUNT_STATE_BULK_RESTRICTION_BYPASS";
  if (casePlan.caseType === "MIXED_OBJECT_STATE") return "OBJECT_STATE_BULK_RESTRICTION_BYPASS";
  if (casePlan.expectedBatchPolicy === "MUST_MATCH_SINGLE_OBJECT_DECISIONS") return "SINGLE_VS_BULK_AUTHORIZATION_INCONSISTENCY";
  return "BULK_OBJECT_AUTHORIZATION_BYPASS";
}

function decisionForFinding(category: BulkAuthorizationFindingCategory): BulkAuthorizationDecisionCategory {
  if (category === "MIXED_OWNERSHIP_BULK_BYPASS") return "MIXED_OWNERSHIP_POLICY_BYPASS";
  if (category === "CROSS_TENANT_BULK_AUTHORIZATION_BYPASS") return "CROSS_TENANT_BULK_ACCESS";
  if (category === "ROLE_RESTRICTED_BULK_ACCESS") return "ROLE_RESTRICTION_BYPASS";
  if (category === "ACCOUNT_STATE_BULK_RESTRICTION_BYPASS") return "ACCOUNT_STATE_RESTRICTION_BYPASS";
  if (category === "OBJECT_STATE_BULK_RESTRICTION_BYPASS") return "OBJECT_STATE_RESTRICTION_BYPASS";
  if (category === "SINGLE_VS_BULK_AUTHORIZATION_INCONSISTENCY" || category === "BULK_SINGLE_OBJECT_AUTHORIZATION_INCONSISTENCY") return "SINGLE_OBJECT_BULK_INCONSISTENCY";
  return "UNAUTHORIZED_OBJECT_INCLUDED";
}

function baseObservation(casePlan: BulkAuthorizationCasePlan, observedDecision: BulkAuthorizationDecisionCategory, response: HttpResponse | undefined, notes: string[]): BulkAuthorizationObservation {
  return {
    definitionId: casePlan.definitionId,
    caseId: casePlan.id,
    actorId: casePlan.actorId,
    actorRelationship: casePlan.actorRelationship,
    ...(casePlan.authSlot ? { authSlot: casePlan.authSlot } : {}),
    operationType: casePlan.safetyContract.operationType,
    requestStyle: casePlan.requestStyle,
    method: casePlan.method,
    url: redactObjects(response?.finalUrl ?? casePlan.url, casePlan.objects),
    ...(casePlan.bodyHash ? { bodyHash: casePlan.bodyHash } : {}),
    expectedBatchPolicy: casePlan.expectedBatchPolicy,
    postSafetyMode: casePlan.postSafetyMode,
    postconditionStatus: casePlan.method === "POST" && casePlan.postSafetyMode === "OPERATOR_ATTESTED_DRY_RUN" ? "OPERATOR_ATTESTED_NOT_INDEPENDENTLY_VERIFIED" : "NOT_APPLICABLE",
    singleObjectComparison: "NOT_CONFIGURED",
    observedDecision,
    safetyContractSatisfied: observedDecision !== "NON_MUTATING_CONTRACT_UNCONFIRMED" && observedDecision !== "NON_MUTATING_CONTRACT_VIOLATED" && observedDecision !== "ASYNCHRONOUS_OPERATION_DETECTED" && observedDecision !== "DOWNLOAD_RESPONSE_BLOCKED",
    matchedSuppliedObjects: 0,
    unknownReturnedItemCount: 0,
    ...(typeof response?.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response?.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response?.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response?.bodyHash ? { responseHash: response.bodyHash } : {}),
    confidence: observedDecision === "INCONCLUSIVE" ? "INCONCLUSIVE" : "MEDIUM",
    objects: casePlan.objects.map((object) => ({ objectAlias: object.redactedAlias, objectIdHash: object.objectIdHash, expectedDecision: object.expectedDecision, included: false, duplicateCount: 0, metadataExposed: false })),
    ...(response?.error ? { error: response.error.message } : {}),
    notes
  };
}

function withBaselineSummary(observation: BulkAuthorizationObservation, baselines: BaselineSummary, postconditionStatus: BulkPostconditionStatus): BulkAuthorizationObservation {
  const comparable = [...baselines.decisions.values()].filter((decision) => decision !== "UNAVAILABLE" && decision !== "INCONCLUSIVE" && decision !== "OBJECT_IDENTITY_MISMATCH" && decision !== "OBJECT_STATE_MISMATCH");
  const singleObjectComparison =
    comparable.length === 0
      ? baselines.decisions.size === 0
        ? "NOT_CONFIGURED"
        : "UNAVAILABLE"
      : comparable.some((decision) => decision === "DENIED_CONFIRMED" || decision === "AUTHENTICATION_REQUIRED" || decision === "OBJECT_NOT_FOUND")
        ? "COMPATIBLE_DENIAL"
        : "COMPATIBLE_ALLOW";
  return {
    ...observation,
    postconditionStatus,
    singleObjectComparison,
    notes: [
      ...observation.notes,
      ...(observation.method === "POST" && postconditionStatus === "OPERATOR_ATTESTED_NOT_INDEPENDENTLY_VERIFIED" ? ["POST non-mutation was operator-attested and was not independently verified by configured pre/postcondition checks."] : []),
      ...(postconditionStatus === "VERIFIED_UNCHANGED" ? ["Configured pre/postcondition checks observed no change in selected state fields."] : [])
    ]
  };
}

function headersForCase(context: ScanContext, casePlan: BulkAuthorizationCasePlan): Record<string, string> {
  if (!casePlan.authSlot || !context.options.authProfileSet) return {};
  return casePlan.authSlot === "account_a" ? authHeadersForProfile(context.options.authProfileSet.accountA) : authHeadersForProfile(context.options.authProfileSet.accountB);
}

function headersForBaseline(context: ScanContext, baseline: BulkSingleObjectBaselinePlan): Record<string, string> {
  if (!baseline.authSlot || !context.options.authProfileSet) return {};
  return baseline.authSlot === "account_a" ? authHeadersForProfile(context.options.authProfileSet.accountA) : authHeadersForProfile(context.options.authProfileSet.accountB);
}

function headersForPostcondition(context: ScanContext, check: BulkPostconditionCheckPlan): Record<string, string> {
  if (!check.authSlot || !context.options.authProfileSet) return {};
  return check.authSlot === "account_a" ? authHeadersForProfile(context.options.authProfileSet.accountA) : authHeadersForProfile(context.options.authProfileSet.accountB);
}

function identityRequirementFor(input: BulkAuthorizationCasePlan | BulkSingleObjectBaselinePlan | BulkPostconditionCheckPlan): IdentityRequirement {
  return {
    ...(input.authSlot ? { authSlot: input.authSlot } : {}),
    requireVerifiedIdentity: input.requireVerifiedIdentity,
    ...(input.expectedTenantHash ? { expectedTenantHash: input.expectedTenantHash } : {}),
    ...(input.expectedRoleHash ? { expectedRoleHash: input.expectedRoleHash } : {}),
    ...("expectedAccountStateHash" in input && input.expectedAccountStateHash ? { expectedAccountStateHash: input.expectedAccountStateHash } : {})
  };
}

function identityBlockReason(context: ScanContext, casePlan: IdentityRequirement): string | undefined {
  if (!casePlan.requireVerifiedIdentity || !casePlan.authSlot) return undefined;
  const report = context.state.getIdentityVerification();
  const result = casePlan.authSlot === "account_a" ? report?.accountA : report?.accountB;
  if (!result?.verified) return `${casePlan.authSlot} required verified identity but result was ${result?.category ?? "missing"}.`;
  if (casePlan.expectedTenantHash && !result.tenantHash) return `${casePlan.authSlot} required verified tenant metadata.`;
  if (casePlan.expectedTenantHash && result.tenantHash !== casePlan.expectedTenantHash) return `${casePlan.authSlot} verified tenant metadata did not match the case expectation.`;
  if (casePlan.expectedRoleHash && !result.roleHash) return `${casePlan.authSlot} required verified role metadata.`;
  if (casePlan.expectedRoleHash && result.roleHash !== casePlan.expectedRoleHash) return `${casePlan.authSlot} verified role metadata did not match the case expectation.`;
  if (casePlan.expectedAccountStateHash && !result.accountStateHash) return `${casePlan.authSlot} required verified account-state metadata.`;
  if (casePlan.expectedAccountStateHash && result.accountStateHash !== casePlan.expectedAccountStateHash) return `${casePlan.authSlot} verified account-state metadata did not match the case expectation.`;
  if (report?.accountA?.verified && report.accountB?.verified && report.accountA.principalHash === report.accountB.principalHash) return "Account A and Account B resolved to the same verified principal.";
  return undefined;
}

function findingsFromReport(report: BulkAuthorizationReport, context: ScanContext): Finding[] {
  const scorer = new RiskScorer();
  return report.observations.filter((observation): observation is BulkAuthorizationObservation & { findingCategory: BulkAuthorizationFindingCategory } => Boolean(observation.findingCategory)).map((observation) => ({
    id: `bulk-authorization-${observation.definitionId}-${observation.caseId}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(),
    title: `Controlled bulk authorization issue: ${observation.findingCategory}`,
    type: "Bulk Authorization Issue" as const,
    severity: "High" as const,
    confidence: "High" as const,
    url: observation.url,
    method: observation.method,
    ...(observation.statusCode ? { statusCode: observation.statusCode } : {}),
    evidence: {
      url: observation.url,
      method: observation.method,
      ...(observation.statusCode ? { statusCode: observation.statusCode } : {}),
      ...(observation.responseHash ? { bodyHash: observation.responseHash } : {}),
      ...(observation.contentType ? { contentType: observation.contentType } : {}),
      ...(typeof observation.contentLength === "number" ? { contentLength: observation.contentLength } : {}),
      curlCommand: redactedCurlCommand(observation.url, authProfileForObservation(context, observation)),
      source: `Bulk ${observation.definitionId}/${observation.caseId}; operation=${observation.operationType}; expected=${observation.expectedBatchPolicy}; observed=${observation.observedDecision}; exact supplied object aliases retained, raw IDs redacted; unknown returned IDs discarded.`,
      severityReason: "A configured non-mutating bulk policy was bypassed for an exact supplied prohibited object.",
      reproductionNotes: ["Use only the supplied actor, exact batch, endpoint, method, and dry-run/preview markers.", "Do not execute a real mutation, poll jobs, download exports, split batches, or generate new object IDs."]
    },
    impact: "A bulk preview, validation, dry-run, or summary endpoint may expose or authorize a protected supplied object contrary to the configured authorization policy.",
    recommendation: "Authorize every object in the batch independently using trusted principal, tenant, role, account state, owner, and object state before returning bulk preview or validation results.",
    manualTestingSuggestions: ["Verify the configured non-mutating safety contract.", "Confirm the supplied object relationship and intended batch policy.", "Add negative tests for this exact mixed batch."],
    tags: ["bulk-authorization", "access-control", observation.findingCategory.toLowerCase().replace(/_/g, "-")],
    riskScore: scorer.score({ severity: "High", confidence: "High", falsePositiveStatus: "likely-valid", tags: ["bulk-authorization", "access-control"] }),
    workflowCase: { id: `${observation.definitionId}/${observation.caseId}` }, sourceModule: "bulk-authorization-testing",
    falsePositiveStatus: "likely-valid" as const,
    timestamp: new Date().toISOString()
  }));
}

function arraysForContract(casePlan: BulkAuthorizationCasePlan, parsed: Record<string, unknown>): { returned: readonly unknown[]; rejected: readonly unknown[] } {
  const returned = arrayAt(parsed, casePlan.responseContract.resultArrayPath);
  const rejected = arrayAt(parsed, casePlan.responseContract.rejectedArrayPath);
  return { returned: returned.slice(0, casePlan.responseContract.maxItems), rejected: rejected.slice(0, casePlan.responseContract.maxItems) };
}

function arrayAt(source: Record<string, unknown>, path: string | undefined): readonly unknown[] {
  if (!path) return [];
  const value = valueAt(source, path);
  return Array.isArray(value) ? value : [];
}

function scalarAt(source: Record<string, unknown>, path: string | undefined): string | undefined {
  if (!path) return undefined;
  const value = valueAt(source, path);
  return typeof value === "string" && value.length <= 256 && !/[\r\n\0]/.test(value) ? value : undefined;
}

function valueAt(source: Record<string, unknown>, path: string): unknown {
  return valueAtSafePath(source, parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "BULK_AUTHORIZATION_FIELD_PATH_INVALID" })).value;
}

function hasConfiguredMetadata(casePlan: BulkAuthorizationCasePlan, entry: Record<string, unknown>): boolean {
  return casePlan.responseContract.metadataPaths.some((path) => valueAt(entry, path) !== undefined);
}

function parseJson(body: string, maxDepth: number): unknown | undefined {
  try {
    const parsed = JSON.parse(body) as unknown;
    return jsonDepth(parsed, maxDepth + 1) <= maxDepth ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function jsonDepth(value: unknown, max: number): number {
  if (max <= 0 || typeof value !== "object" || value === null) return 0;
  const children = Array.isArray(value) ? value : Object.values(value);
  return 1 + Math.max(0, ...children.map((child) => jsonDepth(child, max - 1)));
}

function safetyCategoryFor(response: HttpResponse): BulkAuthorizationDecisionCategory | undefined {
  if (response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") return "TEST_BLOCKED_BY_SAFETY_POLICY";
  if (response.error?.name === "RequestBudgetExceeded") return "BUDGET_EXHAUSTED";
  if (response.error) return "EXECUTION_ERROR";
  return undefined;
}

function matchesContentType(actual: string | undefined, expected: string): boolean {
  return Boolean(actual?.toLowerCase().includes(expected));
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 300;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function redactObjects(url: string, objects: readonly BulkObjectPlan[]): string {
  return objects.reduce((safe, object) => safe.split(encodeURIComponent(object.objectId)).join(`<object:${object.objectIdHash}>`).split(object.objectId).join(`<object:${object.objectIdHash}>`), url);
}

function authProfileForObservation(context: ScanContext, observation: BulkAuthorizationObservation) {
  if (!observation.authSlot || !context.options.authProfileSet) return undefined;
  return observation.authSlot === "account_a" ? context.options.authProfileSet.accountA : context.options.authProfileSet.accountB;
}
