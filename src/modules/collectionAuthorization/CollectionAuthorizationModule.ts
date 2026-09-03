import { createHash } from "node:crypto";
import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import { redactBodyPreview } from "../../core/evidence/EvidenceBuilder.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { CollectionAuthorizationCasePlan, CollectionAuthorizationDefinitionPlan, KnownCollectionObjectPlan } from "../../core/planning/ScanPlan.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type {
  CollectionAuthorizationConfidence,
  CollectionAuthorizationDecisionCategory,
  CollectionAuthorizationFindingCategory,
  CollectionAuthorizationObservation,
  CollectionAuthorizationReport,
  CollectionMembershipCategory
} from "../../reports/ReportTypes.js";
import { parseSafeFieldPath, valueAtSafePath } from "../fieldExposureTesting/SafeFieldPath.js";

interface MembershipExtraction {
  membership: CollectionMembershipCategory;
  responsePartial: boolean;
  matchedIndex?: number;
  duplicateCount?: number;
  objectMetadataConfirmed?: boolean;
  objectTenantConfirmed?: boolean;
  objectOwnerConfirmed?: boolean;
  objectStateConfirmed?: boolean;
  matchedPreview?: string;
  notes: string[];
}

export class CollectionAuthorizationModule implements RouteCairnPlugin {
  public readonly name = "collection-authorization-testing";
  public readonly description = "Runs fixed collection/list/search/count/summary authorization checks.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeCollectionAuthorization(context);
    return {
      pluginName: this.name,
      collectionAuthorization: report,
      findings: findingsFromReport(report, context),
      notes: report.notes
    };
  }
}

async function executeCollectionAuthorization(context: ScanContext): Promise<CollectionAuthorizationReport> {
  const plan = context.options.plan.collectionAuthorizationTesting;
  if (!plan) {
    return {
      enabled: false,
      plannedCollections: 0,
      plannedCases: 0,
      plannedRequests: 0,
      executedRequests: 0,
      confirmedIssues: 0,
      observations: [],
      notes: ["Collection authorization testing skipped because no resolved collection plan was supplied."]
    };
  }

  const observations: CollectionAuthorizationObservation[] = [];
  let executedRequests = 0;
  collectionLoop: for (const collection of plan.collections) {
    for (const casePlan of collection.cases) {
      if (observations.length >= plan.maxRetainedObservations) break collectionLoop;
      const blockReason = identityBlockReason(context, casePlan);
      if (blockReason) {
        observations.push(blockedObservation(collection, casePlan, blockReason));
        continue;
      }
      observations.push(await sendAndClassify(context, collection, casePlan));
      executedRequests += 1;
    }
  }

  const compared = applyReferenceExpectations(observations);
  const confirmedIssues = compared.filter((observation) => observation.findingCategory).length;
  return {
    enabled: true,
    plannedCollections: plan.collections.length,
    plannedCases: plan.requestMatrix.length,
    plannedRequests: plan.requestMatrix.length,
    executedRequests,
    confirmedIssues,
    observations: compared,
    notes: [
      "Collection authorization testing executed only collection cases resolved before scan execution.",
      "Only GET requests were used; no pagination, endpoint discovery, query mutation, search expansion, or identifier harvesting occurred.",
      "Unmatched returned identifiers were discarded and never retained in reports."
    ]
  };
}

async function sendAndClassify(context: ScanContext, collection: CollectionAuthorizationDefinitionPlan, casePlan: CollectionAuthorizationCasePlan): Promise<CollectionAuthorizationObservation> {
  const response = await context.createHttpClient().send({ url: casePlan.url, method: "GET", headers: { ...collection.headers, ...headersForCase(context, casePlan) } });
  return classifyResponse(context, collection, casePlan, response);
}

function headersForCase(context: ScanContext, casePlan: CollectionAuthorizationCasePlan): Record<string, string> {
  if (!casePlan.authSlot) return {};
  const profileSet = context.options.authProfileSet;
  if (!profileSet) return {};
  return casePlan.authSlot === "account_a" ? authHeadersForProfile(profileSet.accountA) : authHeadersForProfile(profileSet.accountB);
}

function classifyResponse(context: ScanContext, collection: CollectionAuthorizationDefinitionPlan, casePlan: CollectionAuthorizationCasePlan, response: HttpResponse): CollectionAuthorizationObservation {
  const base = observationBase(collection, casePlan, response);
  const safety = safetyCategoryFor(response);
  if (safety) return finalize({ ...base, observedDecision: safety, matchedExpectation: false, notes: ["Request was blocked or failed before collection membership could be established."] });
  if (response.statusCode === 429) return finalize({ ...base, observedDecision: "RATE_LIMITED", matchedExpectation: false, notes: ["Rate limiting is not treated as collection denial."] });
  if (!isSuccessful(response)) return finalize({ ...base, observedDecision: "INCONCLUSIVE", matchedExpectation: false, notes: ["Unexpected status code could not establish collection membership."] });
  if ((response.contentLength ?? 0) > collection.maxResponseBytes) return finalize({ ...base, observedDecision: "RESPONSE_TOO_LARGE", matchedExpectation: false, notes: ["Response exceeded configured collection size limit."] });
  const analysisBody = bodyPreviewForAnalysis(response) ?? "";
  if (/login|sign in|required to log in/i.test(analysisBody)) return finalize({ ...base, observedDecision: "INCONCLUSIVE", matchedExpectation: false, notes: ["Response body looked like a login or denial page."] });
  if (!matchesContentType(response.contentType, collection.expectedContentType)) return finalize({ ...base, observedDecision: "RESPONSE_NOT_PARSEABLE", matchedExpectation: false, notes: ["Response did not match the expected JSON content type."] });
  const parsed = parseJson(analysisBody, collection.maxJsonDepth);
  if (!parsed) return finalize({ ...base, observedDecision: "RESPONSE_NOT_PARSEABLE", matchedExpectation: false, notes: ["Response body was not supported bounded JSON."] });

  const knownObject = findKnownObject(context, collection, casePlan);
  const membership = collection.completeness === "SUMMARY_ONLY" || !knownObject ? notEvaluated("No object membership was evaluated for this summary/count-only case.") : extractMembership(collection, casePlan, knownObject, parsed, response, context.options.plan.evidence.level !== "minimal" ? context.options.plan.collectionAuthorizationTesting?.maxPreviewLength ?? 0 : 0);
  const countResult = evaluateCount(casePlan, parsed);
  const summaryResult = evaluateSummary(casePlan, parsed);
  const decision = decisionFor(collection, casePlan, membership, knownObject, countResult, summaryResult);
  return finalize({
    ...base,
    observedMembership: membership.membership,
    ...(membership.matchedIndex !== undefined ? { matchedIndex: membership.matchedIndex } : {}),
    ...(membership.duplicateCount !== undefined ? { duplicateCount: membership.duplicateCount } : {}),
    ...(membership.objectMetadataConfirmed !== undefined ? { objectMetadataConfirmed: membership.objectMetadataConfirmed } : {}),
    ...(membership.objectTenantConfirmed !== undefined ? { objectTenantConfirmed: membership.objectTenantConfirmed } : {}),
    ...(membership.objectOwnerConfirmed !== undefined ? { objectOwnerConfirmed: membership.objectOwnerConfirmed } : {}),
    ...(membership.objectStateConfirmed !== undefined ? { objectStateConfirmed: membership.objectStateConfirmed } : {}),
    ...(membership.matchedPreview ? { matchedObjectPreview: membership.matchedPreview } : {}),
    ...(countResult.countObserved !== undefined && (!casePlan.countExpectation?.securitySensitive || context.options.plan.evidence.level === "strong") ? { countObserved: countResult.countObserved } : {}),
    ...(countResult.countObserved !== undefined && casePlan.countExpectation?.securitySensitive ? { countObservedHash: hashValue(String(countResult.countObserved), "count") } : {}),
    ...(summaryResult.summaryObservedHash ? { summaryObservedHash: summaryResult.summaryObservedHash } : {}),
    observedDecision: decision.observedDecision,
    matchedExpectation: decision.matchedExpectation,
    ...(decision.findingCategory ? { findingCategory: decision.findingCategory } : {}),
    notes: [...membership.notes, ...countResult.notes, ...summaryResult.notes, ...decision.notes]
  });
}

function extractMembership(
  collection: CollectionAuthorizationDefinitionPlan,
  casePlan: CollectionAuthorizationCasePlan,
  knownObject: KnownCollectionObjectPlan,
  parsed: unknown,
  response: HttpResponse,
  maxPreviewLength: number
): MembershipExtraction {
  const entries = entriesAtPath(parsed, collection.resultArrayPath);
  if (!entries) return notEvaluated("Configured result-array path was missing or not an array.");
  const partialSignals = partialResponseSignals(parsed, response, entries.length);
  if (entries.length > collection.maxInspectedEntries) {
    return { ...notEvaluated(`Result array exceeded maxInspectedEntries ${collection.maxInspectedEntries}.`), responsePartial: true };
  }

  let duplicateCount = 0;
  let matchedIndex: number | undefined;
  let metadataMismatch = false;
  let tenantConfirmed: boolean | undefined;
  let ownerConfirmed: boolean | undefined;
  let stateConfirmed: boolean | undefined;
  let matchedPreview: string | undefined;
  const objectIdPath = collection.objectIdPath ? parseSafeFieldPath(collection.objectIdPath, { maxDepth: 8, maxArrayIndex: 50, code: "COLLECTION_AUTHORIZATION_FIELD_PATH_INVALID" }) : [];
  for (const [index, entry] of entries.entries()) {
    if (!isRecord(entry)) continue;
    const objectId = scalarAtSafePath(entry, objectIdPath);
    if (objectId !== knownObject.objectId) continue;
    duplicateCount += 1;
    if (matchedIndex === undefined) matchedIndex = index;
    const metadata = confirmMetadata(collection, casePlan, knownObject, entry);
    tenantConfirmed = metadata.tenantConfirmed ?? tenantConfirmed;
    ownerConfirmed = metadata.ownerConfirmed ?? ownerConfirmed;
    stateConfirmed = metadata.stateConfirmed ?? stateConfirmed;
    if (!metadata.confirmed) metadataMismatch = true;
    if (!matchedPreview && maxPreviewLength > 0) matchedPreview = redactedPreview(entry, knownObject, maxPreviewLength);
  }

  const partialNotes = partialSignals.map((signal) => `Partial collection signal observed: ${signal}.`);
  if (duplicateCount === 0) return { membership: "NOT_FOUND", responsePartial: partialSignals.length > 0, notes: [absenceNote(collection.completeness), ...partialNotes] };
  if (metadataMismatch) {
    return {
      membership: "METADATA_MISMATCH",
      responsePartial: partialSignals.length > 0,
      ...(matchedIndex !== undefined ? { matchedIndex } : {}),
      duplicateCount,
      objectMetadataConfirmed: false,
      ...(tenantConfirmed !== undefined ? { objectTenantConfirmed: tenantConfirmed } : {}),
      ...(ownerConfirmed !== undefined ? { objectOwnerConfirmed: ownerConfirmed } : {}),
      ...(stateConfirmed !== undefined ? { objectStateConfirmed: stateConfirmed } : {}),
      notes: ["Supplied object ID appeared but configured object metadata did not match.", ...partialNotes]
    };
  }
  return {
    membership: duplicateCount === 1 ? "FOUND_ONCE" : "FOUND_MULTIPLE_TIMES",
    responsePartial: partialSignals.length > 0,
    ...(matchedIndex !== undefined ? { matchedIndex } : {}),
    duplicateCount,
    objectMetadataConfirmed: true,
    ...(tenantConfirmed !== undefined ? { objectTenantConfirmed: tenantConfirmed } : {}),
    ...(ownerConfirmed !== undefined ? { objectOwnerConfirmed: ownerConfirmed } : {}),
    ...(stateConfirmed !== undefined ? { objectStateConfirmed: stateConfirmed } : {}),
    ...(matchedPreview ? { matchedPreview } : {}),
    notes: ["Exact supplied object ID appeared in the bounded configured collection response.", ...partialNotes]
  };
}

function confirmMetadata(collection: CollectionAuthorizationDefinitionPlan, casePlan: CollectionAuthorizationCasePlan, knownObject: KnownCollectionObjectPlan, entry: Record<string, unknown>): { confirmed: boolean; tenantConfirmed?: boolean; ownerConfirmed?: boolean; stateConfirmed?: boolean } {
  const checks: boolean[] = [];
  const tenantConfirmed = collection.objectTenantPath && knownObject.tenantIdHash ? hashScalarAtPath(entry, collection.objectTenantPath, "tenant") === knownObject.tenantIdHash : undefined;
  const ownerConfirmed = collection.objectOwnerPath && knownObject.ownerActorId ? scalarAtPath(entry, collection.objectOwnerPath) === knownObject.ownerActorId : undefined;
  const stateConfirmed = collection.objectStatePath && (casePlan.expectedObjectState ?? knownObject.state) ? scalarAtPath(entry, collection.objectStatePath) === (casePlan.expectedObjectState ?? knownObject.state) : undefined;
  const typeConfirmed = collection.objectTypePath ? scalarAtPath(entry, collection.objectTypePath) === knownObject.objectType : undefined;
  for (const value of [tenantConfirmed, ownerConfirmed, stateConfirmed, typeConfirmed]) {
    if (value !== undefined) checks.push(value);
  }
  return {
    confirmed: checks.every(Boolean),
    ...(tenantConfirmed !== undefined ? { tenantConfirmed } : {}),
    ...(ownerConfirmed !== undefined ? { ownerConfirmed } : {}),
    ...(stateConfirmed !== undefined ? { stateConfirmed } : {})
  };
}

function evaluateCount(casePlan: CollectionAuthorizationCasePlan, parsed: unknown): { countObserved?: number; violation: boolean; finding: boolean; notes: string[] } {
  const expectation = casePlan.countExpectation;
  if (!expectation || !isRecord(parsed)) return { violation: false, finding: false, notes: [] };
  const value = scalarUnknownAtPath(parsed, expectation.path);
  if (typeof value !== "number" || !Number.isFinite(value)) return { violation: false, finding: false, notes: ["Configured count path was missing or not numeric."] };
  const violation = (expectation.expectation === "MUST_EQUAL" && expectation.expectedCount !== undefined && value !== expectation.expectedCount) || (expectation.expectation === "MUST_BE_ZERO" && value !== 0);
  return {
    countObserved: value,
    violation,
    finding: violation && expectation.securitySensitive && !expectation.volatile,
    notes: violation ? ["Configured count expectation was not satisfied."] : ["Configured count expectation was satisfied or observe-only."]
  };
}

function evaluateSummary(casePlan: CollectionAuthorizationCasePlan, parsed: unknown): { violation: boolean; finding: boolean; summaryObservedHash?: string; notes: string[] } {
  if (!isRecord(parsed) || casePlan.summaryExpectations.length === 0) return { violation: false, finding: false, notes: [] };
  const observedValues: Array<string | number | boolean | null> = [];
  let violation = false;
  let finding = false;
  for (const expectation of casePlan.summaryExpectations) {
    const value = scalarSummaryAtPath(parsed, expectation.path);
    if (value === undefined) continue;
    observedValues.push(value);
    const differs = expectation.expectedValue !== undefined && value !== expectation.expectedValue;
    const nonZero = expectation.expectation === "MUST_BE_ZERO" && typeof value === "number" && value !== 0;
    if (differs || nonZero) {
      violation = true;
      finding = finding || (expectation.securitySensitive && !expectation.volatile);
    }
  }
  return {
    violation,
    finding,
    ...(observedValues.length > 0 ? { summaryObservedHash: hashValue(JSON.stringify(observedValues), "summary") } : {}),
    notes: violation ? ["Configured summary expectation was not satisfied."] : ["Configured summary expectation was satisfied or observe-only."]
  };
}

function decisionFor(
  collection: CollectionAuthorizationDefinitionPlan,
  casePlan: CollectionAuthorizationCasePlan,
  membership: MembershipExtraction,
  knownObject: KnownCollectionObjectPlan | undefined,
  countResult: { violation: boolean; finding: boolean },
  summaryResult: { violation: boolean; finding: boolean }
): { observedDecision: CollectionAuthorizationDecisionCategory; matchedExpectation: boolean; findingCategory?: CollectionAuthorizationFindingCategory; notes: string[] } {
  if (countResult.finding) return { observedDecision: "COUNT_DISCLOSURE_OBSERVED", matchedExpectation: false, findingCategory: "CONFIRMED_COUNT_DISCLOSURE", notes: ["Count disclosure was treated as a finding only because the configured policy marked it sensitive and deterministic."] };
  if (summaryResult.finding) return { observedDecision: "SUMMARY_DISCLOSURE_OBSERVED", matchedExpectation: false, findingCategory: "CONFIRMED_SUMMARY_DISCLOSURE", notes: ["Summary disclosure was treated as a finding only because the configured policy marked it sensitive and deterministic."] };
  if (membership.membership === "METADATA_MISMATCH") return { observedDecision: "OBJECT_METADATA_MISMATCH", matchedExpectation: false, notes: ["Metadata mismatch prevented a confirmed collection finding."] };
  if (membership.membership === "NOT_EVALUATED") return { observedDecision: "INCONCLUSIVE", matchedExpectation: casePlan.expectedMembership === "OBSERVE_ONLY", notes: ["Membership was not evaluated."] };
  const found = membership.membership === "FOUND_ONCE" || membership.membership === "FOUND_MULTIPLE_TIMES";
  if (found && casePlan.expectedMembership === "MUST_NOT_CONTAIN" && knownObject) {
    const findingCategory = findingCategoryFor(collection, casePlan, knownObject);
    return { observedDecision: decisionForFinding(findingCategory), matchedExpectation: false, findingCategory, notes: ["A supplied object explicitly prohibited by the configured membership policy appeared in the response."] };
  }
  if (!found && casePlan.expectedMembership === "MUST_CONTAIN") return { observedDecision: "EXPECTED_OBJECT_MISSING", matchedExpectation: false, notes: ["An explicitly expected object did not appear. This is operational evidence, not an automatic security finding."] };
  if (!found && casePlan.expectedMembership === "MUST_NOT_CONTAIN") {
    if (membership.responsePartial) {
      return { observedDecision: "COLLECTION_RESPONSE_INCOMPLETE", matchedExpectation: false, notes: ["Absence cannot satisfy a denial expectation because the response signaled an incomplete collection window."] };
    }
    return { observedDecision: collection.completeness === "COMPLETE_COLLECTION" ? "MEMBERSHIP_EXPECTATION_SATISFIED" : "OBJECT_NOT_FOUND_IN_WINDOW", matchedExpectation: collection.completeness === "COMPLETE_COLLECTION", notes: [absenceNote(collection.completeness)] };
  }
  return { observedDecision: "MEMBERSHIP_EXPECTATION_SATISFIED", matchedExpectation: true, notes: ["Membership result satisfied the configured expectation or was observe-only."] };
}

function findingCategoryFor(collection: CollectionAuthorizationDefinitionPlan, casePlan: CollectionAuthorizationCasePlan, knownObject: KnownCollectionObjectPlan): CollectionAuthorizationFindingCategory {
  if (casePlan.actorRelationship === "PUBLIC" && !knownObject.expectedPublic) return "PRIVATE_OBJECT_PUBLIC_LISTING_EXPOSURE";
  if (collection.category === "SEARCH") return "SEARCH_RESULT_AUTHORIZATION_EXPOSURE";
  if (casePlan.actorRelationship.includes("CROSS_TENANT")) return "CROSS_TENANT_COLLECTION_EXPOSURE";
  if (casePlan.expectedRoleHash) return "ROLE_RESTRICTED_COLLECTION_EXPOSURE";
  if (/SUSPENDED/i.test(casePlan.actorRelationship)) return "SUSPENDED_PRINCIPAL_COLLECTION_ACCESS";
  if (/DEACTIVATED/i.test(casePlan.actorRelationship)) return "DEACTIVATED_PRINCIPAL_COLLECTION_ACCESS";
  if (/DRAFT/i.test(casePlan.expectedObjectState ?? knownObject.state ?? "")) return "DRAFT_OBJECT_LISTING_EXPOSURE";
  if (/ARCHIVED/i.test(casePlan.expectedObjectState ?? knownObject.state ?? "")) return "ARCHIVED_OBJECT_LISTING_EXPOSURE";
  if (/DELETED/i.test(casePlan.expectedObjectState ?? knownObject.state ?? "")) return "DELETED_OBJECT_LISTING_EXPOSURE";
  return "UNAUTHORIZED_COLLECTION_MEMBERSHIP";
}

function decisionForFinding(category: CollectionAuthorizationFindingCategory): CollectionAuthorizationDecisionCategory {
  if (category === "CROSS_TENANT_COLLECTION_EXPOSURE") return "CROSS_TENANT_OBJECT_LISTED";
  if (category === "ROLE_RESTRICTED_COLLECTION_EXPOSURE") return "ROLE_RESTRICTED_OBJECT_LISTED";
  if (category === "SUSPENDED_PRINCIPAL_COLLECTION_ACCESS" || category === "DEACTIVATED_PRINCIPAL_COLLECTION_ACCESS") return "ACCOUNT_STATE_RESTRICTED_OBJECT_LISTED";
  if (category === "DRAFT_OBJECT_LISTING_EXPOSURE" || category === "ARCHIVED_OBJECT_LISTING_EXPOSURE" || category === "DELETED_OBJECT_LISTING_EXPOSURE") return "OBJECT_STATE_RESTRICTED_OBJECT_LISTED";
  if (category === "PRIVATE_OBJECT_PUBLIC_LISTING_EXPOSURE") return "PUBLIC_COLLECTION_OVEREXPOSURE";
  if (category === "SEARCH_RESULT_AUTHORIZATION_EXPOSURE") return "SEARCH_RESULT_OVEREXPOSURE";
  return "UNAUTHORIZED_OBJECT_LISTED";
}

function observationBase(collection: CollectionAuthorizationDefinitionPlan, casePlan: CollectionAuthorizationCasePlan, response?: HttpResponse): CollectionAuthorizationObservation {
  return {
    collectionId: collection.id,
    collectionLabel: collection.label,
    caseId: casePlan.id,
    actorId: casePlan.actorId,
    actorRelationship: casePlan.actorRelationship,
    ...(casePlan.authSlot ? { authSlot: casePlan.authSlot } : {}),
    ...(casePlan.referenceCaseId ? { referenceCaseId: casePlan.referenceCaseId } : {}),
    category: collection.category,
    completeness: collection.completeness,
    ...(casePlan.objectType ? { objectType: casePlan.objectType } : {}),
    ...(casePlan.objectIdHash ? { objectIdHash: casePlan.objectIdHash } : {}),
    method: "GET",
    url: redactObjectId(response?.finalUrl || casePlan.url, casePlan.objectId, casePlan.objectIdHash),
    expectedMembership: casePlan.expectedMembership,
    observedMembership: "NOT_EVALUATED",
    observedDecision: "INCONCLUSIVE",
    matchedExpectation: false,
    ...(typeof response?.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response?.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response?.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response?.bodyHash ? { bodyHash: response.bodyHash } : {}),
    confidence: "INCONCLUSIVE",
    ...(response?.error ? { error: response.error.message } : {}),
    notes: []
  };
}

function blockedObservation(collection: CollectionAuthorizationDefinitionPlan, casePlan: CollectionAuthorizationCasePlan, reason: string): CollectionAuthorizationObservation {
  return {
    ...observationBase(collection, casePlan),
    observedDecision: "IDENTITY_REQUIREMENT_UNSATISFIED",
    matchedExpectation: false,
    notes: [`Collection case blocked before execution: ${reason}`, "Verified identity requirements were not downgraded to declared-only metadata."]
  };
}

function identityBlockReason(context: ScanContext, casePlan: CollectionAuthorizationCasePlan): string | undefined {
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

function applyReferenceExpectations(observations: CollectionAuthorizationObservation[]): CollectionAuthorizationObservation[] {
  const byId = new Map(observations.map((observation) => [`${observation.collectionId}:${observation.caseId}`, observation]));
  return observations.map((observation) => {
    if (observation.expectedMembership !== "MUST_MATCH_REFERENCE_CASE" && observation.expectedMembership !== "MUST_NOT_EXCEED_REFERENCE_MEMBERSHIP") return observation;
    const reference = observation.referenceCaseId ? byId.get(`${observation.collectionId}:${observation.referenceCaseId}`) : undefined;
    if (!reference) return { ...observation, matchedExpectation: false, confidence: "INCONCLUSIVE" as const, notes: [...observation.notes, "Reference collection case result was unavailable."] };
    const incompatibleReason = referenceIncompatibility(observation, reference);
    if (incompatibleReason) return { ...observation, matchedExpectation: false, confidence: "INCONCLUSIVE" as const, notes: [...observation.notes, `Reference collection case could not be compared: ${incompatibleReason}.`] };
    const observationFound = isFound(observation.observedMembership);
    const referenceFound = isFound(reference.observedMembership);
    if (observation.expectedMembership === "MUST_MATCH_REFERENCE_CASE") {
      const matched = observation.observedMembership === reference.observedMembership;
      return { ...observation, matchedExpectation: matched, confidence: matched ? "HIGH" : "MEDIUM", notes: [...observation.notes, `Compared with reference collection case ${reference.caseId}.`] };
    }
    const exceededReference = observationFound && !referenceFound;
    const findingCategory = exceededReference && observation.objectMetadataConfirmed !== false ? findingCategoryForObservation(observation) : undefined;
    return {
      ...observation,
      matchedExpectation: !exceededReference,
      ...(findingCategory ? { findingCategory, observedDecision: decisionForFinding(findingCategory) } : {}),
      confidence: exceededReference ? "CONFIRMED" : "HIGH",
      notes: [...observation.notes, `Compared with reference collection case ${reference.caseId}; current membership must not exceed reference membership.`]
    };
  });
}

function referenceIncompatibility(observation: CollectionAuthorizationObservation, reference: CollectionAuthorizationObservation): string | undefined {
  if (observation.url !== reference.url) return "endpoint or fixed query differs";
  if (observation.category !== reference.category) return "endpoint category differs";
  if (observation.completeness !== reference.completeness) return "completeness policy differs";
  if (observation.objectIdHash && reference.objectIdHash && observation.objectIdHash !== reference.objectIdHash) return "known object differs";
  if (!reference.matchedExpectation && reference.observedDecision !== "MEMBERSHIP_EXPECTATION_SATISFIED" && reference.observedDecision !== "OBJECT_NOT_FOUND_IN_WINDOW") return "reference did not complete successfully";
  if (reference.observedDecision === "RATE_LIMITED" || reference.observedDecision === "BUDGET_EXHAUSTED" || reference.observedDecision === "RESPONSE_NOT_PARSEABLE" || reference.observedDecision === "IDENTITY_REQUIREMENT_UNSATISFIED" || reference.observedDecision === "COLLECTION_RESPONSE_INCOMPLETE" || reference.observedDecision === "TEST_BLOCKED_BY_SAFETY_POLICY" || reference.observedDecision === "EXECUTION_ERROR") return `reference result was ${reference.observedDecision}`;
  if (reference.notes.some((note) => /Partial collection signal observed/i.test(note))) return "reference response signaled partial collection data";
  if (observation.notes.some((note) => /Partial collection signal observed/i.test(note))) return "dependent response signaled partial collection data";
  return undefined;
}

function finalize(observation: CollectionAuthorizationObservation): CollectionAuthorizationObservation {
  return { ...observation, confidence: confidenceFor(observation) };
}

function confidenceFor(observation: CollectionAuthorizationObservation): CollectionAuthorizationConfidence {
  if (observation.findingCategory && observation.objectMetadataConfirmed !== false) return "CONFIRMED";
  if (observation.matchedExpectation) return "HIGH";
  if (observation.observedDecision === "INCONCLUSIVE") return "INCONCLUSIVE";
  return "MEDIUM";
}

function findingsFromReport(report: CollectionAuthorizationReport, context: ScanContext): Finding[] {
  const riskScorer = new RiskScorer();
  return report.observations.filter(hasFindingCategory).map((observation) => ({
    id: `collection-authorization-${observation.collectionId}-${observation.caseId}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(),
    title: `Controlled collection authorization issue: ${observation.findingCategory}`,
    type: "Collection Authorization Issue" as const,
    severity: "High" as const,
    confidence: "High" as const,
    url: observation.url,
    method: "GET",
    ...(observation.statusCode ? { statusCode: observation.statusCode } : {}),
    evidence: {
      url: observation.url,
      method: "GET",
      ...(observation.statusCode ? { statusCode: observation.statusCode } : {}),
      ...(observation.bodyHash ? { bodyHash: observation.bodyHash } : {}),
      ...(observation.contentType ? { contentType: observation.contentType } : {}),
      ...(typeof observation.contentLength === "number" ? { contentLength: observation.contentLength } : {}),
      curlCommand: redactedCurlCommand(observation.url, authProfileForObservation(context, observation)),
      source: `Collection ${observation.collectionId}/${observation.caseId}; expected=${observation.expectedMembership}; observed=${observation.observedDecision}; objectHash=${observation.objectIdHash ?? "none"}; unmatched returned IDs discarded; auth material redacted.`,
      severityReason: "A configured collection membership denial was bypassed after the exact supplied object appeared in the bounded response.",
      reproductionNotes: [
        "Use only the supplied actor, collection endpoint, fixed query, and known object.",
        "Do not paginate, fuzz queries, harvest returned IDs, or generalize beyond this configured case.",
        "Repeat the redacted request with the same actor authorization context."
      ]
    },
    impact: "A collection, list, search, count, or summary endpoint may reveal a protected supplied object or authorization-sensitive aggregate outside the configured actor boundary.",
    recommendation: "Filter collection, search, count, and summary queries server-side using trusted principal, tenant, role, account-state, object owner, and object-state authorization before returning results.",
    manualTestingSuggestions: ["Verify the configured membership policy is correct.", "Check whether public or shared visibility intentionally permits this appearance.", "Add a negative authorization test for this exact collection case."],
    tags: ["collection-authorization", "access-control", "needs-manual-policy-review", observation.findingCategory.toLowerCase().replace(/_/g, "-")],
    falsePositiveStatus: "likely-valid" as const,
    timestamp: new Date().toISOString(),
    workflowCase: { id: `${observation.collectionId}/${observation.caseId}` }, sourceModule: "collection-authorization-testing",
    riskScore: riskScorer.score({
      severity: "High",
      confidence: "High",
      falsePositiveStatus: "likely-valid",
      tags: ["collection-authorization", "access-control"]
    })
  }));
}

function hasFindingCategory(observation: CollectionAuthorizationObservation): observation is CollectionAuthorizationObservation & { findingCategory: CollectionAuthorizationFindingCategory } {
  return Boolean(observation.findingCategory);
}

function isFound(membership: CollectionMembershipCategory): boolean {
  return membership === "FOUND_ONCE" || membership === "FOUND_MULTIPLE_TIMES";
}

function findingCategoryForObservation(observation: CollectionAuthorizationObservation): CollectionAuthorizationFindingCategory {
  if (observation.actorRelationship === "PUBLIC") return "PRIVATE_OBJECT_PUBLIC_LISTING_EXPOSURE";
  if (observation.category === "SEARCH") return "SEARCH_RESULT_AUTHORIZATION_EXPOSURE";
  if (observation.actorRelationship.includes("CROSS_TENANT")) return "CROSS_TENANT_COLLECTION_EXPOSURE";
  if (/SUSPENDED/i.test(observation.actorRelationship)) return "SUSPENDED_PRINCIPAL_COLLECTION_ACCESS";
  if (/DEACTIVATED/i.test(observation.actorRelationship)) return "DEACTIVATED_PRINCIPAL_COLLECTION_ACCESS";
  return "UNAUTHORIZED_COLLECTION_MEMBERSHIP";
}

function authProfileForObservation(context: ScanContext, observation: CollectionAuthorizationObservation) {
  if (!observation.authSlot || !context.options.authProfileSet) return undefined;
  return observation.authSlot === "account_a" ? context.options.authProfileSet.accountA : context.options.authProfileSet.accountB;
}

function findKnownObject(context: ScanContext, collection: CollectionAuthorizationDefinitionPlan, casePlan: CollectionAuthorizationCasePlan): KnownCollectionObjectPlan | undefined {
  return context.options.plan.collectionAuthorizationTesting?.collections.find((candidate) => candidate.id === collection.id)?.knownObjects.find((knownObject) => knownObject.id === casePlan.knownObjectId);
}

function entriesAtPath(parsed: unknown, path: string | undefined): readonly unknown[] | undefined {
  if (!path) return Array.isArray(parsed) ? parsed : undefined;
  if (!isRecord(parsed)) return undefined;
  const value = valueAtSafePath(parsed, parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "COLLECTION_AUTHORIZATION_FIELD_PATH_INVALID" })).value;
  return Array.isArray(value) ? value : undefined;
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

function scalarAtPath(source: Record<string, unknown>, path: string): string | undefined {
  const value = scalarUnknownAtPath(source, path);
  if (typeof value === "string") {
    const normalized = value.trim();
    return normalized && normalized.length <= 256 && !/[\r\n\0]/.test(normalized) ? normalized : undefined;
  }
  return undefined;
}

function scalarAtSafePath(source: Record<string, unknown>, segments: ReturnType<typeof parseSafeFieldPath>): string | undefined {
  const value = valueAtSafePath(source, segments).value;
  if (typeof value === "string") {
    const normalized = value.trim();
    return normalized && normalized.length <= 256 && !/[\r\n\0]/.test(normalized) ? normalized : undefined;
  }
  return undefined;
}

function scalarUnknownAtPath(source: Record<string, unknown>, path: string): unknown {
  return valueAtSafePath(source, parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "COLLECTION_AUTHORIZATION_FIELD_PATH_INVALID" })).value;
}

function scalarSummaryAtPath(source: Record<string, unknown>, path: string): string | number | boolean | null | undefined {
  const value = scalarUnknownAtPath(source, path);
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null ? value : undefined;
}

function hashScalarAtPath(source: Record<string, unknown>, path: string, purpose: string): string | undefined {
  const value = scalarAtPath(source, path);
  return value ? hashValue(value, purpose) : undefined;
}

function redactedPreview(entry: Record<string, unknown>, knownObject: KnownCollectionObjectPlan, maxPreviewLength: number): string {
  const raw = redactBodyPreview(JSON.stringify(entry)).split(knownObject.objectId).join(`<object:${knownObject.objectIdHash}>`);
  return raw.length > maxPreviewLength ? `${raw.slice(0, maxPreviewLength)}...` : raw;
}

function redactObjectId(url: string, objectId: string | undefined, objectIdHash: string | undefined): string {
  if (!objectId || !objectIdHash) return url;
  return url.split(encodeURIComponent(objectId)).join(`<object:${objectIdHash}>`).split(objectId).join(`<object:${objectIdHash}>`);
}

function safetyCategoryFor(response: HttpResponse): CollectionAuthorizationDecisionCategory | undefined {
  if (response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") return "TEST_BLOCKED_BY_SAFETY_POLICY";
  if (response.error?.name === "RequestBudgetExceeded" || response.error?.name === "DuplicateRequestBudgetExceeded") return "BUDGET_EXHAUSTED";
  if (response.error) return "EXECUTION_ERROR";
  return undefined;
}

function matchesContentType(actual: string | undefined, expected: string): boolean {
  return Boolean(actual?.toLowerCase().includes(expected.toLowerCase().split(";")[0] ?? expected.toLowerCase()));
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 300;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function notEvaluated(note: string): MembershipExtraction {
  return { membership: "NOT_EVALUATED", responsePartial: false, notes: [note] };
}

function partialResponseSignals(parsed: unknown, response: HttpResponse, returnedCount: number): string[] {
  const signals: string[] = [];
  if (linkHeaderHasNext(headersForAnalysis(response).link)) signals.push("http-link-next");
  if (isRecord(parsed)) {
    for (const path of ["next", "nextPage", "cursor", "nextCursor", "continuationToken", "links.next", "pageInfo.hasNextPage"]) {
      const value = scalarUnknownAtPath(parsed, path);
      if (value === true || (typeof value === "string" && value.trim()) || (typeof value === "number" && value > 0)) signals.push(path);
    }
    const hasMore = scalarUnknownAtPath(parsed, "hasMore");
    if (hasMore === true) signals.push("hasMore");
    const truncated = scalarUnknownAtPath(parsed, "truncated");
    if (truncated === true) signals.push("truncated");
    const total = numericAtAnyPath(parsed, ["total", "totalCount", "countTotal", "resultCount", "metadata.total", "meta.total", "pagination.total"]);
    if (typeof total === "number" && total > returnedCount) signals.push("total-exceeds-returned");
    const cap = numericAtAnyPath(parsed, ["limit", "pageSize", "metadata.limit", "meta.limit", "pagination.limit"]);
    if (typeof cap === "number" && returnedCount >= cap && typeof total === "number" && total > returnedCount) signals.push("server-side-cap");
  }
  return [...new Set(signals)];
}

function numericAtAnyPath(source: Record<string, unknown>, paths: readonly string[]): number | undefined {
  for (const path of paths) {
    const value = scalarUnknownAtPath(source, path);
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return undefined;
}

function linkHeaderHasNext(value: string | readonly string[] | undefined): boolean {
  const text = typeof value === "string" ? value : value?.join(",") ?? "";
  return /rel="?next"?/i.test(text);
}

function absenceNote(completeness: string): string {
  if (completeness === "COMPLETE_COLLECTION") return "Object was absent from an operator-declared complete collection.";
  if (completeness === "SEARCH_RESULT_SET") return "Object was absent only from this exact operator-supplied search result.";
  if (completeness === "UNKNOWN_COMPLETENESS") return "Object absence is inconclusive because completeness is unknown.";
  return "Object was absent only from this exact fixed result window.";
}

function hashValue(value: string, purpose: string): string {
  return createHash("sha256").update(`routecairn-collection-${purpose}:`).update(value).digest("hex").slice(0, 16);
}
