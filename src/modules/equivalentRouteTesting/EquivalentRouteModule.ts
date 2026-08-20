import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { EquivalentRouteCellPlan, EquivalentRouteSetPlan } from "../../core/planning/ScanPlan.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type {
  EquivalentRouteConfidence,
  EquivalentRouteDecisionCategory,
  EquivalentRouteFindingCategory,
  EquivalentRouteObservation,
  EquivalentRouteReport
} from "../../reports/ReportTypes.js";
import { parseSafeFieldPath, valueAtSafePath } from "../fieldExposureTesting/SafeFieldPath.js";

export class EquivalentRouteModule implements RouteCairnPlugin {
  public readonly name = "equivalent-route-testing";
  public readonly description = "Runs fixed equivalent-route authorization consistency checks.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeEquivalentRouteTesting(context);
    return {
      pluginName: this.name,
      equivalentRouteTesting: report,
      findings: findingsFromReport(report, context),
      notes: report.notes
    };
  }
}

async function executeEquivalentRouteTesting(context: ScanContext): Promise<EquivalentRouteReport> {
  const plan = context.options.plan.equivalentRouteTesting;
  if (!plan) {
    return {
      enabled: false,
      plannedRouteSets: 0,
      plannedRoutes: 0,
      plannedRequests: 0,
      executedRequests: 0,
      confirmedIssues: 0,
      observations: [],
      notes: ["Equivalent route testing skipped because no resolved route-set plan was supplied."]
    };
  }

  const observations: EquivalentRouteObservation[] = [];
  let executedRequests = 0;
  for (const routeSet of plan.routeSets) {
    for (const cell of routeSet.cells) {
      const blockReason = identityBlockReason(context, cell);
      if (blockReason) {
        observations.push(blockedObservation(cell, blockReason));
        continue;
      }
      observations.push(await sendAndClassify(context, routeSet, cell));
      executedRequests += 1;
    }
  }

  const compared = applyRouteComparisons(observations);
  const confirmedIssues = compared.filter((observation) => observation.findingCategory).length;
  return {
    enabled: true,
    plannedRouteSets: plan.routeSets.length,
    plannedRoutes: plan.routeSets.reduce((count, routeSet) => count + routeSet.routes.length, 0),
    plannedRequests: plan.requestMatrix.length,
    executedRequests,
    confirmedIssues,
    observations: compared,
    notes: [
      "Equivalent-route testing executed only route cells resolved before scan execution.",
      "Only GET requests were used; no routes, versions, aliases, actors, methods, endpoints, or objects were discovered.",
      "A successful response is treated as allowed only when configured object identity and state are confirmed independently for that route."
    ]
  };
}

async function sendAndClassify(context: ScanContext, routeSet: EquivalentRouteSetPlan, cell: EquivalentRouteCellPlan): Promise<EquivalentRouteObservation> {
  const route = routeSet.routes.find((candidate) => candidate.id === cell.routeId);
  const response = await context.createHttpClient().send({ url: cell.url, method: "GET", headers: { ...(route?.template.headers ?? {}), ...headersForCell(context, cell) } });
  return classifyResponse(context, cell, response);
}

function headersForCell(context: ScanContext, cell: EquivalentRouteCellPlan): Record<string, string> {
  if (!cell.authSlot) return {};
  const profileSet = context.options.authProfileSet;
  if (!profileSet) return {};
  return cell.authSlot === "account_a" ? authHeadersForProfile(profileSet.accountA) : authHeadersForProfile(profileSet.accountB);
}

function classifyResponse(context: ScanContext, cell: EquivalentRouteCellPlan, response: HttpResponse): EquivalentRouteObservation {
  const base = observationBase(cell, response);
  const safety = safetyCategoryFor(response);
  if (safety) return finalize({ ...base, observedDecision: safety, matchedExpectation: matchesExpectation(cell.expectedDecision, safety), notes: ["Request was blocked or failed before comparable route access could be established."] });
  if (response.statusCode === 429) return finalize({ ...base, observedDecision: "RATE_LIMITED", matchedExpectation: false, notes: ["Rate limiting is not treated as denial."] });
  if (response.statusCode === 401) return finalize({ ...base, observedDecision: "AUTHENTICATION_REQUIRED", matchedExpectation: matchesExpectation(cell.expectedDecision, "AUTHENTICATION_REQUIRED"), notes: ["Response required authentication."] });
  if (response.statusCode === 403) return finalize({ ...base, observedDecision: "ACCESS_DENIED_CONFIRMED", matchedExpectation: matchesExpectation(cell.expectedDecision, "ACCESS_DENIED_CONFIRMED"), notes: ["Response denied access."] });
  if (response.statusCode === 404) return finalize({ ...base, observedDecision: "OBJECT_NOT_FOUND", matchedExpectation: matchesExpectation(cell.expectedDecision, "OBJECT_NOT_FOUND"), notes: ["Response returned not found."] });
  if (!isSuccessful(response)) return finalize({ ...base, observedDecision: "INCONCLUSIVE", matchedExpectation: false, notes: ["Unexpected status code could not establish access decision."] });
  if ((response.contentLength ?? 0) > context.options.plan.equivalentRouteTesting!.maxResponseBytes) return finalize({ ...base, observedDecision: "RESPONSE_TOO_LARGE", matchedExpectation: false, notes: ["Response exceeded configured equivalent-route size limit."] });
  const analysisBody = bodyPreviewForAnalysis(response) ?? "";
  if (/login|sign in|required to log in/i.test(analysisBody)) return finalize({ ...base, observedDecision: "SOFT_DENIAL", matchedExpectation: false, notes: ["Response body looked like a login or denial page."] });
  if (!matchesContentType(response.contentType, cell.expectedContentType)) return finalize({ ...base, observedDecision: "RESPONSE_NOT_PARSEABLE", matchedExpectation: false, notes: ["Response did not match the expected JSON content type."] });

  const parsed = parseJsonObject(analysisBody);
  if (!parsed) return finalize({ ...base, observedDecision: "RESPONSE_NOT_PARSEABLE", matchedExpectation: false, notes: ["Response body was not a JSON object."] });
  const objectSource = objectEnvelope(parsed, cell);
  if (!objectSource) return finalize({ ...base, observedDecision: "OBJECT_IDENTITY_MISMATCH", objectIdentityConfirmed: false, matchedExpectation: false, notes: ["Configured response envelope path was missing or not an object."] });
  const objectId = scalarAtPath(objectSource, cell.objectIdentityField);
  if (!objectId || objectId !== cell.objectId) return finalize({ ...base, observedDecision: "OBJECT_IDENTITY_MISMATCH", objectIdentityConfirmed: false, matchedExpectation: false, notes: ["Configured object identity field did not match the supplied object ID."] });
  if (cell.expectedObjectState && cell.objectStateField) {
    const objectState = scalarAtPath(objectSource, cell.objectStateField);
    if (!objectState || objectState !== cell.expectedObjectState) {
      return finalize({ ...base, observedDecision: "OBJECT_STATE_MISMATCH", objectIdentityConfirmed: true, objectStateConfirmed: false, matchedExpectation: false, notes: ["Configured object state field did not match the expected object state."] });
    }
  }

  return finalize({
    ...base,
    observedDecision: cell.expectedDecision === "MUST_REQUIRE_AUTHENTICATION" ? "PUBLIC_REPRESENTATION" : "ACCESS_ALLOWED_CONFIRMED",
    objectIdentityConfirmed: true,
    ...(cell.expectedObjectState ? { objectStateConfirmed: true } : {}),
    matchedExpectation: matchesExpectation(cell.expectedDecision, "ACCESS_ALLOWED_CONFIRMED"),
    notes: ["Configured object identity and state were confirmed for this supplied route."]
  });
}

function observationBase(cell: EquivalentRouteCellPlan, response?: HttpResponse): EquivalentRouteObservation {
  return {
    routeSetId: cell.routeSetId,
    cellId: cell.id,
    actorId: cell.actorId,
    actorRelationship: cell.actorRelationship,
    ...(cell.authSlot ? { authSlot: cell.authSlot } : {}),
    routeId: cell.routeId,
    routeLabel: cell.routeLabel,
    routeCategory: cell.routeCategory,
    isCanonical: cell.isCanonical,
    canonicalRouteId: cell.canonicalRouteId,
    ...(cell.referenceRouteId ? { referenceRouteId: cell.referenceRouteId } : {}),
    objectType: cell.objectType,
    objectIdHash: cell.objectIdHash,
    method: "GET",
    url: redactObjectId(response?.finalUrl || cell.url, cell.objectId, cell.objectIdHash),
    equivalencePolicy: cell.equivalencePolicy,
    expectedDecision: cell.expectedDecision,
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

function blockedObservation(cell: EquivalentRouteCellPlan, reason: string): EquivalentRouteObservation {
  return {
    ...observationBase(cell),
    observedDecision: "IDENTITY_REQUIREMENT_UNSATISFIED",
    matchedExpectation: false,
    notes: [`Equivalent route cell blocked before execution: ${reason}`, "Verified identity requirements were not downgraded to declared-only metadata."]
  };
}

function identityBlockReason(context: ScanContext, cell: EquivalentRouteCellPlan): string | undefined {
  if (!cell.requireVerifiedIdentity || !cell.authSlot) return undefined;
  const report = context.state.getIdentityVerification();
  const result = cell.authSlot === "account_a" ? report?.accountA : report?.accountB;
  if (!result?.verified) return `${cell.authSlot} required verified identity but result was ${result?.category ?? "missing"}.`;
  if (cell.expectedTenantHash && !result.tenantHash) return `${cell.authSlot} required verified tenant metadata.`;
  if (cell.expectedRoleHash && !result.roleHash) return `${cell.authSlot} required verified role metadata.`;
  if (cell.expectedAccountStateHash && !result.accountStateHash) return `${cell.authSlot} required verified account-state metadata.`;
  if (report?.accountA?.verified && report.accountB?.verified && report.accountA.principalHash === report.accountB.principalHash) return "Account A and Account B resolved to the same verified principal.";
  return undefined;
}

function applyRouteComparisons(observations: EquivalentRouteObservation[]): EquivalentRouteObservation[] {
  const byCell = new Map(observations.map((observation) => [`${observation.routeSetId}:${observation.routeId}:${observation.actorId}`, observation]));
  return observations.map((observation) => {
    if (observation.isCanonical || observation.observedDecision !== "ACCESS_ALLOWED_CONFIRMED") return withComparisonExpectation(observation, byCell);
    const referenceRouteId = observation.referenceRouteId ?? canonicalRouteIdFor(observation, observations);
    const reference = referenceRouteId ? byCell.get(`${observation.routeSetId}:${referenceRouteId}:${observation.actorId}`) : undefined;
    const comparable = reference && isProtectedBoundary(reference) && violatesNoGreaterAccess(observation);
    if (!comparable) return withComparisonExpectation(observation, byCell);
    const findingCategory = findingCategoryFor(observation);
    return finalize({
      ...observation,
      matchedExpectation: false,
      comparisonRouteId: reference.routeId,
      findingCategory,
      notes: [...observation.notes, `Alternate route exceeded the protected boundary enforced by reference route ${reference.routeLabel}.`]
    });
  });
}

function withComparisonExpectation(observation: EquivalentRouteObservation, byCell: Map<string, EquivalentRouteObservation>): EquivalentRouteObservation {
  if (observation.expectedDecision !== "MUST_MATCH_CANONICAL_DECISION" && observation.expectedDecision !== "MUST_MATCH_REFERENCE_ROUTE" && observation.expectedDecision !== "MUST_NOT_EXCEED_CANONICAL_ACCESS" && observation.expectedDecision !== "MUST_NOT_EXCEED_PUBLIC_ACCESS") return observation;
  const referenceRouteId = observation.referenceRouteId ?? (observation.expectedDecision.includes("CANONICAL") ? observation.canonicalRouteId : undefined);
  const reference = referenceRouteId ? byCell.get(`${observation.routeSetId}:${referenceRouteId}:${observation.actorId}`) : undefined;
  if (!reference) return { ...observation, matchedExpectation: false, confidence: "INCONCLUSIVE", notes: [...observation.notes, "Reference route result was unavailable."] };
  const matched = observation.expectedDecision.includes("MATCH") ? observation.observedDecision === reference.observedDecision : !isAllowed(observation.observedDecision) || isAllowed(reference.observedDecision);
  return { ...observation, matchedExpectation: matched, confidence: matched ? "HIGH" : "MEDIUM", comparisonRouteId: reference.routeId, notes: [...observation.notes, `Compared with reference route ${reference.routeLabel}.`] };
}

function canonicalRouteIdFor(observation: EquivalentRouteObservation, observations: readonly EquivalentRouteObservation[]): string | undefined {
  return observations.find((candidate) => candidate.routeSetId === observation.routeSetId && candidate.actorId === observation.actorId && candidate.isCanonical)?.routeId;
}

function isProtectedBoundary(observation: EquivalentRouteObservation): boolean {
  return observation.observedDecision === "ACCESS_DENIED_CONFIRMED" || observation.observedDecision === "AUTHENTICATION_REQUIRED" || observation.observedDecision === "OBJECT_NOT_FOUND" || observation.observedDecision === "SOFT_DENIAL";
}

function violatesNoGreaterAccess(observation: EquivalentRouteObservation): boolean {
  return observation.expectedDecision === "MUST_DENY" || observation.expectedDecision === "MUST_NOT_EXCEED_CANONICAL_ACCESS" || observation.expectedDecision === "MUST_NOT_EXCEED_PUBLIC_ACCESS" || observation.expectedDecision === "MUST_MATCH_CANONICAL_DECISION" || observation.expectedDecision === "MUST_MATCH_REFERENCE_ROUTE";
}

function finalize(observation: EquivalentRouteObservation): EquivalentRouteObservation {
  return { ...observation, confidence: confidenceFor(observation) };
}

function matchesExpectation(expected: EquivalentRouteObservation["expectedDecision"], observed: EquivalentRouteDecisionCategory): boolean {
  if (expected === "MUST_ALLOW") return observed === "ACCESS_ALLOWED_CONFIRMED" || observed === "PUBLIC_REPRESENTATION";
  if (expected === "MUST_DENY") return isProtectedBoundary({ observedDecision: observed } as EquivalentRouteObservation);
  if (expected === "MUST_REQUIRE_AUTHENTICATION") return observed === "AUTHENTICATION_REQUIRED" || observed === "LOGIN_REDIRECT";
  if (expected === "MUST_RETURN_NOT_FOUND") return observed === "OBJECT_NOT_FOUND";
  if (expected === "OBSERVE_ONLY") return true;
  return false;
}

function findingCategoryFor(observation: EquivalentRouteObservation): EquivalentRouteFindingCategory {
  if (observation.equivalencePolicy === "SAME_TENANT_BOUNDARY" || observation.actorRelationship.includes("CROSS_TENANT")) return "CROSS_TENANT_ROUTE_INCONSISTENCY";
  if (observation.equivalencePolicy === "SAME_ROLE_BOUNDARY") return "ROLE_BOUNDARY_ROUTE_INCONSISTENCY";
  if (observation.equivalencePolicy === "SAME_STATE_BOUNDARY") return "OBJECT_STATE_ROUTE_INCONSISTENCY";
  if (/SUSPENDED|ACTIVE/i.test(observation.actorRelationship)) return "ACCOUNT_STATE_ROUTE_INCONSISTENCY";
  if (observation.routeCategory === "LEGACY") return "LEGACY_ROUTE_AUTHORIZATION_BYPASS";
  if (observation.routeCategory === "VERSIONED") return "VERSIONED_ROUTE_AUTHORIZATION_BYPASS";
  if (observation.routeCategory === "NESTED") return "NESTED_ROUTE_AUTHORIZATION_BYPASS";
  if (observation.routeCategory === "EXPORT" || observation.routeCategory === "ALTERNATE_FORMAT") return "EXPORT_ROUTE_AUTHORIZATION_BYPASS";
  if (observation.routeCategory === "ALIAS" || observation.routeCategory === "COMPATIBILITY") return "ALIAS_ROUTE_AUTHORIZATION_BYPASS";
  if (observation.routeCategory === "MOBILE") return "MOBILE_ROUTE_AUTHORIZATION_BYPASS";
  return "ALTERNATE_ROUTE_AUTHORIZATION_BYPASS";
}

function confidenceFor(observation: EquivalentRouteObservation): EquivalentRouteConfidence {
  if (observation.findingCategory && observation.objectIdentityConfirmed && observation.objectStateConfirmed !== false) return "CONFIRMED";
  if (observation.matchedExpectation) return "HIGH";
  if (observation.observedDecision === "ACCESS_ALLOWED_CONFIRMED") return "HIGH";
  if (observation.observedDecision === "INCONCLUSIVE") return "INCONCLUSIVE";
  return "MEDIUM";
}

function findingsFromReport(report: EquivalentRouteReport, context: ScanContext): Finding[] {
  const riskScorer = new RiskScorer();
  return report.observations.filter(hasFindingCategory).map((observation) => ({
    id: `equivalent-route-${observation.routeSetId}-${observation.routeId}-${observation.actorId}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(),
    title: `Equivalent route authorization issue: ${observation.findingCategory}`,
    type: "Equivalent Route Authorization Issue" as const,
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
      source: `Equivalent route set ${observation.routeSetId}; actor=${observation.actorId}; alternate=${observation.routeLabel}; reference=${observation.comparisonRouteId ?? "canonical"}; expected=${observation.expectedDecision}; observed=${observation.observedDecision}; objectHash=${observation.objectIdHash}; auth material redacted.`,
      severityReason: "A supplied alternate route returned the protected object after the supplied canonical/reference route enforced the configured denial boundary.",
      reproductionNotes: [
        "Use only the supplied route set, actor, route templates, and object ID.",
        "Confirm the declared route equivalence policy with the application owner.",
        "Repeat the redacted canonical/reference request and then the redacted alternate route request with the same actor authorization context."
      ]
    },
    impact: "A protected object may be accessible through an equivalent route even though the canonical or reference route enforces the configured authorization boundary.",
    recommendation: "Apply one centralized authorization policy across canonical, legacy, versioned, nested, export, mobile, alias, and compatibility routes that expose the same protected object.",
    manualTestingSuggestions: ["Verify the configured route equivalence is correct.", "Check whether a documented public, tenant, role, sharing, or state policy explains the alternate route access.", "Add negative tests for this exact actor, object, and route pair."],
    tags: ["equivalent-route", "access-control", "needs-manual-verification", observation.findingCategory.toLowerCase().replace(/_/g, "-")],
    riskScore: riskScorer.score({ severity: "High", confidence: "High", falsePositiveStatus: "likely-valid", tags: ["equivalent-route", "access-control"] }),
    sourceModule: "equivalent-route-testing",
    falsePositiveStatus: "likely-valid" as const,
    timestamp: new Date().toISOString()
  }));
}

function hasFindingCategory(observation: EquivalentRouteObservation): observation is EquivalentRouteObservation & { findingCategory: EquivalentRouteFindingCategory } {
  return Boolean(observation.findingCategory);
}

function authProfileForObservation(context: ScanContext, observation: EquivalentRouteObservation) {
  if (!observation.authSlot || !context.options.authProfileSet) return undefined;
  return observation.authSlot === "account_a" ? context.options.authProfileSet.accountA : context.options.authProfileSet.accountB;
}

function safetyCategoryFor(response: HttpResponse): EquivalentRouteDecisionCategory | undefined {
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

function objectEnvelope(source: Record<string, unknown>, cell: EquivalentRouteCellPlan): Record<string, unknown> | undefined {
  if (!cell.responseEnvelopePath) return source;
  const extracted = valueAtSafePath(source, parseSafeFieldPath(cell.responseEnvelopePath, { maxDepth: 8, maxArrayIndex: 50, code: "EQUIVALENT_ROUTE_OBJECT_FIELD_INVALID" }));
  return typeof extracted.value === "object" && extracted.value !== null && !Array.isArray(extracted.value) ? (extracted.value as Record<string, unknown>) : undefined;
}

function scalarAtPath(source: Record<string, unknown>, path: string): string | undefined {
  const extracted = valueAtSafePath(source, parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "EQUIVALENT_ROUTE_OBJECT_FIELD_INVALID" }));
  if (typeof extracted.value === "string" || typeof extracted.value === "number") return String(extracted.value);
  return undefined;
}

function matchesContentType(actual: string | undefined, expected: string): boolean {
  if (!actual) return false;
  return actual.toLowerCase().includes(expected.toLowerCase().split(";")[0] ?? expected.toLowerCase());
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 300;
}

function isAllowed(decision: EquivalentRouteDecisionCategory): boolean {
  return decision === "ACCESS_ALLOWED_CONFIRMED" || decision === "PUBLIC_REPRESENTATION";
}

function redactObjectId(url: string, objectId: string, objectIdHash: string): string {
  return url.split(encodeURIComponent(objectId)).join(`<object:${objectIdHash}>`).split(objectId).join(`<object:${objectIdHash}>`);
}
