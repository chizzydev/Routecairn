import { lookup } from "node:dns/promises";
import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { FileAuthorizationCasePlan } from "../../core/planning/ScanPlan.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { FileAuthorizationDecisionCategory, FileAuthorizationFindingCategory, FileAuthorizationObservation, FileAuthorizationReport } from "../../reports/ReportTypes.js";
import { isProhibitedAddress } from "../browserCrawler/BrowserPolicy.js";
import { parseSafeFieldPath, valueAtSafePath } from "../fieldExposureTesting/SafeFieldPath.js";

export class FileAuthorizationModule implements RouteCairnPlugin {
  public readonly name = "file-authorization-testing";
  public readonly description = "Runs fixed file metadata, preview, download, and signed-URL authorization checks.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeFileAuthorization(context);
    return { pluginName: this.name, fileAuthorization: report, findings: findingsFromReport(report, context), notes: report.notes };
  }
}

async function executeFileAuthorization(context: ScanContext): Promise<FileAuthorizationReport> {
  const plan = context.options.plan.fileAuthorizationTesting;
  if (!plan) return { enabled: false, plannedDefinitions: 0, plannedCases: 0, plannedRequests: 0, executedRequests: 0, confirmedIssues: 0, observations: [], notes: ["File authorization skipped because no resolved file plan was supplied."] };
  const observations: FileAuthorizationObservation[] = [];
  let executedRequests = 0;
  outer: for (const definition of plan.definitions) {
    for (const casePlan of definition.cases) {
      if (observations.length >= plan.maxRetainedObservations) break outer;
      const blockReason = identityBlockReason(context, casePlan);
      if (blockReason) {
        observations.push(baseObservation(casePlan, "IDENTITY_REQUIREMENT_UNSATISFIED", undefined, [`File case blocked before execution: ${blockReason}`]));
        continue;
      }
      const streamLimit = streamLimitFor(casePlan);
      const response = await context.createHttpClient().send({
        url: casePlan.url,
        method: casePlan.method,
        headers: { "Accept-Encoding": "identity", ...casePlan.headers, ...headersForCase(context, casePlan) },
        skipCache: true,
        disableRetries: true,
        ...(streamLimit ? { streamLimitBytes: streamLimit, retainBodyPreview: false, ...(casePlan.contentProofMode === "FULL_STREAM_FINGERPRINT" ? { maxStreamContentLength: streamLimit } : {}) } : {})
      });
      executedRequests += 1;
      const classification = await classifyResponse(context, casePlan, response);
      executedRequests += classification.executedRequests;
      observations.push(classification.observation);
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
      "File authorization executed only resolved GET or HEAD cases for exact supplied file references.",
      "Content evidence is bounded and fingerprint-only; no file bytes are persisted, opened, rendered, extracted, or executed.",
      "No file IDs, URLs, ranges, links, endpoints, directories, buckets, or follow-up cases were generated at runtime."
    ]
  };
}

async function classifyResponse(context: ScanContext, casePlan: FileAuthorizationCasePlan, response: HttpResponse): Promise<{ observation: FileAuthorizationObservation; executedRequests: number }> {
  const safety = safetyCategoryFor(response);
  if (safety) return resultOf(baseObservation(casePlan, safety, response, ["Request was blocked or failed before file authorization could be evaluated."]));
  if (response.statusCode === 429) return resultOf(baseObservation(casePlan, "RATE_LIMITED", response, ["Rate limiting is not treated as denial."]));
  if (response.statusCode === 401) return resultOf(finalize(baseObservation(casePlan, "AUTHENTICATION_REQUIRED", response, ["Response required authentication."])));
  if (response.statusCode === 403) return resultOf(finalize(baseObservation(casePlan, "ACCESS_DENIED_CONFIRMED", response, ["Response denied access."])));
  if (response.statusCode === 404) return resultOf(finalize(baseObservation(casePlan, "FILE_NOT_FOUND", response, ["Response returned not found."])));
  if (casePlan.contentProofMode === "BOUNDED_PREFIX" && response.statusCode === 416) return resultOf(finalize(baseObservation(casePlan, "RANGE_NOT_SATISFIABLE", response, ["Server returned 416 for the exact configured bounded range."])));
  if (!isSuccessful(response)) return resultOf(baseObservation(casePlan, "INCONCLUSIVE", response, ["Unexpected status code could not establish file access."]));

  if (casePlan.contentProofMode === "HEADERS_ONLY" || casePlan.method === "HEAD") {
    return resultOf(finalize({ ...baseObservation(casePlan, "HEADERS_ONLY_OBSERVATION", response, ["Headers-only evidence cannot confirm file content exposure."]), identityConfirmed: identityConfirmedFromHeaders(casePlan, response) }));
  }
  if (casePlan.contentProofMode === "METADATA_ONLY") return resultOf(classifyMetadata(casePlan, response));
  if (casePlan.contentProofMode === "SIGNED_URL_ONLY") return classifySignedUrl(context, casePlan, response);
  if (response.error?.name === "DeclaredContentLengthExceeded") return resultOf(baseObservation(casePlan, "DECLARED_CONTENT_LENGTH_EXCEEDS_LIMIT", response, ["Content-Length exceeded configured stream cap before body streaming."]));
  if ((response.contentLength ?? 0) > casePlan.maxFullStreamBytes && casePlan.contentProofMode === "FULL_STREAM_FINGERPRINT") return resultOf(baseObservation(casePlan, "DECLARED_CONTENT_LENGTH_EXCEEDS_LIMIT", response, ["Content-Length exceeded configured full-stream cap."]));
  const identityConfirmed = identityConfirmedFromContent(casePlan, response);
  const rangeValidation = validateRangeResponse(casePlan, response);
  const observedDecision = casePlan.category === "FILE_PREVIEW" || casePlan.category === "THUMBNAIL" ? "PREVIEW_ACCESS_CONFIRMED" : "CONTENT_ACCESS_CONFIRMED";
  if (rangeValidation) return resultOf(finalize({ ...baseObservation(casePlan, rangeValidation.decision, response, rangeValidation.notes), identityConfirmed: false }));
  if (response.rangeIgnored && !identityConfirmed) return resultOf(finalize({ ...baseObservation(casePlan, "RANGE_IGNORED_STREAM_ABORTED", response, ["Server ignored the Range request; stream was bounded and aborted at the probe cap."]), identityConfirmed }));
  if (response.rangeIgnored && identityConfirmed) return resultOf(finalize({ ...baseObservation(casePlan, observedDecision, response, ["Server ignored Range; RouteCairn aborted after the configured probe cap. This is bounded prefix evidence, not complete-file proof."]), identityConfirmed }));
  if (response.streamTruncated && casePlan.contentProofMode === "BOUNDED_PREFIX") return resultOf(baseObservation(casePlan, "STREAM_LIMIT_EXCEEDED", response, ["Bounded range response exceeded the configured probe cap and was aborted."]));
  if (response.streamTruncated && casePlan.contentProofMode === "FULL_STREAM_FINGERPRINT") return resultOf(baseObservation(casePlan, "STREAM_LIMIT_EXCEEDED", response, ["Content stream exceeded the configured full-stream cap."]));
  return resultOf(finalize({ ...baseObservation(casePlan, observedDecision, response, [casePlan.contentProofMode === "BOUNDED_PREFIX" ? "Only a bounded prefix fingerprint was observed; this is not complete-file proof." : "The complete stream was fingerprinted within the configured cap."]), identityConfirmed }));
}

function classifyMetadata(casePlan: FileAuthorizationCasePlan, response: HttpResponse): FileAuthorizationObservation {
  if ((response.contentLength ?? 0) > casePlan.maxMetadataBytes) return baseObservation(casePlan, "RESPONSE_TOO_LARGE", response, ["Metadata response exceeded configured size."]);
  if (!matchesContentType(response.contentType, "application/json")) return baseObservation(casePlan, "RESPONSE_NOT_PARSEABLE", response, ["Metadata response was not JSON."]);
  const parsed = parseJson(bodyPreviewForAnalysis(response) ?? "");
  if (!parsed || !isRecord(parsed)) return baseObservation(casePlan, "RESPONSE_NOT_PARSEABLE", response, ["Metadata response was not a bounded JSON object."]);
  const identityConfirmed = casePlan.identityField ? scalarAt(parsed, casePlan.identityField) === casePlan.fileRef : false;
  if (casePlan.expectedFileState && casePlan.stateField) {
    const state = scalarAt(parsed, casePlan.stateField);
    if (state !== casePlan.expectedFileState) return finalize({ ...baseObservation(casePlan, "FILE_STATE_MISMATCH", response, ["Configured file state did not match."]), identityConfirmed });
  }
  return finalize({ ...baseObservation(casePlan, identityConfirmed ? "METADATA_ACCESS_CONFIRMED" : "FILE_IDENTITY_UNCONFIRMED", response, ["Metadata response was evaluated using configured identity fields."]), identityConfirmed });
}

async function classifySignedUrl(context: ScanContext, casePlan: FileAuthorizationCasePlan, response: HttpResponse): Promise<{ observation: FileAuthorizationObservation; executedRequests: number }> {
  if (!matchesContentType(response.contentType, "application/json")) return resultOf(baseObservation(casePlan, "RESPONSE_NOT_PARSEABLE", response, ["Signed-URL response was not JSON."]));
  const parsed = parseJson(bodyPreviewForAnalysis(response) ?? "");
  const signed = parsed && isRecord(parsed) && casePlan.signedUrlField ? scalarAt(parsed, casePlan.signedUrlField) : undefined;
  if (!signed) return resultOf(finalize(baseObservation(casePlan, "FILE_IDENTITY_UNCONFIRMED", response, ["Configured signed URL field was missing."])));
  const destination = await signedUrlDestinationDecision(signed, casePlan.allowedSignedUrlOrigins, casePlan.followSignedUrl);
  const issuance = { ...baseObservation(casePlan, destination.allowed ? "SIGNED_URL_EXPOSED" : "SIGNED_URL_ORIGIN_BLOCKED", response, [destination.allowed ? "The actor received a signed URL for the supplied file." : destination.reason]), identityConfirmed: true, signedUrlObserved: true };
  if (!destination.allowed) return resultOf(finalize(issuance));
  if (!casePlan.followSignedUrl) {
    return resultOf(finalize({ ...issuance, observedDecision: "SIGNED_URL_FOLLOW_NOT_CONFIGURED", notes: [...issuance.notes, "The signed URL was not followed because followSignedUrl was not enabled."] }));
  }

  const followResponse = await context.createHttpClient().send({
    url: signed,
    method: "GET",
    headers: { "Accept-Encoding": "identity" },
    skipCache: true,
    disableRetries: true,
    streamLimitBytes: casePlan.maxProbeBytes,
    maxStreamContentLength: casePlan.maxProbeBytes,
    retainBodyPreview: false
  });
  const followSafety = safetyCategoryFor(followResponse);
  if (followSafety) {
    return observedResult(finalize({ ...issuance, observedDecision: "SIGNED_URL_FOLLOW_INCONCLUSIVE", signedUrlFollowed: true, bytesObserved: followResponse.bytesRead ?? 0, streamTruncated: Boolean(followResponse.streamTruncated), ...(typeof followResponse.statusCode === "number" ? { statusCode: followResponse.statusCode } : {}), notes: [...issuance.notes, "The one-time signed URL follow was blocked or failed under the shared request broker."] }), 1);
  }
  if (followResponse.statusCode === 401 || followResponse.statusCode === 403 || followResponse.statusCode === 404) {
    return observedResult(finalize({ ...issuance, observedDecision: "SIGNED_URL_DOWNLOAD_DENIED", signedUrlFollowed: true, statusCode: followResponse.statusCode, bytesObserved: followResponse.bytesRead ?? 0, notes: [...issuance.notes, "The signed URL was followed once and denied."] }), 1);
  }
  if (!isSuccessful(followResponse) || !followResponse.bodyHash) {
    return observedResult(finalize({ ...issuance, observedDecision: "SIGNED_URL_FOLLOW_INCONCLUSIVE", signedUrlFollowed: true, ...(typeof followResponse.statusCode === "number" ? { statusCode: followResponse.statusCode } : {}), bytesObserved: followResponse.bytesRead ?? 0, notes: [...issuance.notes, "The signed URL follow did not return a usable bounded content response."] }), 1);
  }
  const matches = identityConfirmedFromContent(casePlan, followResponse);
  return observedResult(finalize({
    ...issuance,
    observedDecision: matches ? "SIGNED_URL_DOWNLOAD_ALLOWED" : "SIGNED_URL_FILE_IDENTITY_MISMATCH",
    signedUrlFollowed: true,
    identityConfirmed: matches,
    ...(typeof followResponse.statusCode === "number" ? { statusCode: followResponse.statusCode } : {}),
    bytesObserved: followResponse.bytesRead ?? 0,
    streamTruncated: Boolean(followResponse.streamTruncated),
    bodyHash: followResponse.bodyHash,
    ...(followResponse.contentType ? { contentType: followResponse.contentType } : {}),
    ...(typeof followResponse.contentLength === "number" ? { contentLength: followResponse.contentLength } : {}),
    notes: [...issuance.notes, matches ? "The signed URL returned the configured bounded file fingerprint." : "The signed URL returned content that did not match the configured file fingerprint."]
  }), 1);
}

function resultOf(observation: FileAuthorizationObservation): { observation: FileAuthorizationObservation; executedRequests: number } {
  return { observation, executedRequests: 0 };
}

function observedResult(observation: FileAuthorizationObservation, executedRequests = 0): { observation: FileAuthorizationObservation; executedRequests: number } {
  return { observation, executedRequests };
}

function finalize(observation: FileAuthorizationObservation): FileAuthorizationObservation {
  const findingCategory = findingCategoryFor(observation);
  return {
    ...observation,
    ...(findingCategory ? { findingCategory } : {}),
    confidence: findingCategory ? "CONFIRMED" : observation.observedDecision === "INCONCLUSIVE" ? "INCONCLUSIVE" : "HIGH"
  };
}

function findingCategoryFor(observation: FileAuthorizationObservation): FileAuthorizationFindingCategory | undefined {
  if (observation.expectedDecision === "OBSERVE_ONLY") return undefined;
  if (!observation.identityConfirmed && observation.contentProofMode !== "SIGNED_URL_ONLY") return undefined;
  const denial = ["MUST_DENY_METADATA", "MUST_DENY_CONTENT", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "MUST_NOT_RECEIVE_SIGNED_URL"];
  if (!denial.includes(observation.expectedDecision)) return undefined;
  if (observation.observedDecision === "METADATA_ACCESS_CONFIRMED") return observation.actorRelationship === "PUBLIC" ? "PUBLIC_PRIVATE_FILE_ACCESS" : "UNAUTHORIZED_FILE_METADATA_ACCESS";
  if (observation.observedDecision === "CONTENT_ACCESS_CONFIRMED") return observation.actorRelationship.includes("CROSS_TENANT") ? "CROSS_TENANT_FILE_ACCESS" : "UNAUTHORIZED_FILE_CONTENT_ACCESS";
  if (observation.observedDecision === "PREVIEW_ACCESS_CONFIRMED") return "PREVIEW_OR_THUMBNAIL_AUTHORIZATION_BYPASS";
  if (observation.observedDecision === "SIGNED_URL_EXPOSED" || observation.observedDecision === "SIGNED_URL_FOLLOW_NOT_CONFIGURED") return "UNAUTHORIZED_SIGNED_URL_ISSUANCE";
  if (observation.observedDecision === "SIGNED_URL_DOWNLOAD_ALLOWED") return "UNAUTHORIZED_SIGNED_URL_DOWNLOAD";
  return undefined;
}

function baseObservation(casePlan: FileAuthorizationCasePlan, observedDecision: FileAuthorizationDecisionCategory, response: HttpResponse | undefined, notes: string[]): FileAuthorizationObservation {
  const dispositionClass = contentDispositionClass(response);
  return {
    definitionId: casePlan.definitionId,
    caseId: casePlan.id,
    label: casePlan.label,
    category: casePlan.category,
    actorId: casePlan.actorId,
    actorRelationship: casePlan.actorRelationship,
    ...(casePlan.authSlot ? { authSlot: casePlan.authSlot } : {}),
    fileAlias: casePlan.fileAlias,
    fileRefHash: casePlan.fileRefHash,
    method: casePlan.method,
    url: redactFileRef(response?.finalUrl ?? casePlan.url, casePlan),
    expectedDecision: casePlan.expectedDecision,
    observedDecision,
    identityStrategy: casePlan.identityStrategy,
    identityConfirmed: false,
    contentProofMode: casePlan.contentProofMode,
    bytesObserved: response?.bytesRead ?? 0,
    streamTruncated: Boolean(response?.streamTruncated),
    rangeIgnored: Boolean(response?.rangeIgnored),
    signedUrlObserved: false,
    signedUrlFollowed: false,
    ...(typeof response?.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response?.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response?.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(dispositionClass ? { contentDispositionClass: dispositionClass } : {}),
    ...(response?.bodyHash ? { bodyHash: response.bodyHash } : {}),
    confidence: observedDecision === "INCONCLUSIVE" ? "INCONCLUSIVE" : "MEDIUM",
    ...(response?.error ? { error: response.error.message } : {}),
    notes
  };
}

function headersForCase(context: ScanContext, casePlan: FileAuthorizationCasePlan): Record<string, string> {
  if (!casePlan.authSlot || !context.options.authProfileSet) return {};
  return casePlan.authSlot === "account_a" ? authHeadersForProfile(context.options.authProfileSet.accountA) : authHeadersForProfile(context.options.authProfileSet.accountB);
}

function identityBlockReason(context: ScanContext, casePlan: FileAuthorizationCasePlan): string | undefined {
  if (!casePlan.requireVerifiedIdentity || !casePlan.authSlot) return undefined;
  const report = context.state.getIdentityVerification();
  const result = casePlan.authSlot === "account_a" ? report?.accountA : report?.accountB;
  if (!result?.verified) return `${casePlan.authSlot} required verified identity but result was ${result?.category ?? "missing"}.`;
  if (casePlan.expectedTenantHash && result.tenantHash !== casePlan.expectedTenantHash) return `${casePlan.authSlot} verified tenant metadata did not match.`;
  if (casePlan.expectedRoleHash && result.roleHash !== casePlan.expectedRoleHash) return `${casePlan.authSlot} verified role metadata did not match.`;
  if (casePlan.expectedAccountStateHash && result.accountStateHash !== casePlan.expectedAccountStateHash) return `${casePlan.authSlot} verified account-state metadata did not match.`;
  if (report?.accountA?.verified && report.accountB?.verified && report.accountA.principalHash === report.accountB.principalHash) return "Account A and Account B resolved to the same verified principal.";
  return undefined;
}

function streamLimitFor(casePlan: FileAuthorizationCasePlan): number | undefined {
  if (casePlan.contentProofMode === "BOUNDED_PREFIX") return casePlan.maxProbeBytes;
  if (casePlan.contentProofMode === "FULL_STREAM_FINGERPRINT") return casePlan.maxFullStreamBytes;
  return undefined;
}

function identityConfirmedFromHeaders(casePlan: FileAuthorizationCasePlan, response: HttpResponse): boolean {
  if (casePlan.identityStrategy === "OBSERVE_ONLY") return false;
  if (casePlan.identityStrategy === "OPERATOR_SUPPLIED_FINGERPRINT") return Boolean(response.bodyHash && response.bodyHash.startsWith(casePlan.expectedFingerprint ?? ""));
  return false;
}

function identityConfirmedFromContent(casePlan: FileAuthorizationCasePlan, response: HttpResponse): boolean {
  if (casePlan.identityStrategy === "OPERATOR_SUPPLIED_FINGERPRINT") return Boolean(response.bodyHash && response.bodyHash === casePlan.expectedFingerprint);
  return casePlan.identityStrategy === "OBSERVE_ONLY" ? false : Boolean(response.bodyHash);
}

function findingsFromReport(report: FileAuthorizationReport, context: ScanContext): Finding[] {
  const scorer = new RiskScorer();
  return report.observations.filter((observation): observation is FileAuthorizationObservation & { findingCategory: FileAuthorizationFindingCategory } => Boolean(observation.findingCategory)).map((observation) => ({
    id: `file-authorization-${observation.definitionId}-${observation.caseId}`.replace(/[^a-z0-9_-]/gi, "-").toLowerCase(),
    title: `Controlled file authorization issue: ${observation.findingCategory}`,
    type: "File Authorization Issue" as const,
    severity: "High" as const,
    confidence: "High" as const,
    url: observation.url,
    method: observation.method,
    ...(observation.statusCode ? { statusCode: observation.statusCode } : {}),
    evidence: {
      url: observation.url,
      method: observation.method,
      ...(observation.statusCode ? { statusCode: observation.statusCode } : {}),
      ...(observation.bodyHash ? { bodyHash: observation.bodyHash } : {}),
      ...(observation.contentType ? { contentType: observation.contentType } : {}),
      ...(typeof observation.contentLength === "number" ? { contentLength: observation.contentLength } : {}),
      curlCommand: redactedCurlCommand(observation.url, authProfileForObservation(context, observation)),
      source: `File ${observation.definitionId}/${observation.caseId}; category=${observation.category}; expected=${observation.expectedDecision}; observed=${observation.observedDecision}; fileRefHash=${observation.fileRefHash}; proof=${observation.contentProofMode}; bytesObserved=${observation.bytesObserved}; raw file reference and bytes redacted.`,
      severityReason: "A configured denial boundary was bypassed for an exact supplied file case with bounded evidence.",
      reproductionNotes: ["Use only the supplied actor, endpoint, method, and file reference.", "Do not enumerate, guess, download beyond the configured byte cap, or follow unapproved signed URLs."]
    },
    impact: "A protected file, file metadata, preview, content prefix, or signed URL may be accessible outside the configured authorization policy.",
    recommendation: "Authorize every metadata, preview, download, and signed-URL issuance request server-side using trusted principal, tenant, role, account state, file owner, and file state before returning file data.",
    manualTestingSuggestions: ["Verify the supplied file relationship and expected policy.", "Confirm whether sharing or public visibility intentionally permits this exact access.", "Repeat only the bounded proof request."],
    tags: ["file-authorization", "access-control", observation.findingCategory.toLowerCase().replace(/_/g, "-")],
    riskScore: scorer.score({ severity: "High", confidence: "High", falsePositiveStatus: "likely-valid", tags: ["file-authorization", "access-control"] }),
    workflowCase: { id: `${observation.definitionId}/${observation.caseId}` }, sourceModule: "file-authorization-testing",
    falsePositiveStatus: "likely-valid" as const,
    timestamp: new Date().toISOString()
  }));
}

function safetyCategoryFor(response: HttpResponse): FileAuthorizationDecisionCategory | undefined {
  if (response.error?.name === "RequestBudgetExceeded") return "BUDGET_EXHAUSTED";
  if (response.error?.name === "DeclaredContentLengthExceeded") return "DECLARED_CONTENT_LENGTH_EXCEEDS_LIMIT";
  if (response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") return "TEST_BLOCKED_BY_SAFETY_POLICY";
  if (response.error) return "EXECUTION_ERROR";
  return undefined;
}

function parseJson(body: string): unknown | undefined {
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return undefined;
  }
}

function scalarAt(source: Record<string, unknown>, path: string): string | undefined {
  const value = valueAtSafePath(source, parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "FILE_AUTHORIZATION_FIELD_PATH_INVALID" })).value;
  return typeof value === "string" ? value : undefined;
}

async function signedUrlDestinationDecision(value: string, allowedOrigins: readonly string[], verifyNetworkDestination: boolean): Promise<{ allowed: true } | { allowed: false; reason: string }> {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return { allowed: false, reason: "Signed URL scheme was not http or https." };
    if (!allowedOrigins.includes(url.origin)) return { allowed: false, reason: "Signed URL origin was not explicitly approved." };
    if (!verifyNetworkDestination) return { allowed: true };
    if (isInternalHostname(url.hostname)) return allowedOrigins.includes(url.origin) ? { allowed: true } : { allowed: false, reason: "Signed URL internal hostname was not explicitly approved." };
    if (isProhibitedAddress(url.hostname)) return allowedOrigins.includes(url.origin) ? { allowed: true } : { allowed: false, reason: "Signed URL private destination was not explicitly approved." };
    const addresses = await lookup(url.hostname, { all: true, verbatim: false }).then((results) => results.map((result) => result.address)).catch(() => undefined);
    if (!addresses || addresses.length === 0) return { allowed: false, reason: "Signed URL hostname could not be safely resolved." };
    if (addresses.some((address) => isProhibitedAddress(address))) return allowedOrigins.includes(url.origin) ? { allowed: true } : { allowed: false, reason: "Signed URL resolved to a private or prohibited destination." };
    return { allowed: true };
  } catch {
    return { allowed: false, reason: "Signed URL was not parseable." };
  }
}

function isInternalHostname(hostname: string): boolean {
  const normalized = hostname.replace(/\.$/, "").toLowerCase();
  return normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".local") || normalized.endsWith(".internal") || !normalized.includes(".");
}

function validateRangeResponse(casePlan: FileAuthorizationCasePlan, response: HttpResponse): { decision: FileAuthorizationDecisionCategory; notes: string[] } | undefined {
  if (casePlan.contentProofMode !== "BOUNDED_PREFIX") return undefined;
  if (response.statusCode === 416) return { decision: "RANGE_NOT_SATISFIABLE", notes: ["Server returned 416 for the exact configured bounded range."] };
  if (response.statusCode !== 206) return undefined;
  const contentRange = String(headersForAnalysis(response)["content-range"] ?? "");
  const match = /^bytes (?<start>\d+)-(?<end>\d+)\/(?<total>\d+|\*)$/i.exec(contentRange);
  if (!match?.groups) return { decision: "INVALID_CONTENT_RANGE", notes: ["Server returned 206 without a valid Content-Range header."] };
  const start = Number(match.groups.start);
  const end = Number(match.groups.end);
  if (casePlan.rangeHeader !== `bytes=${start}-${end}`) return { decision: "INVALID_CONTENT_RANGE", notes: ["Server returned a Content-Range that did not match the exact configured request."] };
  return undefined;
}

function contentDispositionClass(response: HttpResponse | undefined): string | undefined {
  const disposition = String(response?.headers["content-disposition"] ?? "");
  if (!disposition) return undefined;
  return /attachment/i.test(disposition) ? "attachment" : /inline/i.test(disposition) ? "inline" : "present";
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

function redactFileRef(url: string, casePlan: FileAuthorizationCasePlan): string {
  return url.split(encodeURIComponent(casePlan.fileRef)).join(`<file:${casePlan.fileRefHash}>`).split(casePlan.fileRef).join(`<file:${casePlan.fileRefHash}>`);
}

function authProfileForObservation(context: ScanContext, observation: FileAuthorizationObservation) {
  if (!observation.authSlot || !context.options.authProfileSet) return undefined;
  return observation.authSlot === "account_a" ? context.options.authProfileSet.accountA : context.options.authProfileSet.accountB;
}
