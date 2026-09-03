import { createHash, createHmac, randomBytes } from "node:crypto";
import type { HttpResponse, RequestAuditEntry } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding, FindingType } from "../../core/findings/Finding.js";
import type { Severity } from "../../core/findings/Severity.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { redactSensitiveUrl } from "../../core/evidence/ValuePresenceAttestation.js";
import type { BrowserStorageObservation } from "../../reports/ReportTypes.js";
import type { SecretBoundaryReport } from "../../reports/SecretBoundaryReport.js";
import { recommendationRules } from "../../intelligence/recommendations/recommendationRules.js";
import { classifyTransientSecret } from "./SecretBoundaryClassifier.js";
import { extractSetCookieCandidates, extractTransientSecretCandidates } from "./SecretBoundaryExtractor.js";
import { planSecretBoundary } from "./SecretBoundaryPlanner.js";
import { secretBoundarySurfaces, secretMaterialClasses, type SecretActorContext, type SecretBoundaryObservation, type SecretBoundaryPlan, type SecretBoundarySurface, type SecretClassification, type TransientSecretCandidate } from "./SecretBoundaryTypes.js";

interface SourceReview { response: HttpResponse; surface: SecretBoundarySurface; actorContext: SecretActorContext; publicExposure: boolean; }

export class SecretBoundaryModule implements RouteCairnPlugin {
  public readonly name = "secret-boundary";
  public readonly description = "Correlates HTML, JavaScript, source-map, configuration, response, browser-storage, cookie, metadata, debug, GraphQL, and log exposure without retaining secret values.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const plan = planSecretBoundary(context.moduleSettings("secret-boundary"));
    const correlationKey = randomBytes(32);
    const audit = context.state.getRequestAudit();
    const reviewed = new Set<string>();
    const sources: SourceReview[] = [];
    let additionalRequestsUsed = 0;
    let sourceMapsReviewed = 0;

    for (const response of context.state.getResponses().slice(0, plan.maxObservedResponses)) addSource(sources, reviewed, response, surfaceForResponse(response), actorForResponse(response, audit));
    const observedResponsesReviewed = sources.length;

    const target = new URL(context.options.target);
    for (const path of plan.probePaths.slice(0, plan.maxAdditionalRequests)) {
      const url = new URL(path, target.origin).toString();
      const decision = context.scopeMatcher.decide(url, "GET"); context.state.recordScopeDecision(decision);
      if (!decision.allowed || !decision.normalizedUrl) continue;
      const response = await context.httpClient.send({ url: decision.normalizedUrl, method: "GET", retainBodyPreview: true });
      context.state.recordResponse(response); additionalRequestsUsed += 1;
      addSource(sources, reviewed, response, surfaceForResponse(response), "PUBLIC");
    }

    if (plan.inspectSourceMaps) {
      for (const url of (context.state.getJsIntelligence()?.sourceMaps ?? []).slice(0, plan.maxSourceMaps)) {
        const decision = context.scopeMatcher.decide(url, "GET"); context.state.recordScopeDecision(decision);
        if (!decision.allowed || !decision.normalizedUrl) continue;
        const response = await context.httpClient.send({ url: decision.normalizedUrl, method: "GET", retainBodyPreview: true });
        context.state.recordResponse(response); sourceMapsReviewed += 1;
        addSource(sources, reviewed, response, "SOURCE_MAP", "PUBLIC");
      }
    }

    const observations: SecretBoundaryObservation[] = [];
    let candidatesAnalyzed = 0;
    for (const source of sources) {
      if (candidatesAnalyzed >= plan.maxTotalCandidates) break;
      const remaining = plan.maxTotalCandidates - candidatesAnalyzed;
      const body = bodyPreviewForAnalysis(source.response)?.slice(0, plan.maxAnalysisBytes);
      const candidates = extractTransientSecretCandidates(body, Math.min(plan.maxCandidatesPerSource, remaining));
      const cookies = extractSetCookieCandidates(headersForAnalysis(source.response), Math.min(plan.maxCandidatesPerSource - candidates.length, remaining - candidates.length));
      for (const candidate of [...candidates, ...cookies]) {
        candidatesAnalyzed += 1;
        const surface = candidate.cookie ? "COOKIE" : source.surface;
        const classified = observationFor(candidate, classifiedInput(candidate, surface, source.publicExposure), source, surface, correlationKey);
        if (classified.materialClass !== "NON_SENSITIVE") observations.push(classified);
      }
    }

    for (const storage of context.state.getBrowserCrawl()?.authentication?.storage ?? []) {
      if (candidatesAnalyzed >= plan.maxTotalCandidates) break;
      candidatesAnalyzed += 1;
      const observation = observationFromBrowserStorage(storage);
      if (observation) observations.push(observation);
    }

    const deduped = dedupeObservations(observations);
    const findings = deduped.filter(isFinding).map(toFinding);
    const report = buildReport(plan, sources, deduped, findings.length, { observedResponsesReviewed, additionalRequestsUsed, sourceMapsReviewed, candidatesAnalyzed });
    return { pluginName: this.name, secretBoundary: report, findings, notes: report.notes };
  }
}

function addSource(output: SourceReview[], seen: Set<string>, response: HttpResponse, surface: SecretBoundarySurface, actorContext: SecretActorContext): void {
  const key = `${actorContext}:${response.method}:${response.finalUrl}:${response.bodyHash ?? response.statusCode ?? "none"}:${surface}`;
  if (seen.has(key)) return; seen.add(key);
  output.push({ response, surface, actorContext, publicExposure: actorContext === "PUBLIC" });
}

function classifiedInput(candidate: TransientSecretCandidate, surface: SecretBoundarySurface, publicExposure: boolean): SecretClassification {
  return classifyTransientSecret({ name: candidate.name, value: candidate.value, surface, publicExposure, ...(candidate.cookie ? { cookie: candidate.cookie } : {}) });
}

function observationFor(candidate: TransientSecretCandidate, classification: SecretClassification, source: SourceReview, surface: SecretBoundarySurface, correlationKey: Buffer): SecretBoundaryObservation {
  const sourceUrl = redactSensitiveUrl(source.response.finalUrl);
  const base = { surface, sourceUrl, actorContext: surface.startsWith("BROWSER_") ? "BROWSER" as const : source.actorContext, publicExposure: source.publicExposure, candidateName: sanitizeName(candidate.name), valueType: candidate.valueType, valueLength: candidate.value.length, materialClass: classification.materialClass, boundary: classification.boundary, impact: classification.impact, outcome: classification.outcome, confidence: classification.confidence, reasonCode: classification.reasonCode, tokenFormat: classification.tokenFormat, clientSafeNameConflict: classification.clientSafeNameConflict, correlationFingerprint: createHmac("sha256", correlationKey).update(candidate.value).digest("hex").slice(0, 24), method: source.response.method, ...(source.response.statusCode !== undefined ? { statusCode: source.response.statusCode } : {}), ...(source.response.contentType ? { contentType: source.response.contentType } : {}), ...(classification.supabaseRole ? { supabaseRole: classification.supabaseRole } : {}) };
  return { ...base, comparisonFingerprint: comparisonFingerprint(base) };
}

function observationFromBrowserStorage(storage: BrowserStorageObservation): SecretBoundaryObservation | undefined {
  if (!storage.secretBoundary) return undefined;
  const surface: SecretBoundarySurface = storage.storage === "localStorage" ? "BROWSER_LOCAL_STORAGE" : storage.storage === "sessionStorage" ? "BROWSER_SESSION_STORAGE" : "COOKIE";
  const sourceUrl = storage.origin;
  const base = { surface, sourceUrl, actorContext: "BROWSER" as const, publicExposure: false, candidateName: sanitizeName(storage.name), valueType: "string", valueLength: storage.valueLength, materialClass: storage.secretBoundary.materialClass, boundary: storage.secretBoundary.boundary, impact: storage.secretBoundary.impact, outcome: storage.secretBoundary.outcome, confidence: storage.secretBoundary.confidence, reasonCode: storage.secretBoundary.reasonCode, tokenFormat: storage.secretBoundary.tokenFormat, clientSafeNameConflict: storage.secretBoundary.clientSafeNameConflict, correlationFingerprint: storage.valueDigest.slice(0, 24), method: "BROWSER", ...(storage.secretBoundary.supabaseRole ? { supabaseRole: storage.secretBoundary.supabaseRole } : {}) };
  if (base.materialClass === "NON_SENSITIVE") return undefined;
  return { ...base, comparisonFingerprint: comparisonFingerprint(base) };
}

function surfaceForResponse(response: HttpResponse): SecretBoundarySurface {
  const path = safePath(response.finalUrl).toLowerCase(); const content = (response.contentType ?? "").toLowerCase();
  if (path.endsWith(".map")) return "SOURCE_MAP";
  if ((response.statusCode ?? 0) >= 400) return "ERROR_RESPONSE";
  if (/(?:^|\/)(?:debug|_debugbar|telescope|phpinfo)(?:\/|$)/.test(path)) return "DEBUG_ENDPOINT";
  if (/(?:^|\/)(?:graphql|gql)(?:\/|$)/.test(path)) return "GRAPHQL_RESPONSE";
  if (/(?:\.log$|\/logs?(?:\/|$))/.test(path)) return "PUBLIC_LOG";
  if (/(?:runtime[_-]?config|config\.json$|env\.js$)/.test(path)) return "RUNTIME_CONFIGURATION";
  if (/(?:build[_-]?(?:info|metadata)|asset-manifest|version\.json|\/version$)/.test(path)) return "BUILD_METADATA";
  if (/javascript|ecmascript/.test(content) || /\.m?js$/.test(path)) return "JAVASCRIPT_BUNDLE";
  if (/html/.test(content) || path === "/") return "HTML";
  return "API_RESPONSE";
}

function actorForResponse(response: HttpResponse, audit: readonly RequestAuditEntry[]): SecretActorContext {
  const entry = response.requestId ? audit.find((item) => item.requestId === response.requestId) : [...audit].reverse().find((item) => item.method === response.method && (item.finalUrl === response.finalUrl || item.requestedUrl === response.requestedUrl));
  if (!entry) return "UNKNOWN";
  return Object.keys(entry.requestHeaders).some((name) => /^(?:authorization|cookie|apikey|x-api-key|x-auth-token)$/i.test(name)) ? "AUTHENTICATED" : "PUBLIC";
}

function buildReport(plan: SecretBoundaryPlan, sources: readonly SourceReview[], observations: readonly SecretBoundaryObservation[], confirmedFindings: number, counts: { observedResponsesReviewed: number; additionalRequestsUsed: number; sourceMapsReviewed: number; candidatesAnalyzed: number }): SecretBoundaryReport {
  const coverage = Object.fromEntries(secretBoundarySurfaces.map((surface) => [surface, { sourcesObserved: sources.filter((item) => item.surface === surface).length + (surface.startsWith("BROWSER_") || surface === "COOKIE" ? Number(observations.some((item) => item.surface === surface)) : 0), candidatesAnalyzed: observations.filter((item) => item.surface === surface).length, classifiedObservations: observations.filter((item) => item.surface === surface).length, findings: observations.filter((item) => item.surface === surface && isFinding(item)).length }])) as SecretBoundaryReport["coverage"];
  const impactCounts = Object.fromEntries(["NONE", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((impact) => [impact, observations.filter((item) => item.impact === impact).length])) as SecretBoundaryReport["impactCounts"];
  const materialCounts = Object.fromEntries(secretMaterialClasses.map((material) => [material, observations.filter((item) => item.materialClass === material).length])) as SecretBoundaryReport["materialCounts"];
  return { enabled: true, schemaVersion: 1, observedResponsesReviewed: counts.observedResponsesReviewed, additionalRequestsUsed: counts.additionalRequestsUsed, additionalRequestLimit: plan.maxAdditionalRequests, sourceMapsReviewed: counts.sourceMapsReviewed, sourceMapLimit: plan.maxSourceMaps, candidatesAnalyzed: counts.candidatesAnalyzed, candidateLimit: plan.maxTotalCandidates, classifiedObservations: observations.length, confirmedFindings, clientSafeMaterial: observations.filter((item) => item.boundary === "CLIENT_SAFE").length, serverOnlyMaterial: observations.filter((item) => item.boundary === "SERVER_ONLY").length, clientSafeNameConflicts: observations.filter((item) => item.clientSafeNameConflict).length, supabase: { anonKeys: observations.filter((item) => item.materialClass === "SUPABASE_ANON_KEY").length, publishableKeys: observations.filter((item) => item.materialClass === "SUPABASE_PUBLISHABLE_KEY").length, serviceRoleKeys: observations.filter((item) => item.materialClass === "SUPABASE_SERVICE_ROLE_KEY").length, distinctionEnforced: true }, impactCounts, materialCounts, coverage, observations: [...observations], notes: [...plan.notes, "Supabase anon and publishable keys are expected client material; service-role and secret keys are server-only regardless of variable naming.", "Generic API-key-shaped values remain review observations unless name, format, token claims, storage context, or capability evidence proves impact."] };
}

function isFinding(value: SecretBoundaryObservation): boolean { return ["CONFIRMED_SENSITIVE_EXPOSURE", "CLIENT_STORAGE_RISK", "COOKIE_TRANSPORT_RISK", "SENSITIVE_FIELD_EXPOSURE"].includes(value.outcome) && value.confidence !== "LOW"; }
function toFinding(value: SecretBoundaryObservation): Finding {
  const type: FindingType = value.outcome === "CLIENT_STORAGE_RISK" ? "Client-Side Session Secret Exposure" : value.materialClass === "PERSONAL_DATA" ? "Sensitive Response Exposure" : ["USER_SESSION_SECRET", "ONE_TIME_OR_RECOVERY_TOKEN"].includes(value.materialClass) ? "Session Secret Exposure" : "Server Credential Exposure";
  const severity = severityFor(value.impact); const confidence = value.confidence === "CONFIRMED" || value.confidence === "HIGH" ? "High" as const : "Medium" as const; const scorer = new RiskScorer();
  const base = { severity, confidence, falsePositiveStatus: "likely-valid" as const, tags: ["secret-boundary", value.surface.toLowerCase(), value.materialClass.toLowerCase()] };
  return { id: `finding-${createHash("sha256").update(`secret-boundary:${value.comparisonFingerprint}`).digest("hex").slice(0, 12)}`, title: `${value.materialClass.toLowerCase().replaceAll("_", " ")} crossed its intended boundary`, type, severity, confidence, url: value.sourceUrl, method: value.method, ...(value.statusCode !== undefined ? { statusCode: value.statusCode } : {}), evidence: { url: value.sourceUrl, method: value.method, ...(value.statusCode !== undefined ? { statusCode: value.statusCode } : {}), ...(value.contentType ? { contentType: value.contentType } : {}), source: `secret-boundary:${value.surface}:${value.reasonCode}`, severityReason: `${value.impact} impact ${value.materialClass} was classified with ${value.confidence} confidence.`, reproductionNotes: [`Candidate ${value.candidateName}; comparison fingerprint ${value.comparisonFingerprint}.`, "Raw values, token claims other than the Supabase role class, response bodies, cookie values, and storage values are not retained."] }, impact: impactFor(value), recommendation: recommendationRules[type], manualTestingSuggestions: ["Confirm the intended client/server boundary without copying the value into tickets or logs.", "Rotate or revoke server credentials and user/session tokens after removing the exposure.", "Retest the same bounded source and verify the structural fingerprint disappears."], tags: base.tags, riskScore: scorer.score(base), workflowCase: { id: value.comparisonFingerprint, comparisonFingerprint: value.comparisonFingerprint }, sourceModule: "secret-boundary", falsePositiveStatus: base.falsePositiveStatus, timestamp: new Date().toISOString() };
}
function severityFor(impact: SecretBoundaryObservation["impact"]): Severity { return impact === "CRITICAL" ? "Critical" : impact === "HIGH" ? "High" : impact === "MEDIUM" ? "Medium" : "Low"; }
function impactFor(value: SecretBoundaryObservation): string { if (value.materialClass === "PERSONAL_DATA") return "A publicly reachable response exposes a field classified as sensitive personal or credential-derived data."; if (value.outcome === "CLIENT_STORAGE_RISK") return "Script-accessible session or recovery material can be stolen by injected browser code and replayed as the user."; if (value.outcome === "COOKIE_TRANSPORT_RISK") return "A reusable session or recovery cookie lacks the Secure transport boundary and may be exposed if an HTTP request reaches its cookie scope."; return "Server-only or session-bearing credential material is reachable across a client/public boundary and may enable unauthorized access at the credential's effective privilege."; }
function comparisonFingerprint(value: Omit<SecretBoundaryObservation, "comparisonFingerprint">): string { return createHash("sha256").update(JSON.stringify({ surface: value.surface, path: safePath(value.sourceUrl), actor: value.actorContext, name: value.candidateName, material: value.materialClass, boundary: value.boundary, outcome: value.outcome, reason: value.reasonCode, format: value.tokenFormat, conflict: value.clientSafeNameConflict })).digest("hex").slice(0, 24); }
function dedupeObservations(values: readonly SecretBoundaryObservation[]): SecretBoundaryObservation[] { const seen = new Set<string>(); return values.filter((value) => { const key = `${value.comparisonFingerprint}:${value.correlationFingerprint}`; if (seen.has(key)) return false; seen.add(key); return true; }); }
function safePath(value: string): string { try { return new URL(value).pathname; } catch { return "/unknown"; } }
function sanitizeName(value: string): string { return value.replace(/[\r\n\0|]/g, "_").slice(0, 200); }
