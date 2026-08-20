import { createHash } from "node:crypto";
import { authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { ValuePresenceAttestation } from "../../core/evidence/ValuePresenceAttestation.js";
import { evidenceFromResponse } from "../../core/evidence/EvidenceBuilder.js";
import type { Finding, FindingType } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { NextJsDataRouteReview, NextJsDetectionConfidence, NextJsManifestReview, NextJsObservation, NextJsReviewReport, NextJsRouterKind, NextJsSensitivitySignal, NextJsSourceMapReview, NextJsSurface } from "../../reports/ReportTypes.js";
import { analyzeStructuredBody, cacheMetadata, classifyRscSurface, derivePagesDataUrl, extractNextDataFromHtml, extractSourceMapReferences, isDynamicRouteTemplate, normalizeRouteTemplate, parseManifest, parseSourceMap, safeBuildIdDisplay, shortFingerprint, type TransientSensitivityCandidate } from "./NextJsParsers.js";

type Actor = "PUBLIC" | "PRIMARY" | "ACCOUNT_A" | "ACCOUNT_B";
type CacheReviewMode = "PASSIVE_CACHE_REVIEW" | "CONTROLLED_CACHE_DIFFERENTIAL";
interface ReviewSettings { maxManifestRequests: number; maxDataRequests: number; maxSourceMapRequests: number; maxCacheRequests: number; maxAssets: number; maxRoutes: number; inspectSourceMaps: boolean; inspectDataSurfaces: boolean; cacheReviewMode: CacheReviewMode; }
interface SensitiveAnalysis { response: HttpResponse; actor: Actor; candidates: TransientSensitivityCandidate[]; attestations: ValuePresenceAttestation[]; safeSignals: NextJsSensitivitySignal[]; }

export class NextJsReviewModule implements RouteCairnPlugin {
  public readonly name = "nextjs-review";
  public readonly description = "Performs bounded, evidence-driven Next.js Pages/App Router, manifest, data, RSC, source-map, and cache review.";
  public readonly phase = "analysis" as const;
  public async run(context: ScanContext): Promise<ModuleResult> {
    const { report, findings } = await reviewNextJs(context);
    return { pluginName: this.name, nextJsReview: report, findings, notes: report.notes };
  }
}

async function reviewNextJs(context: ScanContext): Promise<{ report: NextJsReviewReport; findings: Finding[] }> {
  const settings = resolveSettings(context);
  const initialResponses = context.state.getResponses();
  const detection = detectNextJs(initialResponses, context.state.getTechnologies().some((item) => item.name === "Next.js"), context.state.getBrowserCrawl()?.networkRequests.map((item) => item.url) ?? []);
  const requestBudget = budgetReport(settings);
  if (detection.confidence === "NOT_DETECTED") return skippedReview(detection, settings, requestBudget);

  const observations: NextJsObservation[] = [{ category: "NEXTJS_DETECTED", summary: `Next.js detection confidence: ${detection.confidence}.`, provenance: detection.evidence.join(", "), parseStatus: "PARSED" }];
  const surfaces: NextJsSurface[] = [], findings: Finding[] = [];
  const findingValueKeys = new Set<string>(), buildIds = new Set<string>(), actualBuildIds = new Set<string>(), routerEvidence = new Set<string>();
  const knownConcreteRoutes = new Set<string>(), knownTemplates = new Set<string>(), manifestUrls = new Set<string>();
  const sourceMapRefs = new Map<string, string | undefined>();

  for (const response of initialResponses.slice(0, settings.maxAssets)) {
    throwIfCancelled(context);
    const body = bodyPreviewForAnalysis(response) ?? "";
    const type = response.contentType ?? headerValue(headersForAnalysis(response), "content-type") ?? "";
    const isHtml = /text\/html/i.test(type) || /<html|__NEXT_DATA__/i.test(body.slice(0, 4096));
    if (isHtml) {
      const nextData = extractNextDataFromHtml(body);
      if (nextData.status === "PARSED") {
        routerEvidence.add("__NEXT_DATA__ identified a Pages Router representation.");
        if (nextData.buildId) { actualBuildIds.add(nextData.buildId); buildIds.add(safeBuildIdDisplay(nextData.buildId)); }
        if (nextData.page) addKnownRoute(nextData.page, knownConcreteRoutes, knownTemplates);
        const analysis = attestCandidates(context, response, "PUBLIC", nextData.sensitivity, "body");
        surfaces.push(surface(response, "NEXT_DATA", "PAGES_ROUTER", "NEXT_DATA", "OBSERVED_RESPONSE", analysis.safeSignals, nextData.page));
        observations.push({ category: "NEXTJS_PAGES_ROUTER_OBSERVED", summary: "Parsed __NEXT_DATA__ without retaining its props tree.", sourceUrl: safeUrlForReport(response.finalUrl), provenance: "NEXT_DATA", parseStatus: nextData.status });
        if (nextData.runtimeConfigPaths.length > 0) observations.push({ category: "NEXTJS_PUBLIC_RUNTIME_CONFIG_OBSERVED", summary: `${nextData.runtimeConfigPaths.length} bounded runtime-config field path(s) observed.`, sourceUrl: safeUrlForReport(response.finalUrl), provenance: "NEXT_DATA", parseStatus: "PARSED" });
        findings.push(...findingsForCandidates(response, analysis, nextData.runtimeConfigPaths.length > 0 ? "NEXT_DATA_WITH_RUNTIME_CONFIG" : "NEXT_DATA", findingValueKeys));
      }
      if (!response.error && typeof response.statusCode === "number" && response.statusCode < 400) addKnownRoute(concreteRouteFromUrl(response.finalUrl), knownConcreteRoutes, knownTemplates);
      discoverReferencedArtifacts(body, response.finalUrl, manifestUrls, sourceMapRefs);
      surfaces.push(surface(response, "HTML", nextData.status === "PARSED" ? "PAGES_ROUTER" : "UNKNOWN", "EXPLICIT_TARGET", "OBSERVED_RESPONSE", [], concreteRouteFromUrl(response.finalUrl)));
    }
    if (classifyRscSurface(response.finalUrl, type, headersForAnalysis(response), body)) {
      routerEvidence.add("Observed an exact RSC/Flight response or request signature.");
      surfaces.push(surface(response, "RSC", "APP_ROUTER", "BROWSER_NETWORK", "OBSERVED_RESPONSE", [], concreteRouteFromUrl(response.finalUrl)));
      observations.push({ category: "NEXTJS_RSC_SURFACE_OBSERVED", summary: "Observed an exact RSC/Flight surface; no RSC token or router state was synthesized.", sourceUrl: safeUrlForReport(response.finalUrl), provenance: "BROWSER_NETWORK", parseStatus: "PARSED" });
    }
    if (/\/_next\/data\//.test(response.finalUrl)) {
      routerEvidence.add("Observed a Pages Router data response.");
      const id = /\/_next\/data\/([^/]+)\//.exec(response.finalUrl)?.[1];
      if (id) { const decoded = decodeURIComponent(id); actualBuildIds.add(decoded); buildIds.add(safeBuildIdDisplay(decoded)); }
    }
  }

  for (const script of context.state.getJsIntelligence()?.scripts.slice(0, settings.maxAssets) ?? []) {
    const response = responseForUrl(initialResponses, script.scriptUrl);
    if (response) {
      const body = bodyPreviewForAnalysis(response) ?? "";
      extractSourceMapReferences(body, response.finalUrl).forEach((reference) => sourceMapRefs.set(reference.url, reference.inlineBody));
      surfaces.push(surface(response, "JS_CHUNK", /app[-_/]|server-reference|react-server/i.test(body) ? "APP_ROUTER" : "UNKNOWN", "HTML_SCRIPT_REFERENCE", "OBSERVED_RESPONSE", []));
      if (/app-router|react-server|server-reference|__next_f/i.test(body)) routerEvidence.add("Observed App Router/RSC client bootstrap structures.");
    }
    script.sourceMapUrls.forEach((url) => sourceMapRefs.set(url, undefined));
  }
  for (const request of context.state.getBrowserCrawl()?.networkRequests ?? []) {
    if (classifyRscSurface(request.url)) {
      routerEvidence.add("Browser crawler observed an exact RSC URL.");
      surfaces.push({ surfaceType: "RSC", sourceUrl: safeUrlForReport(request.url), normalizedUrl: safeUrlForReport(request.url), routerKind: "APP_ROUTER", actor: "PUBLIC", source: "BROWSER_NETWORK", retrievalMethod: "BROWSER_NETWORK", sensitivitySignals: [], evidenceReferences: ["browser-network"], parseStatus: "PARSED" });
    }
    if (/\/_next\/data\//.test(request.url)) { routerEvidence.add("Browser crawler observed an exact Pages data URL."); addKnownRoute(dataRouteToConcreteRoute(request.url), knownConcreteRoutes, knownTemplates); }
  }

  const manifests: NextJsManifestReview[] = [];
  for (const url of deterministicScopedUrls(context, manifestUrls, settings.maxManifestRequests)) {
    throwIfCancelled(context);
    const existing = responseForUrl(context.state.getResponses(), url);
    const response = existing ?? await context.httpClient.send({ url, method: "GET" });
    if (!existing) { context.state.recordResponse(response); countRequest(response, requestBudget.manifest); }
    const review = response.error ? failedManifest(response) : parseManifest(bodyPreviewForAnalysis(response) ?? "", response.finalUrl); manifests.push(review);
    if (review.parseStatus === "PARSED") {
      observations.push({ category: review.kind === "SSG_MANIFEST" ? "NEXTJS_SSG_MANIFEST_OBSERVED" : "NEXTJS_BUILD_MANIFEST_OBSERVED", summary: `${review.kind} parsed with ${review.totalEntries} bounded entry signal(s).`, sourceUrl: review.url, provenance: "HTML_SCRIPT_REFERENCE", parseStatus: review.parseStatus });
      review.routes.forEach((route) => addKnownRoute(route, knownConcreteRoutes, knownTemplates));
      review.assets.filter((asset) => /\.map(?:$|\?)/.test(asset)).forEach((asset) => { try { sourceMapRefs.set(new URL(asset, response.finalUrl).toString(), undefined); } catch { /* ignored */ } });
      surfaces.push(surface(response, review.kind, review.kind === "APP_MANIFEST" ? "APP_ROUTER" : "PAGES_ROUTER", "BUILD_MANIFEST", "BROKER_GET", []));
      routerEvidence.add(review.kind === "APP_MANIFEST" ? "Parsed a public App Router manifest." : "Parsed public Pages Router build metadata.");
    } else observations.push({ category: "NEXTJS_UNKNOWN_MANIFEST_SHAPE", summary: review.notes[0] ?? "Manifest shape was not supported.", sourceUrl: review.url, provenance: "HTML_SCRIPT_REFERENCE", parseStatus: review.parseStatus });
  }

  const candidates = new Set<string>();
  if (settings.inspectDataSurfaces) {
    for (const response of initialResponses) if (/\/_next\/data\//.test(response.finalUrl) && !response.error && typeof response.statusCode === "number" && response.statusCode < 400) candidates.add(response.finalUrl);
    for (const buildId of actualBuildIds) for (const route of [...knownConcreteRoutes].sort().slice(0, settings.maxRoutes)) { const derived = derivePagesDataUrl(context.options.target, buildId, route); if (derived) candidates.add(derived); }
  }
  const selectedDataUrls = deterministicScopedUrls(context, candidates, settings.maxDataRequests);
  const dataRoutes: NextJsDataRouteReview[] = [], publicAnalyses = new Map<string, SensitiveAnalysis>();
  for (const url of selectedDataUrls) {
    throwIfCancelled(context);
    const existing = responseForUrl(context.state.getResponses(), url);
    const response = existing ?? await context.httpClient.send({ url, method: "GET" }); if (!existing) context.state.recordResponse(response); countRequest(response, requestBudget.dataSurface);
    const parsed = analyzeStructuredBody(bodyPreviewForAnalysis(response) ?? ""), analysis = attestCandidates(context, response, "PUBLIC", parsed.sensitivity, "body");
    publicAnalyses.set(logicalSurfaceKey(url), analysis);
    const review = toDataRouteReview(response, parsed, analysis); dataRoutes.push(review);
    surfaces.push(surface(response, "NEXT_DATA", "PAGES_ROUTER", "DERIVED_KNOWN_DATA_ROUTE", "BROKER_GET", analysis.safeSignals, dataRouteToConcreteRoute(url)));
    observations.push({ category: "NEXTJS_DATA_SURFACE_OBSERVED", summary: `Reviewed data surface with status ${response.statusCode ?? "error"}.`, sourceUrl: safeUrlForReport(response.finalUrl), provenance: "DERIVED_KNOWN_DATA_ROUTE", parseStatus: review.parseStatus ?? "REQUEST_FAILED" });
    findings.push(...findingsForCandidates(response, analysis, "PAGES_DATA", findingValueKeys));
  }

  const sourceMaps: NextJsSourceMapReview[] = [];
  if (settings.inspectSourceMaps) for (const [url, inlineBody] of [...sourceMapRefs.entries()].sort(([a], [b]) => a.localeCompare(b)).slice(0, settings.maxSourceMapRequests)) {
    throwIfCancelled(context);
    if (inlineBody !== undefined || url.endsWith("#inline-source-map")) {
      const response = responseForUrl(context.state.getResponses(), url.replace(/#inline-source-map$/, "")) ?? syntheticResponse(url);
      const parsed = parseSourceMap(inlineBody ?? "", url, true), analysis = attestCandidates(context, response, "PUBLIC", parsed.transientSensitivity, "source-map");
      parsed.sensitivitySignals = analysis.safeSignals; delete (parsed as Partial<typeof parsed>).transientSensitivity; sourceMaps.push(parsed);
      findings.push(...sourceMapFindings(response, analysis, findingValueKeys, url)); observations.push(sourceMapObservation(parsed)); continue;
    }
    const scoped = context.scopeMatcher.decide(url, "GET"); context.state.recordScopeDecision(scoped);
    if (!scoped.allowed || !scoped.normalizedUrl) { sourceMaps.push({ url: safeUrlForReport(url), classification: /\/_next\/static\//.test(url) ? "nextjs-public-source-map-review" : "generic-source-map-review", severityHint: "low", reason: `Source map reference was not fetched: ${scoped.reason}.`, parseStatus: "OUT_OF_SCOPE" }); continue; }
    const existing = responseForUrl(context.state.getResponses(), scoped.normalizedUrl);
    const response = existing ?? await context.httpClient.send({ url: scoped.normalizedUrl, method: "GET" });
    if (!existing) { context.state.recordResponse(response); countRequest(response, requestBudget.sourceMap); }
    const parsed = response.error ? failedSourceMap(response) : parseSourceMap(bodyPreviewForAnalysis(response) ?? "", response.finalUrl, false), analysis = attestCandidates(context, response, "PUBLIC", parsed.transientSensitivity, "source-map");
    parsed.sensitivitySignals = analysis.safeSignals; delete (parsed as Partial<typeof parsed>).transientSensitivity; sourceMaps.push(parsed);
    findings.push(...sourceMapFindings(response, analysis, findingValueKeys, response.finalUrl)); observations.push(sourceMapObservation(parsed)); surfaces.push(surface(response, "SOURCE_MAP", "UNKNOWN", "SOURCE_MAPPING_URL", "BROKER_GET", analysis.safeSignals));
  }

  findings.push(...await controlledCacheReview(context, settings, selectedDataUrls, requestBudget, surfaces, observations, findingValueKeys));
  const routerKind = classifyRouter(routerEvidence);
  observations.push({ category: routerKind === "MIXED" ? "NEXTJS_MIXED_ROUTER_OBSERVED" : routerKind === "APP_ROUTER" ? "NEXTJS_APP_ROUTER_OBSERVED" : "NEXTJS_PAGES_ROUTER_OBSERVED", summary: `Router classification: ${routerKind}.`, provenance: [...routerEvidence].join(" "), parseStatus: "PARSED" });
  const cacheSignals = dataRoutes.filter((route) => route.cacheRisk !== "normal-public-cache").map((route) => `${route.url}: ${route.cacheRisk}`);
  const counts = Object.fromEntries([...new Set(findings.map((finding) => finding.type))].map((type) => [type, findings.filter((finding) => finding.type === type).length]));
  const availableRoutes = knownConcreteRoutes.size + knownTemplates.size;
  const limitations = ["Unknown future Next.js artifact shapes fall back safely and may not be parsed.", "Dynamic route templates are never expanded without an already observed concrete route.", "Unreferenced source maps and non-public server build manifests are not guessed.", "RSC internals are observed but not fuzzed; Server Actions are never invoked.", "Passive cache headers are signals, not proof of a vulnerability.", "Browser-managed traffic retains RouteCairn's documented Playwright DNS residual boundary."];
  return { report: {
    detected: true, detectionConfidence: detection.confidence, detectionEvidence: detection.evidence, routerKind, routerEvidence: [...routerEvidence], buildIds: [...buildIds].sort(), surfaces: dedupeSurfaces(surfaces), observations, manifests, dataRoutes, sourceMaps, cacheSignals, securityFindingCounts: counts,
    coverage: { moduleState: "EXECUTED", sourceMapReview: !settings.inspectSourceMaps ? "DISABLED" : sourceMapRefs.size === 0 ? "NO_REFERENCES" : sourceMaps.some((item) => item.parseStatus === "BUDGET_EXHAUSTED") ? "BUDGET_EXHAUSTED" : "EXECUTED", dataSurfaceReview: selectedDataUrls.length === 0 ? "NO_CONCRETE_ROUTES" : dataRoutes.some((item) => item.parseStatus === "BUDGET_EXHAUSTED") ? "BUDGET_EXHAUSTED" : "EXECUTED", cacheDifferential: settings.cacheReviewMode !== "CONTROLLED_CACHE_DIFFERENTIAL" ? "DISABLED" : observations.some((item) => item.provenance === "CONTROLLED_CACHE_DIFFERENTIAL" && item.parseStatus === "BUDGET_EXHAUSTED") ? "BUDGET_EXHAUSTED" : requestBudget.cacheDifferential.used > 0 ? "EXECUTED" : "NOT_CONFIGURED", processedRoutes: Math.min(availableRoutes, settings.maxRoutes), availableRoutes, truncated: availableRoutes > settings.maxRoutes || manifestUrls.size > settings.maxManifestRequests || sourceMapRefs.size > settings.maxSourceMapRequests || candidates.size > settings.maxDataRequests, limitations },
    requestBudget, notes: [`Next.js deep review ran at ${detection.confidence} confidence with ${routerKind} classification.`, `Processed ${Math.min(availableRoutes, settings.maxRoutes)} of ${availableRoutes} route entries; dynamic templates were not expanded.`, `Additional-request ceiling: ${requestBudget.maximumAdditionalRequests} (${settings.maxManifestRequests} manifest + ${settings.maxDataRequests} data + ${settings.maxSourceMapRequests} source map + ${settings.maxCacheRequests} cache differential).`, "Expected Next.js metadata, route names, build IDs, RSC signals, source-map availability, and cache headers remain informational unless concrete sensitive exposure is proven."]
  }, findings: dedupeFindings(findings) };
}

function skippedReview(detection: ReturnType<typeof detectNextJs>, settings: ReviewSettings, requestBudget: ReturnType<typeof budgetReport>): { report: NextJsReviewReport; findings: Finding[] } {
  return { report: { detected: false, detectionConfidence: detection.confidence, detectionEvidence: detection.evidence, routerKind: "UNKNOWN", routerEvidence: [], buildIds: [], surfaces: [], observations: [], manifests: [], dataRoutes: [], sourceMaps: [], cacheSignals: [], securityFindingCounts: {}, coverage: { moduleState: "SKIPPED_NOT_DETECTED", sourceMapReview: settings.inspectSourceMaps ? "NO_REFERENCES" : "DISABLED", dataSurfaceReview: "NO_CONCRETE_ROUTES", cacheDifferential: settings.cacheReviewMode === "CONTROLLED_CACHE_DIFFERENTIAL" ? "NOT_CONFIGURED" : "DISABLED", processedRoutes: 0, availableRoutes: 0, truncated: false, limitations: ["Next.js deep review did not run because available evidence did not meet the detection threshold."] }, requestBudget, notes: ["Next.js was not detected; Next.js deep review safely skipped."] }, findings: [] };
}

function resolveSettings(context: ScanContext): ReviewSettings {
  const value = context.moduleSettings("nextjs-review");
  return { maxManifestRequests: boundedNumber(value.maxNextJsManifestRequests, 4, 32), maxDataRequests: boundedNumber(value.maxNextJsDataSurfaceRequests ?? value.maxDataRoutes, 8, 64), maxSourceMapRequests: boundedNumber(value.maxNextJsSourceMapRequests, 4, 32), maxCacheRequests: boundedNumber(value.maxNextJsCacheDifferentialRequests, 0, 12, true), maxAssets: boundedNumber(value.maxNextJsAssetsInspected, 50, 500), maxRoutes: boundedNumber(value.maxNextJsRoutesProcessed, 200, 2_000), inspectSourceMaps: value.inspectNextJsSourceMaps !== false, inspectDataSurfaces: value.inspectKnownNextJsDataSurfaces !== false, cacheReviewMode: value.nextJsCacheReviewMode === "CONTROLLED_CACHE_DIFFERENTIAL" ? "CONTROLLED_CACHE_DIFFERENTIAL" : "PASSIVE_CACHE_REVIEW" };
}

function detectNextJs(responses: HttpResponse[], technologyDetected: boolean, browserUrls: string[]): { confidence: NextJsDetectionConfidence; evidence: string[] } {
  const evidence = new Set<string>(); let strong = technologyDetected ? 1 : 0, weak = 0; if (technologyDetected) evidence.add("technology classifier");
  for (const response of responses) { const body = bodyPreviewForAnalysis(response) ?? "", headers = headersForAnalysis(response); if (/<script\b[^>]*\bid=["']__NEXT_DATA__["']/i.test(body)) { evidence.add("__NEXT_DATA__"); strong += 2; } if (Object.entries(headers).some(([name, value]) => /^x-nextjs-|^x-powered-by$/i.test(name) && String(value).toLowerCase().includes("next"))) { evidence.add("Next.js response header"); strong += 1; } if (/\/_next\/static\//.test(`${response.finalUrl} ${body}`)) { evidence.add("/_next/static asset"); weak += 1; } if (/__BUILD_MANIFEST|__SSG_MANIFEST|__next_f|react-server-dom-webpack/i.test(body)) { evidence.add("Next.js bootstrap/manifest structure"); strong += 1; } if (classifyRscSurface(response.finalUrl, response.contentType ?? "", headers, body)) { evidence.add("RSC/Flight behavior"); strong += 1; } }
  if (browserUrls.some((url) => /\/_next\/(?:static|data)\//.test(url))) { evidence.add("browser-observed Next.js request"); weak += 1; }
  return { confidence: strong >= 2 || (strong >= 1 && weak >= 1) ? "CONFIRMED" : strong >= 1 || weak >= 2 ? "HIGH_CONFIDENCE" : weak >= 1 ? "POSSIBLE" : "NOT_DETECTED", evidence: [...evidence] };
}

function discoverReferencedArtifacts(body: string, baseUrl: string, manifests: Set<string>, sourceMaps: Map<string, string | undefined>): void { for (const match of body.matchAll(/["']([^"']*(?:_buildManifest|_ssgManifest|routes-manifest|app-(?:build-)?manifest)[^"']*)["']/gi)) { try { const url = new URL(match[1] ?? "", baseUrl); if (["http:", "https:"].includes(url.protocol)) manifests.add(url.toString()); } catch { /* ignored */ } } extractSourceMapReferences(body, baseUrl).forEach((reference) => sourceMaps.set(reference.url, reference.inlineBody)); }
function addKnownRoute(value: string | undefined, concrete: Set<string>, templates: Set<string>): void { if (!value) return; const route = normalizeRouteTemplate(value); if (!route) return; if (isDynamicRouteTemplate(route)) templates.add(route); else concrete.add(route); }
function deterministicScopedUrls(context: ScanContext, values: Iterable<string>, maximum: number): string[] { const result: string[] = []; for (const value of [...new Set(values)]) { if (result.length >= maximum) break; const decision = context.scopeMatcher.decide(value, "GET"); context.state.recordScopeDecision(decision); if (decision.allowed && decision.normalizedUrl) result.push(decision.normalizedUrl); } return result; }

function attestCandidates(context: ScanContext, response: HttpResponse, actor: Actor, candidates: TransientSensitivityCandidate[], location: "body" | "source-map"): SensitiveAnalysis {
  const attestations = candidates.slice(0, 32).map((candidate) => context.httpClient.attestTransientResponseValue({ rawValue: candidate.rawValue, location, name: candidate.fieldPath || candidate.category, classification: candidate.category === "PRIVATE_FIELD" ? "private-data" : "secret-material", response }));
  const safeSignals = candidates.slice(0, 32).map((candidate, index): NextJsSensitivitySignal => ({ category: candidate.category, fieldPath: safeFieldPath(candidate.fieldPath), valueType: candidate.valueType, valueLength: candidate.valueLength, confidence: candidate.confidence, ...(attestations[index] ? { correlationFingerprint: attestations[index].correlationFingerprint } : {}) }));
  return { response, actor, candidates, attestations, safeSignals };
}

function findingsForCandidates(response: HttpResponse, analysis: SensitiveAnalysis, source: string, seen: Set<string>): Finding[] { return analysis.candidates.flatMap((candidate, index) => { const runtime = /runtimeconfig/i.test(candidate.fieldPath), type: FindingType = runtime ? "Next.js Public Runtime Secret Exposure" : "Next.js Public Serialized Sensitive Data Exposure", key = `${type}:${logicalSurfaceKey(response.finalUrl)}:${shortFingerprint(candidate.rawValue)}`; if (seen.has(key)) return []; seen.add(key); return [nextFinding(response, type, candidate, analysis.attestations[index] ? [analysis.attestations[index]!] : [], source)]; }); }
function sourceMapFindings(response: HttpResponse, analysis: SensitiveAnalysis, seen: Set<string>, url: string): Finding[] { return analysis.candidates.flatMap((candidate, index) => { const key = `source-map:${logicalAssetKey(url)}:${shortFingerprint(candidate.rawValue)}`; if (seen.has(key)) return []; seen.add(key); return [nextFinding(response, "Next.js Source Map Sensitive Data Exposure", candidate, analysis.attestations[index] ? [analysis.attestations[index]!] : [], "SOURCE_MAPPING_URL")]; }); }

async function controlledCacheReview(context: ScanContext, settings: ReviewSettings, urls: string[], budget: ReturnType<typeof budgetReport>, surfaces: NextJsSurface[], observations: NextJsObservation[], seen: Set<string>): Promise<Finding[]> {
  if (settings.cacheReviewMode !== "CONTROLLED_CACHE_DIFFERENTIAL" || settings.maxCacheRequests <= 0 || urls.length === 0) return [];
  const profiles = controlledProfiles(context); if (profiles.length === 0) return [];
  const findings: Finding[] = [], actorAnalyses = new Map<string, SensitiveAnalysis>(); let remaining = settings.maxCacheRequests, budgetExhausted = false;
  for (const url of urls) for (const actor of profiles) {
    if (remaining < 2) { budgetExhausted = true; break; }
    throwIfCancelled(context);
    const actorResponse = await context.httpClient.send({ url, method: "GET", headers: authHeadersForProfile(actor.profile), skipCache: true });
    const publicReplay = await context.httpClient.send({ url, method: "GET", skipCache: true });
    remaining -= 2; budget.cacheDifferential.used += 2;
    const actorAnalysis = attestCandidates(context, actorResponse, actor.actor, analyzeStructuredBody(bodyPreviewForAnalysis(actorResponse) ?? "").sensitivity, "body");
    const publicAnalysis = attestCandidates(context, publicReplay, "PUBLIC", analyzeStructuredBody(bodyPreviewForAnalysis(publicReplay) ?? "").sensitivity, "body");
    actorAnalyses.set(`${logicalSurfaceKey(url)}:${actor.actor}`, actorAnalysis);
    surfaces.push(surface(actorResponse, "NEXT_DATA", "PAGES_ROUTER", "CONTROLLED_CACHE_DIFFERENTIAL", "BROKER_GET", actorAnalysis.safeSignals, dataRouteToConcreteRoute(url), actor.actor));
    const publicFingerprints = new Set(publicAnalysis.attestations.map((item) => item.correlationFingerprint));
    actorAnalysis.candidates.forEach((candidate, index) => {
      const attestation = actorAnalysis.attestations[index]; if (!attestation || !publicFingerprints.has(attestation.correlationFingerprint)) return;
      const key = `cache:${logicalSurfaceKey(url)}:${attestation.correlationFingerprint}`; if (seen.has(key)) return; seen.add(key);
      findings.push(nextFinding(publicReplay, "Next.js Shared Cache Private Data Exposure", candidate, [attestation, ...publicAnalysis.attestations.filter((item) => item.correlationFingerprint === attestation.correlationFingerprint)], `CONTROLLED_CACHE_DIFFERENTIAL:${actor.actor}->PUBLIC`));
    });
    observations.push({ category: "NEXTJS_CACHE_SIGNAL_OBSERVED", summary: "Completed a bounded authenticated-to-public replay with tool-side response caching disabled.", sourceUrl: safeUrlForReport(url), provenance: "CONTROLLED_CACHE_DIFFERENTIAL", parseStatus: actorResponse.error || publicReplay.error ? "REQUEST_FAILED" : "PARSED" });
  }
  if (budgetExhausted) observations.push({ category: "NEXTJS_CACHE_SIGNAL_OBSERVED", summary: "Controlled cache review stopped at its configured request ceiling.", provenance: "CONTROLLED_CACHE_DIFFERENTIAL", parseStatus: "BUDGET_EXHAUSTED" });
  for (const url of urls) {
    const accountA = actorAnalyses.get(`${logicalSurfaceKey(url)}:ACCOUNT_A`), accountB = actorAnalyses.get(`${logicalSurfaceKey(url)}:ACCOUNT_B`);
    if (!accountA || !accountB) continue;
    const bFingerprints = new Set(accountB.attestations.map((item) => item.correlationFingerprint));
    accountA.candidates.forEach((candidate, index) => {
      const attestation = accountA.attestations[index]; if (!attestation || !bFingerprints.has(attestation.correlationFingerprint)) return;
      const key = `cross-actor:${logicalSurfaceKey(url)}:${attestation.correlationFingerprint}`; if (seen.has(key)) return; seen.add(key);
      findings.push(nextFinding(accountB.response, "Next.js Cross-Actor Data Exposure", candidate, [attestation, ...accountB.attestations.filter((item) => item.correlationFingerprint === attestation.correlationFingerprint)], "CONTROLLED_CACHE_DIFFERENTIAL:ACCOUNT_A->ACCOUNT_B"));
    });
  }
  return findings;
}

function controlledProfiles(context: ScanContext): Array<{ actor: "PRIMARY" | "ACCOUNT_A" | "ACCOUNT_B"; profile: AuthProfile }> { if (context.options.authProfileSet) { const { accountA, accountB } = context.options.authProfileSet; if (accountA.principalId && accountB.principalId && accountA.principalId !== accountB.principalId) return [{ actor: "ACCOUNT_A", profile: accountA }, { actor: "ACCOUNT_B", profile: accountB }]; return []; } const profile = context.options.authProfile; return profile?.principalId ? [{ actor: "PRIMARY", profile }] : []; }

function nextFinding(response: HttpResponse, type: FindingType, candidate: TransientSensitivityCandidate, attestations: ValuePresenceAttestation[], source: string): Finding {
  const severity = type === "Next.js Shared Cache Private Data Exposure" || candidate.confidence === "HIGH" ? "High" as const : "Medium" as const, confidence = candidate.confidence === "HIGH" ? "High" as const : "Medium" as const;
  const boundaryTag = type.includes("Cross-Actor") ? "cross-actor" : type.includes("Cache") ? "cache" : "public-boundary";
  const tags = ["nextjs", "exposure", type.includes("Source Map") ? "source-map" : "serialized-data", boundaryTag, `surface:${logicalSurfaceKey(response.finalUrl)}`], falsePositiveStatus = "likely-valid" as const, base = { severity, confidence, falsePositiveStatus, tags };
  const evidence = evidenceFromResponse(response, { source: `${source}; ${candidate.category} at ${safeFieldPath(candidate.fieldPath)}; raw value excluded`, severity, confidence, tags }); evidence.valueAttestations = attestations; delete evidence.bodyPreview;
  return { id: stableFindingId(type, response.finalUrl, candidate.fieldPath), title: titleForFinding(type), type, severity, confidence, url: safeUrlForReport(response.finalUrl), method: "GET", ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}), evidence, impact: impactForFinding(type), recommendation: recommendationForFinding(type), manualTestingSuggestions: ["Reproduce only with authorized read-only requests.", "Compare the scan-scoped presence fingerprint; do not copy private values into the report.", "Confirm the field is not intentionally public before triage."], tags, riskScore: new RiskScorer().score(base), sourceModule: "nextjs-review", falsePositiveStatus, timestamp: new Date().toISOString() };
}

function toDataRouteReview(response: HttpResponse, parsed: ReturnType<typeof analyzeStructuredBody>, analysis: SensitiveAnalysis): NextJsDataRouteReview {
  const headers = headersForAnalysis(response), metadata = cacheMetadata(headers, analysis.actor, response.bodyHash, analysis.safeSignals.length > 0 ? "SENSITIVE" : parsed.propertyPaths.length > 0 ? "SIGNAL" : "NONE"), contentType = response.contentType ?? headerValue(headers, "content-type") ?? "", dataIndicators = dataLeakageIndicators(bodyPreviewForAnalysis(response) ?? "", parsed.propertyPaths, analysis.safeSignals), cacheRisk = classifyCacheRisk(response.statusCode, metadata.cacheControl, dataIndicators);
  const concreteRoute = dataRouteToConcreteRoute(response.finalUrl);
  return { url: safeUrlForReport(response.finalUrl), ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}), ...(contentType ? { contentType } : {}), ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}), ...(metadata.cacheControl ? { cacheControl: metadata.cacheControl } : {}), cacheMetadata: metadata, parseStatus: response.error ? requestFailureStatus(response) : parsed.status, propertyPaths: parsed.propertyPaths, sensitivitySignals: analysis.safeSignals, actor: analysis.actor, ...(concreteRoute ? { concreteRoute } : {}), ...(response.bodyHash ? { responseFingerprint: response.bodyHash } : {}), dataIndicators, cacheRisk, notes: [cacheRisk === "possible-private-data-cache" ? "Sensitive evidence and public-cache metadata co-occur; headers alone are not treated as proof of unauthorized cache exposure." : "No demonstrated shared-cache private-data exposure was inferred from headers alone.", `Structured parse status: ${response.error ? requestFailureStatus(response) : parsed.status}.`] };
}

function surface(response: HttpResponse, surfaceType: NextJsSurface["surfaceType"] | NextJsManifestReview["kind"], routerKind: NextJsRouterKind, source: string, retrievalMethod: NextJsSurface["retrievalMethod"], sensitivitySignals: NextJsSensitivitySignal[], concreteRoute?: string, actor: Actor = "PUBLIC"): NextJsSurface { return { surfaceType: surfaceType === "UNKNOWN" ? "OTHER_NEXT_METADATA" : surfaceType, sourceUrl: safeUrlForReport(response.finalUrl), normalizedUrl: safeUrlForReport(response.finalUrl), routerKind, ...(concreteRoute ? { concreteRoute } : {}), actor, ...(response.contentType ? { contentType: response.contentType } : {}), ...(typeof response.statusCode === "number" ? { status: response.statusCode } : {}), cacheMetadata: cacheMetadata(headersForAnalysis(response), actor, response.bodyHash, sensitivitySignals.length ? "SENSITIVE" : "NONE"), source, retrievalMethod, sensitivitySignals, evidenceReferences: [response.requestId ?? response.bodyHash ?? source], parseStatus: response.error ? requestFailureStatus(response) : "PARSED" }; }
function sourceMapObservation(review: NextJsSourceMapReview): NextJsObservation { return { category: (review.sourcesContentCount ?? 0) > 0 ? "NEXTJS_SOURCE_MAP_WITH_SOURCES_CONTENT" : "NEXTJS_SOURCE_MAP_OBSERVED", summary: (review.sourcesContentCount ?? 0) > 0 ? `Source map contains ${review.sourcesContentCount} embedded source content entr${review.sourcesContentCount === 1 ? "y" : "ies"}; source text was not retained.` : "Source map availability recorded as informational intelligence.", sourceUrl: review.url, provenance: "SOURCE_MAPPING_URL", parseStatus: review.parseStatus ?? "UNSUPPORTED_SHAPE" }; }
function classifyRouter(evidence: Set<string>): NextJsRouterKind { const pages = [...evidence].some((value) => /Pages|__NEXT_DATA__|data response|Pages data/i.test(value)), app = [...evidence].some((value) => /App Router|RSC|Flight/i.test(value)); return pages && app ? "MIXED" : pages ? "PAGES_ROUTER" : app ? "APP_ROUTER" : "UNKNOWN"; }
function classifyCacheRisk(statusCode: number | undefined, cacheControl: string | undefined, indicators: string[]): NextJsDataRouteReview["cacheRisk"] { if (!statusCode || statusCode >= 400) return "not-reachable"; const cache = cacheControl?.toLowerCase() ?? ""; if (indicators.includes("validated-sensitive-data") && /(?:public|s-maxage|max-age=\d+)/.test(cache) && !/(?:private|no-store)/.test(cache)) return "possible-private-data-cache"; if (indicators.length > 0) return "data-needs-review"; return "normal-public-cache"; }
function dataLeakageIndicators(body: string, paths: string[], signals: NextJsSensitivitySignal[]): string[] { const indicators: string[] = []; if (/"(?:email|phone|address|token|session|role|user|account|customer)"\s*:/i.test(body)) indicators.push("sensitive-keywords"); if (paths.some((path) => /(?:^|\.)(?:props|pageProps)(?:\.|$)/.test(path))) indicators.push("nextjs-page-props"); if (/"__N_SS[PG]"\s*:\s*true/i.test(body)) indicators.push("nextjs-render-mode"); if (signals.length > 0) indicators.push("validated-sensitive-data"); return [...new Set(indicators)]; }
function budgetReport(settings: ReviewSettings) { return { manifest: { used: 0, limit: settings.maxManifestRequests }, dataSurface: { used: 0, limit: settings.maxDataRequests }, sourceMap: { used: 0, limit: settings.maxSourceMapRequests }, cacheDifferential: { used: 0, limit: settings.maxCacheRequests }, other: { used: 0, limit: 0 }, maximumAdditionalRequests: settings.maxManifestRequests + settings.maxDataRequests + settings.maxSourceMapRequests + settings.maxCacheRequests }; }
function countRequest(response: HttpResponse, counter: { used: number }): void { if (response.error?.name !== "RequestBudgetExceeded") counter.used += 1; }
function failedManifest(response: HttpResponse): NextJsManifestReview { return { url: safeUrlForReport(response.finalUrl), kind: "UNKNOWN", parseStatus: requestFailureStatus(response), routes: [], assets: [], processedEntries: 0, totalEntries: 0, truncated: false, notes: [response.error?.name ?? "Request failed."] }; }
function failedSourceMap(response: HttpResponse): ReturnType<typeof parseSourceMap> { return { url: safeUrlForReport(response.finalUrl), classification: /\/_next\/static\//.test(response.finalUrl) ? "nextjs-public-source-map-review" : "generic-source-map-review", severityHint: "low", reason: response.error?.name ?? "Source-map request failed.", parseStatus: requestFailureStatus(response), transientSensitivity: [] }; }
function requestFailureStatus(response: HttpResponse): "BUDGET_EXHAUSTED" | "CANCELLED" | "OUT_OF_SCOPE" | "REQUEST_FAILED" { if (response.error?.name === "RequestBudgetExceeded") return "BUDGET_EXHAUSTED"; if (/cancel/i.test(response.error?.name ?? "")) return "CANCELLED"; if (/scope/i.test(response.error?.name ?? "")) return "OUT_OF_SCOPE"; return "REQUEST_FAILED"; }
function responseForUrl(responses: HttpResponse[], url: string): HttpResponse | undefined { return responses.find((response) => response.requestedUrl === url || response.finalUrl === url); }
function concreteRouteFromUrl(url: string): string | undefined { try { const parsed = new URL(url); if (parsed.pathname.startsWith("/_next/") || parsed.pathname.startsWith("/api/") || /\.[a-z0-9]{2,8}$/i.test(parsed.pathname)) return undefined; return `${parsed.pathname}${parsed.search}`; } catch { return undefined; } }
function dataRouteToConcreteRoute(url: string): string | undefined { try { const parsed = new URL(url), match = /^\/_next\/data\/[^/]+\/(.+)\.json$/.exec(parsed.pathname); if (!match?.[1]) return undefined; const route = match[1] === "index" ? "/" : `/${match[1].replace(/\/index$/, "")}`; return isDynamicRouteTemplate(route) ? undefined : `${route}${parsed.search}`; } catch { return undefined; } }
function logicalSurfaceKey(url: string): string { try { const parsed = new URL(url); parsed.hash = ""; parsed.pathname = parsed.pathname.replace(/^\/_next\/data\/[^/]+\//, "/").replace(/\.json$/, "").replace(/\/index$/, "/"); for (const key of [...parsed.searchParams.keys()]) if (/^_rsc$|token|secret|session|auth|key/i.test(key)) parsed.searchParams.set(key, "<redacted>"); return `${parsed.origin}${parsed.pathname}${parsed.search}`; } catch { return url.replace(/\/_next\/data\/[^/]+\//, "/"); } }
function logicalAssetKey(url: string): string { return logicalSurfaceKey(url).replace(/([._-])[a-f0-9]{6,}(?=\.(?:js|css|map)|[._-])/gi, "$1<hash>").replace(/\/_next\/static\/[^/]+\//, "/_next/static/<build>/"); }
function stableFindingId(type: FindingType, url: string, fieldPath: string): string { return `finding-${createHash("sha256").update(`${type}:${logicalAssetKey(url)}:${safeFieldPath(fieldPath)}`).digest("hex").slice(0, 16)}`; }
function titleForFinding(type: FindingType): string { if (type === "Next.js Source Map Sensitive Data Exposure") return "Next.js source map exposes sensitive security material"; if (type === "Next.js Public Runtime Secret Exposure") return "Next.js public runtime configuration exposes a secret"; if (type === "Next.js Shared Cache Private Data Exposure") return "Next.js shared cache exposes private data to a public actor"; if (type === "Next.js Cross-Actor Data Exposure") return "Next.js data surface exposes protected data across actors"; return "Next.js public serialized data exposes sensitive material"; }
function impactForFinding(type: FindingType): string { return type.includes("Cache") || type.includes("Cross-Actor") ? "A protected representation was reproduced through an actor that should not receive the same sensitive value." : "Sensitive server-derived material is present in a browser-retrievable Next.js representation."; }
function recommendationForFinding(type: FindingType): string { if (type.includes("Source Map")) return "Remove the secret from source and history, rotate it where applicable, prevent sensitive build-time values from entering browser bundles/maps, and apply an appropriate production source-map publication policy."; if (type.includes("Cache")) return "Prevent shared caching of user-specific representations and ensure cache keys and directives account for the relevant authentication state."; return "Remove server-only fields before serialization, return only client-required data, and enforce authorization before producing the Next.js payload."; }
function safeFieldPath(value: string): string { return value.replace(/[^a-zA-Z0-9_$.[\]-]/g, "_").slice(0, 512) || "unknown"; }
function safeUrlForReport(value: string): string { try { const url = new URL(value); url.username = ""; url.password = ""; for (const key of [...url.searchParams.keys()]) if (/token|secret|session|cookie|auth|password|key|jwt|^_rsc$/i.test(key)) url.searchParams.set(key, "<redacted>"); return url.toString(); } catch { return value; } }
function headerValue(headers: Readonly<Record<string, string | readonly string[]>>, name: string): string | undefined { const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1]; return typeof entry === "string" ? entry : entry?.join(", "); }
function boundedNumber(value: unknown, fallback: number, maximum: number, allowZero = false): number { return typeof value === "number" && Number.isInteger(value) && value <= maximum && (allowZero ? value >= 0 : value > 0) ? value : fallback; }
function throwIfCancelled(context: ScanContext): void { if (context.options.abortSignal?.aborted) throw context.options.abortSignal.reason instanceof Error ? context.options.abortSignal.reason : new Error("Next.js review cancelled."); }
function syntheticResponse(url: string): HttpResponse { return { requestedUrl: url, finalUrl: url, method: "GET", statusCode: 200, headers: {}, responseTimeMs: 0, redirectChain: [], bodyHash: shortFingerprint(url) }; }
function dedupeSurfaces(surfaces: NextJsSurface[]): NextJsSurface[] { const seen = new Set<string>(); return surfaces.filter((item) => { const key = `${item.surfaceType}:${item.actor}:${item.normalizedUrl}`; if (seen.has(key)) return false; seen.add(key); return true; }).slice(0, 500); }
function dedupeFindings(findings: Finding[]): Finding[] { const seen = new Set<string>(); return findings.filter((finding) => { if (seen.has(finding.id)) return false; seen.add(finding.id); return true; }); }
