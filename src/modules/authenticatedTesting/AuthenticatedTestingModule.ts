import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import { authHeadersForProfile, redactedCurlCommand, summarizeAuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { AuthComparisonResult, AuthenticatedScanReport } from "../../reports/ReportTypes.js";

export class AuthenticatedTestingModule implements RouteCairnPlugin {
  public readonly name = "authenticated-testing";
  public readonly description = "Compares anonymous and authenticated responses without storing auth material.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const profile = context.options.authProfile;
    const report = profile ? await compareAuthenticatedSurfaces(context, profile) : disabledReport();

    return {
      pluginName: this.name,
      authenticatedScan: report,
      notes: report.notes
    };
  }
}

async function compareAuthenticatedSurfaces(context: ScanContext, profile: AuthProfile): Promise<AuthenticatedScanReport> {
  const candidates = candidateUrls(context);
  const anonymousByUrl = responseMap(context.state.getResponses());
  const compareClient = context.createHttpClient();
  const authHeaders = authHeadersForProfile(profile);
  const results: AuthComparisonResult[] = [];
  const notes = [
    "Authenticated requests used the supplied profile, but auth values are redacted from report output.",
    "Only response summaries are stored for authenticated requests; private response bodies are not stored."
  ];

  for (const url of candidates) {
    const anonymous = anonymousByUrl.get(url) ?? (await compareClient.send({ url, method: "GET" }));
    const authenticated = await compareClient.send({ url, method: "GET", headers: authHeaders });
    results.push(toComparison(url, anonymous, authenticated, profile));
  }

  return {
    profile: summarizeAuthProfile(profile),
    comparedUrls: results.length,
    authOnlySurfaces: results.filter((result) => result.classification === "auth-only"),
    changedSurfaces: results.filter((result) => result.classification === "changed-content"),
    results,
    notes
  };
}

function disabledReport(): AuthenticatedScanReport {
  return {
    profile: summarizeAuthProfile(undefined),
    comparedUrls: 0,
    authOnlySurfaces: [],
    changedSurfaces: [],
    results: [],
    notes: ["No auth profile supplied. Run with --auth ./examples/auth.example.json to compare public and authenticated behavior."]
  };
}

function candidateUrls(context: ScanContext): string[] {
  const target = context.scopeMatcher.decide(context.options.target, "GET").normalizedUrl ?? context.options.target;
  const urls = new Set<string>([target]);

  for (const observation of context.state.getDiscoveredUrls()) {
    if (observation.falsePositiveStatus !== "likely-false-positive") {
      urls.add(observation.url);
    }
  }

  for (const endpoint of context.state.getApiMapper()?.endpoints ?? []) {
    urls.add(endpoint.endpoint);
  }

  for (const surface of context.state.getAuthSurface()?.surfaces ?? []) {
    urls.add(surface.endpoint);
  }

  for (const candidate of context.state.getQueuedPathCandidates()) {
    try {
      urls.add(new URL(candidate.path, target).toString());
    } catch {
      // Ignore malformed candidates here; scope validation elsewhere already reports them.
    }
  }

  return [...urls]
    .filter((url) => context.scopeMatcher.decide(url, "GET").allowed)
    .slice(0, context.moduleSettings("authenticated-testing").maxComparisons ?? 40);
}

function responseMap(responses: HttpResponse[]): Map<string, HttpResponse> {
  const map = new Map<string, HttpResponse>();
  for (const response of responses) {
    if (!response.error) {
      map.set(response.requestedUrl, response);
      map.set(response.finalUrl, response);
    }
  }
  return map;
}

function toComparison(url: string, anonymous: HttpResponse, authenticated: HttpResponse, profile: AuthProfile): AuthComparisonResult {
  const classification = classify(anonymous, authenticated);

  return {
    url,
    method: "GET",
    anonymous: summarizeResponse(anonymous),
    authenticated: summarizeResponse(authenticated),
    classification,
    reason: reasonFor(classification, anonymous, authenticated),
    proof: {
      anonymousCurlCommand: redactedCurlCommand(url),
      authenticatedCurlCommand: redactedCurlCommand(url, profile),
      authMaterialRedacted: true
    }
  };
}

function summarizeResponse(response: HttpResponse) {
  return {
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response.finalUrl ? { finalUrl: response.finalUrl } : {}),
    ...(response.title ? { title: response.title } : {}),
    ...(response.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
    ...(response.redirectChain.length > 0 ? { redirectChain: response.redirectChain } : {}),
    ...(response.error ? { error: response.error.message } : {})
  };
}

function classify(anonymous: HttpResponse, authenticated: HttpResponse): AuthComparisonResult["classification"] {
  if (authenticated.error || !authenticated.statusCode) {
    return "auth-error";
  }

  if (!anonymous.statusCode) {
    return "inconclusive";
  }

  if (isDeniedOrLogin(anonymous) && isSuccessful(authenticated)) {
    return "auth-only";
  }

  if (isSuccessful(anonymous) && isSuccessful(authenticated)) {
    if (anonymous.bodyHash && authenticated.bodyHash && anonymous.bodyHash === authenticated.bodyHash) {
      return "same-access";
    }

    const delta = Math.abs((anonymous.contentLength ?? 0) - (authenticated.contentLength ?? 0));
    if (delta > 150 || anonymous.title !== authenticated.title || anonymous.finalUrl !== authenticated.finalUrl) {
      return "changed-content";
    }

    return "same-access";
  }

  return "inconclusive";
}

function reasonFor(classification: AuthComparisonResult["classification"], anonymous: HttpResponse, authenticated: HttpResponse): string {
  switch (classification) {
    case "auth-only":
      return `Anonymous response looked denied/login-gated (${anonymous.statusCode ?? "error"}), while authenticated response was reachable (${authenticated.statusCode ?? "error"}).`;
    case "changed-content":
      return "Both responses were reachable, but status/title/redirect/body hash/length differed enough to justify manual review.";
    case "same-access":
      return "Anonymous and authenticated responses looked materially similar from status, redirect, title, hash, and length signals.";
    case "auth-error":
      return `Authenticated request failed: ${authenticated.error?.message ?? "unknown error"}.`;
    case "inconclusive":
    default:
      return "The comparison did not produce enough evidence for a confident access classification.";
  }
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 400;
}

function isDeniedOrLogin(response: HttpResponse): boolean {
  if (response.statusCode === 401 || response.statusCode === 403 || response.statusCode === 404) {
    return true;
  }

  const finalUrl = response.finalUrl.toLowerCase();
  const title = response.title?.toLowerCase() ?? "";
  return response.statusCode !== undefined && response.statusCode >= 300 && response.statusCode < 400 && /login|signin|sign-in|auth|account/.test(finalUrl + " " + title);
}
