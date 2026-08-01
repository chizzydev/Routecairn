import { authHeadersForProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { classifyStateAwareApiCandidate } from "../../intelligence/apiSafety/ApiCandidateClassifier.js";
import { classifyApiMethodSafety, safeApiMethods } from "../../intelligence/apiSafety/ApiMethodSafety.js";
import type { AuthResponseSummary, StateAwareApiEndpointReview, StateAwareApiReport } from "../../reports/ReportTypes.js";

const skippedMutatingMethods = ["POST", "PUT", "PATCH", "DELETE"];

export class StateAwareApiModule implements RouteCairnPlugin {
  public readonly name = "state-aware-api";
  public readonly description = "Safely reviews API access-control behavior using non-mutating methods.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await reviewStateAwareApi(context);

    return {
      pluginName: this.name,
      stateAwareApi: report,
      notes: report.notes
    };
  }
}

async function reviewStateAwareApi(context: ScanContext): Promise<StateAwareApiReport> {
  const endpoints = context.state.getApiMapper()?.endpoints ?? [];
  const candidates = endpoints
    .map((endpoint) => classifyStateAwareApiCandidate(endpoint))
    .filter((candidate) => typeof candidate !== "undefined")
    .sort((left, right) => priorityRank(right.priority) - priorityRank(left.priority))
    .slice(0, context.moduleSettings("state-aware-api").maxEndpointReviews ?? 30);

  const anonymousByUrl = responseMap(context.state.getResponses());
  const client = context.createHttpClient();
  const reviews: StateAwareApiEndpointReview[] = [];

  for (const candidate of candidates) {
    const safeMethodResults = [];
    const decision = context.scopeMatcher.decide(candidate.endpoint, "GET");

    if (!decision.allowed || !decision.normalizedUrl) {
      continue;
    }

    for (const method of safeApiMethods) {
      const methodDecision = classifyApiMethodSafety(method);
      const response = method === "GET" ? anonymousByUrl.get(candidate.endpoint) ?? (await client.send({ url: candidate.endpoint, method })) : await client.send({ url: candidate.endpoint, method });
      const allowHeader = headerValue(response.headers, "allow");
      const corsAllowMethods = headerValue(response.headers, "access-control-allow-methods");
      safeMethodResults.push({
        method,
        safety: methodDecision.safety,
        ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
        ...(response.contentType ? { contentType: response.contentType } : {}),
        ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
        ...(allowHeader ? { allowHeader } : {}),
        ...(corsAllowMethods ? { corsAllowMethods } : {}),
        ...(response.error ? { error: response.error.message } : {})
      });
    }

    const anonymous = anonymousByUrl.get(candidate.endpoint) ?? (await client.send({ url: candidate.endpoint, method: "GET" }));
    const authenticated = context.options.authProfile
      ? await client.send({ url: candidate.endpoint, method: "GET", headers: authHeadersForProfile(context.options.authProfile) })
      : undefined;
    const accountA = context.options.authProfileSet
      ? await client.send({ url: candidate.endpoint, method: "GET", headers: authHeadersForProfile(context.options.authProfileSet.accountA) })
      : undefined;
    const accountB = context.options.authProfileSet
      ? await client.send({ url: candidate.endpoint, method: "GET", headers: authHeadersForProfile(context.options.authProfileSet.accountB) })
      : undefined;

    reviews.push({
      endpoint: candidate.endpoint,
      routeType: candidate.routeType,
      candidateReasons: candidate.reasons,
      priority: candidate.priority,
      safeMethodsTested: safeMethodResults,
      skippedMethods: skippedMutatingMethods.map((method) => classifyApiMethodSafety(method)),
      accessComparison: {
        anonymous: summarizeResponse(anonymous),
        ...(authenticated ? { authenticated: summarizeResponse(authenticated) } : {}),
        ...(accountA ? { accountA: summarizeResponse(accountA) } : {}),
        ...(accountB ? { accountB: summarizeResponse(accountB) } : {}),
        signal: classifyAccessSignal(anonymous, authenticated, accountA, accountB),
        needsManualVerification: true
      },
      evidenceNotes: evidenceNotes(candidate.reasons)
    });
  }

  return {
    safeMethods: [...safeApiMethods],
    skippedMethods: skippedMutatingMethods,
    candidateCount: candidates.length,
    reviewedEndpoints: reviews,
    bolaIdorCandidates: reviews.filter((review) => review.candidateReasons.includes("object-id") || review.candidateReasons.includes("export-download")),
    notes: [
      "State-aware API testing uses GET, HEAD, and OPTIONS only.",
      "POST, PUT, PATCH, and DELETE are skipped by default to avoid mutating application state.",
      "Access-control signals are hypotheses for manual BOLA/IDOR review, not confirmed vulnerabilities.",
      "Private response bodies are not stored; evidence is status, headers, redirects, hashes, titles, and lengths."
    ]
  };
}

function classifyAccessSignal(anonymous: HttpResponse, authenticated?: HttpResponse, accountA?: HttpResponse, accountB?: HttpResponse): StateAwareApiEndpointReview["accessComparison"]["signal"] {
  if (accountA && accountB) {
    const aAccess = isSuccessful(accountA);
    const bAccess = isSuccessful(accountB);
    if (aAccess && !bAccess) {
      return "account-a-only";
    }
    if (!aAccess && bAccess) {
      return "account-b-only";
    }
    if (!isSuccessful(anonymous) && aAccess && bAccess) {
      return "only-authenticated-access";
    }
    if (aAccess && bAccess && !sameMaterialResponse(accountA, accountB)) {
      return "both-authenticated-different";
    }
  }

  if (authenticated && !isSuccessful(anonymous) && isSuccessful(authenticated)) {
    return "auth-only";
  }

  if (authenticated && isSuccessful(anonymous) && isSuccessful(authenticated) && !sameMaterialResponse(anonymous, authenticated)) {
    return "authenticated-different";
  }

  if (isSuccessful(anonymous)) {
    return "publicly-accessible";
  }

  return "inconclusive";
}

function evidenceNotes(reasons: string[]): string[] {
  const notes = ["Verify authorization intent with accounts you control before calling this a vulnerability."];

  if (reasons.includes("object-id")) {
    notes.push("Object identifier present; compare whether another account can access or infer ownership-bound data.");
  }

  if (reasons.includes("export-download")) {
    notes.push("Export/download route present; verify returned data belongs only to the requesting account.");
  }

  if (reasons.includes("sensitive-data")) {
    notes.push("Sensitive-data route; preserve minimal evidence and avoid storing private payloads.");
  }

  return notes;
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

function summarizeResponse(response: HttpResponse): AuthResponseSummary {
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

function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(", ") : value;
}

function sameMaterialResponse(left: HttpResponse, right: HttpResponse): boolean {
  return left.statusCode === right.statusCode && left.finalUrl === right.finalUrl && left.title === right.title && Boolean(left.bodyHash && right.bodyHash && left.bodyHash === right.bodyHash);
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 400;
}

function priorityRank(priority: "low" | "medium" | "high"): number {
  return { low: 0, medium: 1, high: 2 }[priority];
}
