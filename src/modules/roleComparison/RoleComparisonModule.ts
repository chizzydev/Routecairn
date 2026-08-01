import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import { summarizeAuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { RoleComparisonResult, RoleComparisonReport } from "../../reports/ReportTypes.js";

export class RoleComparisonModule implements RouteCairnPlugin {
  public readonly name = "role-comparison";
  public readonly description = "Compares anonymous, account A, and account B access safely.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const profileSet = context.options.authProfileSet;
    const report = profileSet ? await compareRoles(context) : disabledReport();

    return {
      pluginName: this.name,
      roleComparison: report,
      notes: report.notes
    };
  }
}

async function compareRoles(context: ScanContext): Promise<RoleComparisonReport> {
  const profileSet = context.options.authProfileSet;
  if (!profileSet) {
    return disabledReport();
  }

  const candidates = candidateUrls(context);
  const anonymousByUrl = responseMap(context.state.getResponses());
  const compareClient = context.createHttpClient();
  const accountAHeaders = authHeadersForProfile(profileSet.accountA);
  const accountBHeaders = authHeadersForProfile(profileSet.accountB);
  const results: RoleComparisonResult[] = [];

  for (const url of candidates) {
    const anonymous = anonymousByUrl.get(url) ?? (await compareClient.send({ url, method: "GET" }));
    const accountA = await compareClient.send({ url, method: "GET", headers: accountAHeaders });
    const accountB = await compareClient.send({ url, method: "GET", headers: accountBHeaders });
    results.push(toRoleResult(url, anonymous, accountA, accountB, context));
  }

  return {
    profileSet: summarizeAuthProfileSet(profileSet),
    comparedUrls: results.length,
    accountAOnly: results.filter((result) => result.classification === "account-a-only"),
    accountBOnly: results.filter((result) => result.classification === "account-b-only"),
    bothAuthenticatedAccess: results.filter((result) => result.classification === "both-authenticated-access"),
    onlyAuthenticatedAccess: results.filter((result) => result.classification === "only-authenticated-access"),
    results,
    notes: [
      "Role comparison uses safe GET requests only.",
      "Results are labelled needs manual verification because authorization intent must be confirmed before calling a bug.",
      "Private response bodies are not stored; report evidence is status, redirects, hashes, titles, and lengths."
    ]
  };
}

function disabledReport(): RoleComparisonReport {
  return {
    profileSet: summarizeAuthProfileSet(undefined),
    comparedUrls: 0,
    accountAOnly: [],
    accountBOnly: [],
    bothAuthenticatedAccess: [],
    onlyAuthenticatedAccess: [],
    results: [],
    notes: ["No account A/account B profiles supplied. Run with --auth-a and --auth-b to compare roles."]
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
    .slice(0, context.moduleSettings("role-comparison").maxComparisons ?? 40);
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

function toRoleResult(url: string, anonymous: HttpResponse, accountA: HttpResponse, accountB: HttpResponse, context: ScanContext): RoleComparisonResult {
  const profileSet = context.options.authProfileSet;
  if (!profileSet) {
    throw new Error("Role comparison requires authProfileSet.");
  }

  const classification = classifyRole(anonymous, accountA, accountB);

  return {
    url,
    method: "GET",
    anonymous: summarizeResponse(anonymous),
    accountA: summarizeResponse(accountA),
    accountB: summarizeResponse(accountB),
    classification,
    needsManualVerification: true,
    reason: reasonFor(classification, anonymous, accountA, accountB),
    proof: {
      anonymousCurlCommand: redactedCurlCommand(url),
      accountACurlCommand: redactedCurlCommand(url, profileSet.accountA),
      accountBCurlCommand: redactedCurlCommand(url, profileSet.accountB),
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

function classifyRole(anonymous: HttpResponse, accountA: HttpResponse, accountB: HttpResponse): RoleComparisonResult["classification"] {
  if (accountA.error || accountB.error || !accountA.statusCode || !accountB.statusCode) {
    return "role-error";
  }

  const anonymousAccess = isSuccessful(anonymous);
  const accountAAccess = isSuccessful(accountA);
  const accountBAccess = isSuccessful(accountB);

  if (accountAAccess && !accountBAccess) {
    return "account-a-only";
  }

  if (!accountAAccess && accountBAccess) {
    return "account-b-only";
  }

  if (!anonymousAccess && accountAAccess && accountBAccess) {
    return "only-authenticated-access";
  }

  if (anonymousAccess && accountAAccess && accountBAccess) {
    if (sameMaterialResponse(anonymous, accountA) && sameMaterialResponse(accountA, accountB)) {
      return "same-as-anonymous";
    }

    if (!sameMaterialResponse(accountA, accountB)) {
      return "both-authenticated-access";
    }

    return "both-authenticated-access";
  }

  return "inconclusive";
}

function reasonFor(classification: RoleComparisonResult["classification"], anonymous: HttpResponse, accountA: HttpResponse, accountB: HttpResponse): string {
  const statuses = `anonymous=${anonymous.statusCode ?? "error"}, accountA=${accountA.statusCode ?? "error"}, accountB=${accountB.statusCode ?? "error"}`;

  switch (classification) {
    case "account-a-only":
      return `Account A can access, but Account B cannot (${statuses}). Verify whether this matches intended ownership or role rules.`;
    case "account-b-only":
      return `Account B can access, but Account A cannot (${statuses}). Verify whether this matches intended ownership or role rules.`;
    case "only-authenticated-access":
      return `Anonymous access was blocked while both authenticated accounts could access (${statuses}). This is expected for private areas but useful for manual review.`;
    case "both-authenticated-access":
      return `Both accounts can access, but content or routing may differ (${statuses}). Review whether the behavior matches expected account boundaries.`;
    case "same-as-anonymous":
      return `Anonymous, Account A, and Account B responses looked materially similar (${statuses}).`;
    case "role-error":
      return `At least one account comparison request failed (${statuses}).`;
    case "inconclusive":
    default:
      return `The three-way role comparison did not produce a confident access pattern (${statuses}).`;
  }
}

function sameMaterialResponse(left: HttpResponse, right: HttpResponse): boolean {
  return left.statusCode === right.statusCode && left.finalUrl === right.finalUrl && left.title === right.title && Boolean(left.bodyHash && right.bodyHash && left.bodyHash === right.bodyHash);
}

function isSuccessful(response: HttpResponse): boolean {
  return typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 400;
}
