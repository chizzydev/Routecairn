import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { NextJsDataRouteReview, NextJsReviewReport, NextJsSourceMapReview } from "../../reports/ReportTypes.js";

export class NextJsReviewModule implements RouteCairnPlugin {
  public readonly name = "nextjs-review";
  public readonly description = "Reviews Next.js data routes, build IDs, cache behavior, and source-map exposure without overstating normal assets.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await reviewNextJs(context);

    return {
      pluginName: this.name,
      nextJsReview: report,
      notes: report.notes
    };
  }
}

async function reviewNextJs(context: ScanContext): Promise<NextJsReviewReport> {
  const isNext = context.state.getTechnologies().some((technology) => technology.name === "Next.js") || hasNextSignals(context.state.getResponses());

  if (!isNext) {
    return {
      detected: false,
      buildIds: [],
      dataRoutes: [],
      sourceMaps: [],
      cacheSignals: [],
      notes: ["Next.js was not detected; Next.js review skipped."]
    };
  }

  const buildIds = discoverBuildIds(context.state.getResponses());
  const client = context.createHttpClient();
  const dataRoutes: NextJsDataRouteReview[] = [];

  for (const url of dataRouteCandidates(context, buildIds).slice(0, context.moduleSettings("nextjs-review").maxDataRoutes ?? 25)) {
    const decision = context.scopeMatcher.decide(url, "GET");
    context.state.recordScopeDecision(decision);
    if (!decision.allowed || !decision.normalizedUrl) continue;
    const response = await client.send({ url: decision.normalizedUrl, method: "GET" });
    dataRoutes.push(toDataRouteReview(response));
  }

  const sourceMaps = sourceMapReviews(context);
  const cacheSignals = dataRoutes
    .filter((route) => route.cacheRisk !== "normal-public-cache")
    .map((route) => `${route.url}: ${route.cacheRisk}`);

  return {
    detected: true,
    buildIds,
    dataRoutes,
    sourceMaps,
    cacheSignals,
    notes: [
      `Next.js review ran with ${buildIds.length} build ID signal(s), ${dataRoutes.length} data route review(s), and ${sourceMaps.length} source map classification(s).`,
      "Normal _next/static assets are expected in public Next.js applications and are not treated as vulnerabilities by themselves.",
      "Data route or source map signals require manual review for private data, cacheability, or source disclosure impact."
    ]
  };
}

function hasNextSignals(responses: HttpResponse[]): boolean {
  return responses.some((response) => /_next\/static|__NEXT_DATA__|x-powered-by.+next/i.test(`${bodyPreviewForAnalysis(response) ?? ""} ${JSON.stringify(headersForAnalysis(response))}`));
}

function discoverBuildIds(responses: HttpResponse[]): string[] {
  const ids = new Set<string>();

  for (const response of responses) {
    const body = bodyPreviewForAnalysis(response) ?? "";
    const nextDataMatch = /"buildId"\s*:\s*"(?<buildId>[^"]+)"/i.exec(body);
    if (nextDataMatch?.groups?.buildId) ids.add(nextDataMatch.groups.buildId);

    for (const match of body.matchAll(/\/_next\/(?:data|static)\/([^/"'?#]+)/g)) {
      const id = match[1];
      if (id && !["chunks", "css", "media", "webpack"].includes(id)) ids.add(id);
    }

    const pathMatch = /\/_next\/data\/([^/]+)\//.exec(response.finalUrl);
    if (pathMatch?.[1]) ids.add(pathMatch[1]);
  }

  return [...ids].sort();
}

function dataRouteCandidates(context: ScanContext, buildIds: string[]): string[] {
  const urls = new Set<string>();
  const base = context.scopeMatcher.decide(context.options.target, "GET").normalizedUrl ?? context.options.target;
  const candidates = [
    ...context.state.getDiscoveredUrls().map((observation) => observation.url),
    ...context.state.getResponses().map((response) => response.finalUrl),
    ...(context.state.getJsIntelligence()?.queuedEndpoints ?? []).map((candidate) => new URL(candidate.path, base).toString())
  ];

  for (const value of candidates) {
    const parsed = safeUrl(value, base);
    if (!parsed) continue;
    if (/\/_next\/data\//.test(parsed.pathname)) {
      urls.add(parsed.toString());
      continue;
    }

    if (buildIds.length > 0 && isPageLikePath(parsed.pathname)) {
      const routePath = parsed.pathname === "/" ? "/index" : parsed.pathname.replace(/\/$/, "");
      for (const buildId of buildIds) urls.add(new URL(`/_next/data/${buildId}${routePath}.json${parsed.search}`, base).toString());
    }
  }

  return [...urls].sort();
}

function toDataRouteReview(response: HttpResponse): NextJsDataRouteReview {
  const analysisHeaders = headersForAnalysis(response);
  const contentType = response.contentType ?? headerValue(analysisHeaders, "content-type") ?? "";
  const cacheControl = headerValue(analysisHeaders, "cache-control");
  const body = bodyPreviewForAnalysis(response) ?? "";
  const dataIndicators = dataLeakageIndicators(body);
  const cacheRisk = classifyCacheRisk(response.statusCode, cacheControl, dataIndicators);

  return {
    url: response.finalUrl,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(contentType ? { contentType } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(cacheControl ? { cacheControl } : {}),
    dataIndicators,
    cacheRisk,
    notes: notesForDataRoute(response.statusCode, contentType, cacheRisk, dataIndicators)
  };
}

function sourceMapReviews(context: ScanContext): NextJsSourceMapReview[] {
  const urls = new Set<string>(context.state.getJsIntelligence()?.sourceMaps ?? []);

  for (const response of context.state.getResponses()) {
    if (response.finalUrl.endsWith(".map")) urls.add(response.finalUrl);
  }

  return [...urls].sort().map((url) => {
    const isNextStatic = /\/_next\/static\//.test(url);
    return {
      url,
      classification: isNextStatic ? "nextjs-public-source-map-review" : "generic-source-map-review",
      severityHint: isNextStatic ? "low" : "medium",
      reason: isNextStatic
        ? "Public Next.js source maps can reveal frontend source and routes, but normal static assets alone are not a vulnerability. Review for sensitive comments, endpoints, or source disclosure impact."
        : "Source map is publicly reachable outside the normal Next.js static path. Review exposure impact."
    };
  });
}

function classifyCacheRisk(statusCode: number | undefined, cacheControl: string | undefined, dataIndicators: string[]): NextJsDataRouteReview["cacheRisk"] {
  if (!statusCode || statusCode >= 400) return "not-reachable";
  const cache = cacheControl?.toLowerCase() ?? "";
  if (dataIndicators.length > 0 && /(public|s-maxage|max-age=\d+)/.test(cache) && !/(private|no-store)/.test(cache)) return "possible-private-data-cache";
  if (dataIndicators.length > 0) return "data-needs-review";
  return "normal-public-cache";
}

function dataLeakageIndicators(body: string): string[] {
  const indicators: string[] = [];
  if (/"(?:email|phone|address|token|session|role|user|account|customer)"\s*:/i.test(body)) indicators.push("sensitive-keywords");
  if (/"props"\s*:|"pageProps"\s*:/i.test(body)) indicators.push("nextjs-page-props");
  if (/"__N_SSP"\s*:\s*true|"__N_SSG"\s*:\s*true/i.test(body)) indicators.push("nextjs-render-mode");
  return [...new Set(indicators)];
}

function notesForDataRoute(statusCode: number | undefined, contentType: string, cacheRisk: NextJsDataRouteReview["cacheRisk"], indicators: string[]): string[] {
  const notes: string[] = [];
  if (statusCode && statusCode < 400) notes.push("_next/data route is reachable and returned a successful response.");
  if (!/json/i.test(contentType)) notes.push("Response did not clearly identify as JSON; verify route behavior manually.");
  if (indicators.length > 0) notes.push(`Data indicators: ${indicators.join(", ")}.`);
  if (cacheRisk === "possible-private-data-cache") notes.push("Cache headers may allow shared caching of data-looking content; manually verify whether content is private.");
  if (cacheRisk === "normal-public-cache") notes.push("Looks like normal public cache/static behavior; do not overstate severity without private data evidence.");
  return notes;
}

function isPageLikePath(pathname: string): boolean {
  return !pathname.startsWith("/_next") && !pathname.startsWith("/api") && !/\.[a-z0-9]{2,5}$/i.test(pathname);
}

function safeUrl(value: string, base: string): URL | undefined {
  try { return new URL(value, base); } catch { return undefined; }
}

function headerValue(headers: Readonly<Record<string, string | readonly string[]>>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return typeof value === "string" ? value : value?.join(", ");
}
