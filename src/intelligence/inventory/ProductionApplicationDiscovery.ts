import { createHash } from "node:crypto";
import { load } from "cheerio";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import type { TargetAuthorization } from "../../core/authorization/TargetAuthorization.js";
export const PRODUCTION_DISCOVERY_ALGORITHM = "production-native-discovery-v1";
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
export function structuralUrl(value: string, base?: string) {
  try {
    const u = new URL(value, base);
    if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || value.length > 4096) return;
    const parts = u.pathname
      .split("/")
      .map((p, i, a) =>
        p.length > 40 ||
        /^\d+$/.test(p) ||
        /^[a-f0-9-]{32,}$/i.test(p) ||
        (/^(?:users?|accounts?|sessions?|customers?)$/i.test(a[i - 1] ?? "") &&
          !/^(?:me|login|logout|register|refresh)$/.test(p))
          ? ":id"
          : p
      );
    return { origin: u.origin, path: parts.join("/").slice(0, 240), hadQuery: !!u.search };
  } catch {
    return;
  }
}
export interface PublicDocumentObservation {
  url: string;
  responseFingerprint: string;
  complete: boolean;
  framework: "NEXTJS" | "UNKNOWN";
  candidates: {
    origin: string;
    path: string;
    source: "HTML_SCRIPT" | "HTML_LINK" | "HTML_FORM" | "HTML_METADATA" | "HEADER_LINK";
    evidenceFingerprint: string;
  }[];
  candidateBoundExceeded: boolean;
}
export function observePublicDocument(
  body: string,
  url: string,
  headers: Readonly<Record<string, string | readonly string[]>>,
  complete: boolean
): PublicDocumentObservation {
  const out: PublicDocumentObservation = {
    url,
    responseFingerprint: hash(body),
    complete,
    framework: /__NEXT_DATA__|\/_next\/static\/|self\.__next_f/.test(body) ? "NEXTJS" : "UNKNOWN",
    candidates: [],
    candidateBoundExceeded: false
  };
  if (Buffer.byteLength(body) > 1024 * 1024) {
    out.complete = false;
    return out;
  }
  const add = (raw: string | undefined, source: PublicDocumentObservation["candidates"][number]["source"]) => {
    if (!raw) return;
    const u = structuralUrl(raw, url);
    if (!u) return;
    if (out.candidates.length >= 128) {
      out.candidateBoundExceeded = true;
      out.complete = false;
      return;
    }
    if (!out.candidates.some((c) => c.origin === u.origin && c.path === u.path && c.source === source))
      out.candidates.push({ origin: u.origin, path: u.path, source, evidenceFingerprint: hash(source + "\0" + raw) });
  };
  const $ = load(body);
  $("script[src]").each((_, e) => add($(e).attr("src"), "HTML_SCRIPT"));
  $("a[href],link[href]").each((_, e) => add($(e).attr("href"), $(e).is("a") ? "HTML_LINK" : "HTML_METADATA"));
  $("form[action]").each((_, e) => add($(e).attr("action"), "HTML_FORM"));
  $("meta[content]").each((_, e) => {
    const v = $(e).attr("content");
    if (v && /^https?:\/\//.test(v)) add(v, "HTML_METADATA");
  });
  for (const [k, v] of Object.entries(headers ?? {}))
    if (k.toLowerCase() === "link") for (const m of String(v).matchAll(/<([^>]+)>/g)) add(m[1], "HEADER_LINK");
  return out;
}
export function projectProductionDiscovery(
  report: RouteCairnReport,
  authorization: TargetAuthorization,
  sourceReportSha256: string,
  sourceHints: readonly { url: string; sourceSha256: string }[] = []
) {
  const campaign = authorization.productionCampaign;
  if (!campaign) throw Error("PRODUCTION_CAMPAIGN_REQUIRED");
  const origins = new Map<
    string,
    {
      origin: string;
      approval: "APPROVED_CAMPAIGN_ORIGIN" | "REQUIRES_ORIGIN_REVIEW";
      evidence: { kind: string; fingerprint: string; statusCode?: number }[];
    }
  >();
  const routes = new Map<
    string,
    { origin: string; pathTemplate: string; classification: string; sources: string[]; executionAuthority: "NONE" }
  >();
  let candidatesDropped = 0;
  const origin = (url: string, kind: string, fp: string, statusCode?: number) => {
    const u = structuralUrl(url);
    if (!u) return;
    if (origins.size >= 128 && !origins.has(u.origin)) {
      candidatesDropped++;
      return;
    }
    let r = origins.get(u.origin);
    if (!r) {
      r = {
        origin: u.origin,
        approval: campaign.inScope.some((a) => a.origin === u.origin)
          ? "APPROVED_CAMPAIGN_ORIGIN"
          : "REQUIRES_ORIGIN_REVIEW",
        evidence: []
      };
      origins.set(u.origin, r);
    }
    if (r.evidence.length < 16 && !r.evidence.some((e) => e.kind === kind && e.fingerprint === fp))
      r.evidence.push({ kind, fingerprint: fp, ...(statusCode !== undefined ? { statusCode } : {}) });
  };
  const route = (url: string, base: string, source: string) => {
    const u = structuralUrl(url, base);
    if (!u) return;
    origin(u.origin, source, hash(url));
    if (!/^\/[A-Za-z0-9_./:{}$-]*$/.test(u.path)) return;
    const key = u.origin + u.path;
    if (routes.size >= 256 && !routes.has(key)) {
      candidatesDropped++;
      return;
    }
    let r = routes.get(key);
    if (!r) {
      r = {
        origin: u.origin,
        pathTemplate: u.path,
        classification: /auth|login|signin|sign-in|register|session|password/i.test(u.path)
          ? "AUTHENTICATION_SURFACE_CANDIDATE"
          : /^\/api(?:\/|$)/i.test(u.path)
            ? "API_ROUTE_CANDIDATE"
            : "PUBLIC_ROUTE_CANDIDATE",
        sources: [],
        executionAuthority: "NONE"
      };
      routes.set(key, r);
    }
    if (!r.sources.includes(source)) r.sources.push(source);
  };
  for (const response of report.responses.slice(0, 300)) {
    if (!response.error && response.statusCode !== undefined)
      origin(
        response.finalUrl,
        "NATIVE_HTTP_RESPONSE",
        response.bodyHash ?? hash(response.finalUrl),
        response.statusCode
      );
    for (const hop of response.redirectChain ?? []) {
      const u = structuralUrl(hop.location, response.requestedUrl);
      if (u) origin(u.origin, "HTTP_REDIRECT_DESTINATION", hash(hop.location), hop.statusCode);
    }
    if (response.redirectLocation) {
      const u = structuralUrl(response.redirectLocation, response.requestedUrl);
      if (u) origin(u.origin, "HTTP_REDIRECT_CANDIDATE", hash(response.redirectLocation), response.statusCode);
    }
  }
  for (const d of report.jsIntelligence?.applicationDocuments ?? [])
    for (const c of d.candidates) {
      origin(c.origin, c.source, c.evidenceFingerprint);
      route(c.origin + c.path, d.url, c.source);
    }
  for (const s of (report.jsIntelligence?.scripts ?? []).slice(0, 100)) {
    origin(
      s.scriptUrl,
      s.downloaded ? "APPROVED_STATIC_ASSET_RESPONSE" : "STATIC_ASSET_CANDIDATE",
      s.responseFingerprint ?? hash(s.scriptUrl)
    );
    if (s.downloaded)
      for (const u of [...s.absoluteUrls, ...s.endpoints].slice(0, 256))
        route(u, s.scriptUrl, "PUBLIC_ASSET_LITERAL_HINT");
  }
  for (const n of (report.browserCrawl?.networkRequests ?? []).slice(0, 300)) {
    origin(
      n.url,
      n.transmitted ? "BROWSER_REQUEST_SENT" : "BROWSER_REQUEST_ATTEMPT_BLOCKED",
      hash(n.url + "\0" + n.method)
    );
    route(
      n.url,
      report.target,
      ["xhr", "fetch"].includes(n.resourceType)
        ? "BROWSER_API_CALL_" + (n.transmitted ? "SENT" : "BLOCKED")
        : "BROWSER_" + n.resourceType.toUpperCase()
    );
  }
  for (const h of sourceHints.slice(0, 20))
    origin(h.url, "SOURCE_CONFIGURATION_HINT_NOT_DEPLOYMENT_PROOF", h.sourceSha256);
  for (const m of report.nextJsReview?.manifests ?? [])
    for (const r of m.routes.slice(0, 100)) route(r, m.url, "APPROVED_MANIFEST_DECLARATION");
  const cases = campaign.requests.map((c, index) => {
    const audit = report.requestAudit.filter(
      (a) =>
        a.method === c.method &&
        structuralUrl(a.requestedUrl)?.origin === c.origin &&
        new URL(a.requestedUrl).pathname === c.path &&
        a.outcome === "sent"
    );
    const native =
      report.apiGraphql?.checks
        .filter(
          (x) =>
            x.routeAliases.includes("campaign-control-" + index) &&
            report.scanPlan.apiGraphql?.routes.some(
              (r) => r.id === "campaign-control-" + index && r.urlFingerprint === hash(c.origin + c.path)
            )
        )
        .flatMap((x) => x.requests.filter((r) => r.method === c.method).map((r) => r.statusCode ?? null)) ?? [];
    const statuses = audit.length ? audit.map((a) => a.statusCode ?? null) : native;
    return {
      origin: c.origin,
      pathTemplate: c.path,
      method: c.method,
      expectedStatuses: c.expectedStatuses,
      observedStatuses: statuses,
      outcome: !statuses.length
        ? "UNTESTED"
        : statuses.every((status) => status !== null && c.expectedStatuses.includes(status))
          ? "EXPECTED_HTTP_CONTROL_OBSERVED"
          : "INCONCLUSIVE_UNEXPECTED_RESPONSE",
      meaning: "HTTP assertion only; no application security conclusion"
    };
  });
  return {
    algorithm: PRODUCTION_DISCOVERY_ALGORITHM,
    sourceReportSha256,
    campaignId: campaign.campaignId,
    entry: structuralUrl(report.target),
    execution: report.execution?.status ?? "UNKNOWN",
    origins: [...origins.values()].sort((a, b) => a.origin.localeCompare(b.origin)),
    routeFamilies: [...routes.values()].sort((a, b) =>
      (a.origin + a.pathTemplate).localeCompare(b.origin + b.pathTemplate)
    ),
    publicControls: cases,
    requestBudget: campaign.maxRequests,
    requestsTransmitted: report.requestAudit.filter((a) => a.outcome === "sent").length,
    blockedRequests: report.requestAudit.filter((a) => a.outcome !== "sent").length,
    publicDocuments: report.jsIntelligence?.applicationDocuments ?? [],
    browser: report.browserCrawl
      ? {
          coverage: report.browserCrawl.networkRequests.some((n) => n.transmitted)
            ? "PARTIAL_NATIVE_BROWSER_OBSERVATION"
            : "UNTESTED_NO_TRANSMISSION",
          transmittedRequests: report.browserCrawl.networkRequests.filter((n) => n.transmitted).length,
          blockedRequests: report.browserCrawl.networkRequests.filter((n) => !n.transmitted).length,
          policyReasons: [...new Set((report.browserCrawl.policyEvents ?? []).map((e) => e.reason))],
          navigationAttempts: report.browserCrawl.visitedPages?.map((p) => ({
            url: structuralUrl(p.url),
            depth: p.depth
          })),
          formsDetected: report.browserCrawl.formsDetected,
          formsSubmitted: report.browserCrawl.formsSubmitted,
          networkIsolation: report.browserCrawl.networkIsolation
        }
      : null,
    findingsForReview: report.findings.map((f) => ({
      type: f.type,
      severity: f.severity,
      sourceModule: f.sourceModule,
      confidence: f.confidence,
      requiresHumanReview: true
    })),
    confirmedBusinessVulnerabilities: [],
    candidateBoundExceeded: candidatesDropped > 0,
    missingTests: [
      "Fresh controlled authenticated identities and exact ownership policies",
      "Historical refresh rotation/replay deployed remediation",
      "Customer and tenant isolation not inferred from public checks",
      "State-changing rollback contracts remain separate",
      "Unapproved origins/routes, third-party providers and private customer data",
      "Hidden server endpoints and unobserved branches"
    ],
    applicationSecureConclusion: false,
    independentAccuracy: false,
    scopeExpandedAutomatically: false
  };
}
