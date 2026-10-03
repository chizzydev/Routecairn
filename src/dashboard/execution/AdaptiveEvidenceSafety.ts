import type { HttpResponse, RequestAuditEntry } from "../../core/http/HttpTypes.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { isReadOnlyGraphqlDocument } from "../../modules/apiGraphql/GraphqlDocumentSafety.js";

/** Evidence from an unknown or incomplete outcome cannot authorize replay. */
export function isConclusiveAdaptiveOutcome(value: unknown): boolean {
  return typeof value === "string" && /^(?:PASS|FAIL|ALLOW|DENY|PROVEN|SECURE_FOR_CASE|MUTATION_PROVEN|MUTATION_REJECTED|ACCESS_ALLOWED|ACCESS_DENIED|EMPTY_RESULT|SIGNED_URL_ISSUED|SIGNED_URL_DOWNLOAD_ALLOWED|SIGNED_URL_DOWNLOAD_DENIED)$/.test(value);
}

export function isVerifiedAdaptiveCleanup(value: unknown): boolean {
  return typeof value === "string" && /^(?:PASSED|VERIFIED|ROLLBACK_VERIFIED|RESTORED|SUCCESS)$/.test(value);
}

export function adaptiveHttpUrl(raw: string, base: string): URL | undefined {
  try {
    const url = new URL(raw, base);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return;
    return url;
  } catch { return; }
}

/** Hash this identity before retaining it: query values and concrete IDs are private. */
export function adaptiveRequestIdentity(raw: string, method: string, base: string): string | undefined {
  const url = adaptiveHttpUrl(raw, base);
  if (!url || !/^[A-Z]{2,12}$/.test(method.toUpperCase())) return;
  return `${method.toUpperCase()}:${url.origin}${url.pathname}${url.search}`;
}

export function adaptiveCredentialHeaderNames(report: RouteCairnReport): string[] {
  return [...new Set([...(report.authenticatedScan?.profile.headerNames ?? []), ...(report.roleComparison?.profileSet.accountA?.headerNames ?? []), ...(report.roleComparison?.profileSet.accountB?.headerNames ?? [])].map((name) => name.toLowerCase()))];
}

export function isAnonymousAdaptiveRequest(audit: RequestAuditEntry, credentialHeaderNames: readonly string[] = []): boolean {
  return audit.source !== "browser" && !Object.entries(audit.requestHeaders ?? {}).some(([name, value]) => credentialHeaderNames.includes(name.toLowerCase()) || /(?:authorization|cookie|api[-_]?key|auth[-_]?token|access[-_]?token|session)/i.test(name) || /(?:<redacted>|\[redacted\])/i.test(value));
}

/** Modern reports bind by request ID. Legacy reports need an unambiguous pair. */
export function exactAdaptiveResponse(audit: RequestAuditEntry, audits: readonly RequestAuditEntry[], responses: readonly HttpResponse[], base: string): HttpResponse | undefined {
  return createAdaptiveResponseMatcher(audits, responses, base)(audit);
}

/** Index once per report to keep graph acquisition linear in exchange count. */
export function createAdaptiveResponseMatcher(audits: readonly RequestAuditEntry[], responses: readonly HttpResponse[], base: string): (audit: RequestAuditEntry) => HttpResponse | undefined {
  const responseIndex = new Map<string, HttpResponse[]>();
  const responseIdentityCounts = new Map<string, number>();
  const responseIdCounts = new Map<string, number>();
  const auditCounts = new Map<string, number>();
  const idCounts = new Map<string, number>();
  for (const audit of audits) {
    if (audit.outcome !== "sent") continue;
    const identity = adaptiveRequestIdentity(audit.requestedUrl, audit.method, base); if (!identity) continue;
    auditCounts.set(identity, (auditCounts.get(identity) ?? 0) + 1);
    if (audit.requestId) idCounts.set(audit.requestId, (idCounts.get(audit.requestId) ?? 0) + 1);
  }
  for (const response of responses) {
    if (response.error || response.redirectChain?.length || !response.statusCode) continue;
    const identity = adaptiveRequestIdentity(response.requestedUrl, response.method, base);
    if (!identity || (response.finalUrl && adaptiveRequestIdentity(response.finalUrl, response.method, base) !== identity)) continue;
    const key = JSON.stringify([identity, response.statusCode, response.requestId ?? ""]);
    const bucket = responseIndex.get(key) ?? []; bucket.push(response); responseIndex.set(key, bucket);
    responseIdentityCounts.set(identity, (responseIdentityCounts.get(identity) ?? 0) + 1);
    if (response.requestId) responseIdCounts.set(response.requestId, (responseIdCounts.get(response.requestId) ?? 0) + 1);
  }
  return (audit) => {
    if (audit.outcome !== "sent" || audit.error || audit.redirectChain?.length || !audit.statusCode) return;
    const identity = adaptiveRequestIdentity(audit.requestedUrl, audit.method, base);
    if (!identity || (audit.finalUrl && adaptiveRequestIdentity(audit.finalUrl, audit.method, base) !== identity)) return;
    const matches = responseIndex.get(JSON.stringify([identity, audit.statusCode, audit.requestId ?? ""])) ?? [];
    if (matches.length !== 1) return;
    if (audit.requestId) return idCounts.get(audit.requestId) === 1 && responseIdCounts.get(audit.requestId) === 1 ? matches[0] : undefined;
    if (auditCounts.get(identity) !== 1 || responseIdentityCounts.get(identity) !== 1 || matches[0]?.requestId) return;
    return matches[0];
  };
}

export function isReadOnlyAdaptiveApiOperation(check: Record<string, unknown>, route: Record<string, unknown>, request: Record<string, unknown> | undefined, method: string): boolean {
  if (route.protocol === "GRAPHQL") {
    if (check.kind === "GRAPHQL_INTROSPECTION") return true;
    const documents = records(check.documents).length ? records(check.documents) : [record(request?.graphql)].filter((value): value is Record<string, unknown> => Boolean(value));
    return documents.length > 0 && documents.every((value) => {
      if (typeof value.document !== "string" || value.document.length > 65_536) return false;
      return isReadOnlyGraphqlDocument(value.document);
    });
  }
  const methods = check.kind === "METHOD_CONFUSION" ? [String(check.canonicalMethod), ...(Array.isArray(check.alternateMethods) ? check.alternateMethods.map(String) : [])] : [method];
  return methods.every((value) => ["GET", "HEAD", "OPTIONS"].includes(value) || (value === "POST" && route.operatorConfirmedNonMutatingPost === true && request?.operatorConfirmedNonMutating === true && typeof request.nonMutatingMarkerPath === "string" && request.nonMutatingMarkerValue !== undefined));
}
function record(value: unknown): Record<string, unknown> | undefined { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function records(value: unknown): Record<string, unknown>[] { return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(record(item))) : []; }
