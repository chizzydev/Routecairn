import { randomUUID } from "node:crypto";
import { createReadStream,existsSync,realpathSync,statSync } from "node:fs";
import type { IncomingMessage,ServerResponse } from "node:http";
import { extname,join,resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { ScanRepository } from "../db/DashboardRepositories.js";
import { FindingCommandError,type FindingQuery } from "../findings/FindingCommandCenterService.js";
import { inspectImageDimensions } from "../security/ImageDimensions.js";
import type { ReviewStatus } from "../types/DashboardTypes.js";

export function serveStatic(response: ServerResponse, root: string, pathname: string): void {
  const candidate = pathname === "/" ? join(root, "index.html") : join(root, pathname);
  const filePath = existsSync(candidate) && statSync(candidate).isFile() ? candidate : join(root, "index.html");
  if (!existsSync(filePath)) {
    response.statusCode = 503;
    response.setHeader("content-type", "text/plain; charset=utf-8");
    response.end(`Dashboard UI is not built yet. Run npm run dashboard:build.\nExpected ${pathToFileURL(root).toString()}`);
    return;
  }
  response.setHeader("content-type", contentType(filePath));
  createReadStream(filePath).pipe(response);
}

export function serveArtifact(response: ServerResponse, artifact: { path: string; contentType: string; name: string }, roots: readonly string[]): void {
  if (!existsSync(resolve(artifact.path))) throw new HttpError(404, "Artifact file missing.");
  const canonical = realpathSync(resolve(artifact.path));
  const allowed = roots.map((root) => realpathSync(resolve(root))).some((root) => canonical === root || canonical.startsWith(`${root}\\`) || canonical.startsWith(`${root}/`));
  if (!allowed) throw new HttpError(403, "Artifact path blocked.");
  if (!existsSync(canonical) || !statSync(canonical).isFile()) throw new HttpError(404, "Artifact file missing.");
  response.setHeader("content-type", artifact.contentType);
  response.setHeader("content-disposition", `attachment; filename="${artifact.name.replace(/"/g, "")}"`);
  response.setHeader("x-content-type-options", "nosniff");
  createReadStream(canonical).pipe(response);
}

export function serveImagePreview(response: ServerResponse, artifact: { path: string; contentType: string; name: string }, roots: readonly string[]): void {
  if (!["image/png", "image/jpeg", "image/webp", "image/gif"].includes(artifact.contentType)) throw new HttpError(415, "Artifact is not a supported preview image.");
  if (!existsSync(resolve(artifact.path))) throw new HttpError(404, "Artifact file missing.");
  const canonical = realpathSync(resolve(artifact.path));
  const allowed = roots.map((root) => realpathSync(resolve(root))).some((root) => canonical === root || canonical.startsWith(`${root}\\`) || canonical.startsWith(`${root}/`));
  if (!allowed) throw new HttpError(403, "Artifact path blocked.");
  const stat = statSync(canonical);
  if (!stat.isFile()) throw new HttpError(404, "Artifact file missing.");
  if (stat.size > 10 * 1024 * 1024) throw new HttpError(413, "Screenshot preview exceeds the 10 MiB preview limit.");
  try {
    const dimensions = inspectImageDimensions(canonical, artifact.contentType);
    response.setHeader("x-routecairn-image-dimensions", `${dimensions.width}x${dimensions.height}`);
  } catch (error) {
    throw new HttpError(415, error instanceof Error ? error.message : "Image dimensions could not be validated.");
  }
  response.setHeader("content-type", artifact.contentType);
  response.setHeader("content-disposition", `inline; filename="${artifact.name.replace(/"/g, "")}"`);
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("content-security-policy", "default-src 'none'; img-src 'self'");
  response.setHeader("cache-control", "private, no-store");
  createReadStream(canonical).pipe(response);
}

export function setSecurityHeaders(response: ServerResponse): void {
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("content-security-policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-src 'self'");
}

export function contentType(path: string): string {
  switch (extname(path)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    default:
      return "application/octet-stream";
  }
}

export function numberParam(url: URL, name: string, fallback: number): number {
  const value = Number(url.searchParams.get(name) ?? fallback);
  return Number.isFinite(value) ? value : fallback;
}

export function stringParam(url: URL, name: string): string | undefined {
  const value = url.searchParams.get(name);
  return value && value.length <= 200 ? value : undefined;
}

export function scanStatusParam(url: URL) {
  const value = url.searchParams.get("status");
  return value && ["QUEUED", "PLANNING", "RUNNING", "CANCEL_REQUESTED", "CANCELLED", "COMPLETED", "FAILED", "INTERRUPTED", "IMPORTED"].includes(value)
    ? (value as NonNullable<Parameters<ScanRepository["list"]>[1]>["status"])
    : undefined;
}

export function scanSortParam(url: URL) {
  const value = url.searchParams.get("sort");
  return value && ["created_desc", "created_asc", "status", "target"].includes(value) ? (value as NonNullable<Parameters<ScanRepository["list"]>[1]>["sort"]) : undefined;
}

export function findingQuery(url: URL): FindingQuery {
  return {
    scanId: stringParam(url, "scanId"),
    search: stringParam(url, "q"),
    projectId: stringParam(url, "projectId"),
    targetId: stringParam(url, "targetId"),
    module: stringParam(url, "module"),
    category: stringParam(url, "category"),
    severity: stringParam(url, "severity"),
    confidence: stringParam(url, "confidence"),
    reviewStatus: enumParam(url, "review", ["UNREVIEWED", "IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE", "RESOLVED", "REOPENED"] as const),
    remediationStatus: enumParam(url, "remediation", ["OPEN", "ASSIGNED", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST", "FIXED_VERIFIED", "WONT_FIX"] as const),
    assigneeUserId: stringParam(url, "assignee"),
    retestStatus: enumParam(url, "retest", ["NOT_RETESTED", "RETEST_SCHEDULED", "RETEST_RUNNING", "RETEST_PASSED", "RETEST_FAILED", "RETEST_INCONCLUSIVE"] as const),
    proofReadiness: enumParam(url, "proof", ["NOT_READY", "MISSING_REVIEW", "MISSING_EVIDENCE", "READY", "IN_PROOF_PACK"] as const),
    firstSeenFrom: stringParam(url, "firstSeenFrom"),
    firstSeenTo: stringParam(url, "firstSeenTo"),
    lastSeenFrom: stringParam(url, "lastSeenFrom"),
    lastSeenTo: stringParam(url, "lastSeenTo"),
    newOccurrence: booleanParam(url, "newOccurrence"),
    reopened: booleanParam(url, "reopened"),
    sourceKind: enumParam(url, "source", ["NATIVE", "IMPORTED"] as const),
    evidence: enumParam(url, "evidence", ["HAS_EVIDENCE", "MISSING_EVIDENCE"] as const),
    sort: enumParam(url, "sort", ["severity_desc", "confidence_desc", "first_seen_desc", "last_seen_desc", "occurrences_desc", "review", "remediation", "target", "project"] as const),
    page: numberParam(url, "page", 1),
    pageSize: numberParam(url, "pageSize", numberParam(url, "limit", 25))
  };
}

export function enumParam<const T extends string>(url: URL, name: string, allowed: readonly T[]): T | undefined {
  const value = url.searchParams.get(name);
  if (!value) return undefined;
  if (!allowed.includes(value as T)) throw new FindingCommandError("FINDING_FILTER_INVALID", `Unsupported ${name} filter.`);
  return value as T;
}

export function booleanParam(url: URL, name: string): boolean | undefined {
  const value = url.searchParams.get(name);
  if (value === null || value === "") return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new FindingCommandError("FINDING_FILTER_INVALID", `${name} must be true or false.`);
}

export function correlationId(request: IncomingMessage): string {
  const value = request.headers["x-request-id"];
  return typeof value === "string" && /^[a-zA-Z0-9._-]{1,100}$/.test(value) ? value : randomUUID();
}

export function reviewAuditAction(status: ReviewStatus): string {
  switch (status) {
    case "IN_REVIEW": return "FINDING_REVIEW_STARTED";
    case "CONFIRMED": return "FINDING_CONFIRMED";
    case "FALSE_POSITIVE": return "FINDING_FALSE_POSITIVE";
    case "ACCEPTED_RISK": return "FINDING_ACCEPTED_RISK";
    case "DUPLICATE": return "FINDING_DUPLICATE_MARKED";
    case "RESOLVED": return "FINDING_RESOLVED";
    case "REOPENED": return "FINDING_REOPENED";
    case "UNREVIEWED": return "FINDING_REVIEW_RESET";
  }
}

export class HttpError extends Error {
  public constructor(public readonly statusCode: number, message: string) {
    super(message);
    this.name = "HttpError";
  }
}
