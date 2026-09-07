import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { ScanLimits } from "../../core/planning/ScanPlan.js";

export function assertRegisteredTargetScope(
  requested: RouteCairnScope,
  approved: RouteCairnScope,
  limits: Pick<ScanLimits, "rateLimitPerSecond" | "concurrency" | "maxDepth">
): void {
  const violations: string[] = [];
  const approvedMethods = new Set(approved.allowedMethods);
  const unapprovedMethods = requested.allowedMethods.filter((method) => !approvedMethods.has(method));
  if (unapprovedMethods.length > 0) violations.push(`methods (${unapprovedMethods.join(", ")})`);

  const unapprovedDomains = requested.allowedDomains.filter((domain) => !domainWithinApprovedScope(domain, requested.includeSubdomains, approved));
  if (unapprovedDomains.length > 0) violations.push(`domains (${unapprovedDomains.join(", ")})`);

  const missingExclusions = approved.disallowedPaths.filter((approvedPath) => !requested.disallowedPaths.some((requestedPath) => pathExclusionCovers(requestedPath, approvedPath)));
  if (missingExclusions.length > 0) violations.push(`required path exclusions (${missingExclusions.join(", ")})`);

  if (approved.sameOriginOnly && !requested.sameOriginOnly) violations.push("same-origin enforcement");
  if (!approved.includeSubdomains && requested.includeSubdomains) violations.push("subdomain access");
  if (approved.respectRobotsTxt && !requested.respectRobotsTxt) violations.push("robots.txt enforcement");
  if (limits.maxDepth > approved.maxDepth) violations.push(`crawl depth (${limits.maxDepth} > ${approved.maxDepth})`);
  if (limits.rateLimitPerSecond > approved.rateLimitPerSecond) violations.push(`request rate (${limits.rateLimitPerSecond} > ${approved.rateLimitPerSecond})`);
  if (limits.concurrency > approved.concurrency) violations.push(`concurrency (${limits.concurrency} > ${approved.concurrency})`);

  if (violations.length > 0) {
    throw new Error(`REGISTERED_TARGET_SCOPE_EXCEEDED: The executable scan exceeds the selected target's approved scope: ${violations.join("; ")}.`);
  }
}

function domainWithinApprovedScope(domain: string, requestedIncludesSubdomains: boolean, approved: RouteCairnScope): boolean {
  const requested = parseDomain(domain);
  if (!requested.name) return false;
  const exactCovered = requested.wildcard || approved.allowedDomains.some((candidate) => approvedDomainCoversExact(parseDomain(candidate), requested.name, approved.includeSubdomains));
  const descendantsCovered = !requestedIncludesSubdomains || approved.allowedDomains.some((candidate) => approvedDomainCoversDescendants(parseDomain(candidate), requested.name, approved.includeSubdomains));
  return exactCovered && descendantsCovered;
}

function parseDomain(domain: string): { name: string; wildcard: boolean } {
  const normalized = domain.trim().toLowerCase().replace(/\.$/, "");
  return { name: normalized.replace(/^\*\./, ""), wildcard: normalized.startsWith("*.") };
}

function approvedDomainCoversExact(approved: ReturnType<typeof parseDomain>, requestedName: string, includesSubdomains: boolean): boolean {
  if (!approved.name) return false;
  if (requestedName === approved.name) return !approved.wildcard;
  return includesSubdomains && requestedName.endsWith(`.${approved.name}`);
}

function approvedDomainCoversDescendants(approved: ReturnType<typeof parseDomain>, requestedName: string, includesSubdomains: boolean): boolean {
  if (!approved.name || !includesSubdomains) return false;
  return requestedName === approved.name || requestedName.endsWith(`.${approved.name}`);
}

function pathExclusionCovers(requestedPath: string, approvedPath: string): boolean {
  return approvedPath === requestedPath || approvedPath.startsWith(`${requestedPath}/`);
}
