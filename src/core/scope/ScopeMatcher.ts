import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { normalizeUrl } from "../urls/UrlNormalizer.js";
import type { ScopeDecision } from "./ScopeTypes.js";
import type { TargetAuthorizationGuard } from "../authorization/TargetAuthorization.js";

export class ScopeMatcher {
  private readonly target: URL;
  private readonly scope: RouteCairnScope;

  public constructor(targetUrl: string, scope: RouteCairnScope, public readonly authorization?: TargetAuthorizationGuard) {
    this.target = new URL(normalizeUrl(targetUrl));
    this.scope = scope;
  }

  public decide(url: string, method = "GET"): ScopeDecision {
    let parsed: URL;
    let normalizedUrl: string;

    try {
      normalizedUrl = normalizeUrl(url, this.target);
      parsed = new URL(normalizedUrl);
    } catch {
      return { allowed: false, reason: "invalid-url" };
    }

    if (!this.scope.allowedMethods.includes(method.toUpperCase() as (typeof this.scope.allowedMethods)[number])) {
      return { allowed: false, reason: "method-not-allowed", normalizedUrl };
    }

    if (this.scope.sameOriginOnly && parsed.origin !== this.target.origin) {
      return { allowed: false, reason: "different-origin", normalizedUrl };
    }

    if (!this.isAllowedHostname(parsed.hostname)) {
      return { allowed: false, reason: "domain-not-allowed", normalizedUrl };
    }

    if (this.isDisallowedPath(parsed.pathname)) {
      return { allowed: false, reason: "disallowed-path", normalizedUrl };
    }

    if (this.authorization?.check(normalizedUrl, method)) return { allowed: false, reason: "target-authorization-denied", normalizedUrl };
    return { allowed: true, reason: "allowed", normalizedUrl };
  }

  public isAllowed(url: string, method = "GET"): boolean {
    return this.decide(url, method).allowed;
  }

  public targetOrigin(): string {
    return this.target.origin;
  }

  private isAllowedHostname(hostname: string): boolean {
    const normalizedHostname = hostname.toLowerCase();

    return this.scope.allowedDomains.some((domain) => {
      const normalizedDomain = domain.toLowerCase();

      if (normalizedDomain.startsWith("*.")) {
        const root = normalizedDomain.slice(2);
        const isSubdomain = normalizedHostname.endsWith(`.${root}`);
        return this.scope.includeSubdomains && isSubdomain;
      }

      if (normalizedHostname === normalizedDomain) {
        return true;
      }

      return this.scope.includeSubdomains && normalizedHostname.endsWith(`.${normalizedDomain}`);
    });
  }

  private isDisallowedPath(pathname: string): boolean {
    return this.scope.disallowedPaths.some((path) => pathname === path || pathname.startsWith(`${path}/`));
  }
}
