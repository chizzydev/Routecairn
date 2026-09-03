import type { RouteCairnScope } from "../../config/ConfigSchema.js";

export type ScopeDecisionReason =
  | "allowed"
  | "target-authorization-denied"
  | "invalid-url"
  | "domain-not-allowed"
  | "subdomain-not-allowed"
  | "different-origin"
  | "disallowed-path"
  | "method-not-allowed";

export interface ScopeDecision {
  allowed: boolean;
  reason: ScopeDecisionReason;
  normalizedUrl?: string;
}

export interface ScopeMatcherOptions {
  targetUrl: string;
  scope: RouteCairnScope;
}
