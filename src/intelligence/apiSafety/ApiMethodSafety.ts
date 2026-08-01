import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const safeApiMethods = ["GET", "HEAD", "OPTIONS"] as const satisfies readonly HttpMethod[];
export const destructiveApiMethods = ["POST", "PUT", "PATCH", "DELETE"] as const;

export type SafeApiMethod = (typeof safeApiMethods)[number];
export type DestructiveApiMethod = (typeof destructiveApiMethods)[number];
export type ApiMethodSafety = "safe" | "destructive-skipped" | "unknown-skipped";

export interface ApiMethodSafetyDecision {
  method: string;
  safety: ApiMethodSafety;
  reason: string;
}

export function classifyApiMethodSafety(method: string): ApiMethodSafetyDecision {
  const normalized = method.toUpperCase();

  if ((safeApiMethods as readonly string[]).includes(normalized)) {
    return {
      method: normalized,
      safety: "safe",
      reason: "Method is safe for RouteCairn state-aware probing."
    };
  }

  if ((destructiveApiMethods as readonly string[]).includes(normalized)) {
    return {
      method: normalized,
      safety: "destructive-skipped",
      reason: "Method can mutate state and is skipped by default."
    };
  }

  return {
    method: normalized,
    safety: "unknown-skipped",
    reason: "Method is not in the safe allowlist and is skipped by default."
  };
}

export function isSafeApiMethod(method: string): method is SafeApiMethod {
  return classifyApiMethodSafety(method).safety === "safe";
}
