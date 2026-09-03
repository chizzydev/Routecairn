import type { ResolvedScanPlan } from "../planning/ScanPlan.js";

/**
 * Recovery never replays attack traffic. Its complete bounded network budget is
 * therefore assigned to the cleanup lane so restoration and authoritative
 * verification remain possible after the originating scan has terminated.
 */
export function recoveryOnlyPlan(plan: ResolvedScanPlan, maxRequests = plan.limits.maxRequests): ResolvedScanPlan {
  if (!Number.isInteger(maxRequests) || maxRequests < 1) throw new Error("RECOVERY_REQUEST_BUDGET_INVALID");
  return {
    ...plan,
    limits: {
      ...plan.limits,
      maxRequests,
      cleanupReservedRequests: maxRequests,
      concurrency: 1,
      retry: { ...plan.limits.retry, maxAttempts: 1 }
    }
  };
}
