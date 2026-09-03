import type { AssistedReviewReport } from "../../reports/AssistedReviewReport.js";
import { assistedReviewLanes } from "../../modules/assistedReview/AssistedReviewTypes.js";
import { redactDashboardValue } from "../security/Redaction.js";

/** Lane names are schema enums, not secret-bearing object keys. Rebuild only their numeric coverage. */
export function safeReviewCoverage(coverage: AssistedReviewReport["coverageMatrix"]): AssistedReviewReport["coverageMatrix"] {
  const count = (value: number): number => Number.isSafeInteger(value) && value >= 0 ? value : 0;
  return Object.fromEntries(assistedReviewLanes.map((lane) => {
    const item = coverage[lane];
    return [lane, { selected: item.selected === true, required: item.required === true, total: count(item.total), cleanupFailures: count(item.cleanupFailures), outcomes: { PROVEN: count(item.outcomes.PROVEN), INCONCLUSIVE: count(item.outcomes.INCONCLUSIVE), NOT_ASSESSED: count(item.outcomes.NOT_ASSESSED), BLOCKED: count(item.outcomes.BLOCKED) } }];
  })) as AssistedReviewReport["coverageMatrix"];
}

export function serializeAssistedReview(report: AssistedReviewReport): string {
  return JSON.stringify({ ...redactDashboardValue(report) as Record<string, unknown>, coverageMatrix: safeReviewCoverage(report.coverageMatrix) });
}
