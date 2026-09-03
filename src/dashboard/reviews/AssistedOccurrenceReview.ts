import type { DashboardDatabase } from "../db/DashboardDatabase.js";

/** Confirmation is bound to an immutable occurrence, never inherited from an older scan. */
export function hasOccurrenceReview(database: DashboardDatabase, findingId: string, occurrenceId: string, status: string): boolean {
  return Boolean(database.db.prepare("SELECT 1 FROM finding_reviews WHERE finding_id = ? AND source = 'HUMAN' AND new_review_status = ? AND json_valid(safe_metadata_json) AND json_extract(safe_metadata_json, '$.occurrenceId') = ? LIMIT 1").get(findingId, status, occurrenceId));
}
