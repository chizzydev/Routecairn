import { join } from "node:path";
import { MutationJournal } from "../../core/offensive/MutationJournal.js";
import { CleanupAttemptLedger, cleanupDigest } from "./CleanupAttemptLedger.js";
import type { WorkerRecoveryResult } from "../worker/ScanWorkerManager.js";
export async function cleanupJournalBaseline(directory: string) {
  const rows = await new MutationJournal(join(directory, "mutation-journal.json")).read();
  return { journalSequence: rows.length, journalDigest: cleanupDigest(rows) };
}
export async function cleanupResultProof(directory: string, caseId: string) {
  const rows = await new MutationJournal(join(directory, "mutation-journal.json")).read(),
    row = rows.filter((r) => r.caseId === caseId).at(-1);
  return row ? { sequence: row.sequence, entryDigest: cleanupDigest(row) } : undefined;
}
export async function verifyCleanupRestoration(
  ledger: CleanupAttemptLedger,
  id: string,
  directory: string,
  result: WorkerRecoveryResult
) {
  const h = ledger.history(id),
    binding = JSON.parse(h.attempt.binding_json) as { journalSequence: number; journalDigest: string };
  if (
    h.phase !== "RESULT_RECEIVED" ||
    result.cleanupOutcome !== "ROLLBACK_VERIFIED" ||
    !result.proof ||
    !h.events.some((e) => e.kind === "DISPATCH_ATTEMPTED")
  )
    return false;
  const rows = await new MutationJournal(join(directory, "mutation-journal.json")).read(),
    row = rows.filter((r) => r.caseId === h.attempt.case_id).at(-1);
  return Boolean(
    row &&
    row.stage === "ROLLBACK_VERIFIED" &&
    row.sequence > binding.journalSequence &&
    row.sequence === result.proof.sequence &&
    cleanupDigest(row) === result.proof.entryDigest &&
    cleanupDigest(rows.slice(0, binding.journalSequence)) === binding.journalDigest
  );
}
