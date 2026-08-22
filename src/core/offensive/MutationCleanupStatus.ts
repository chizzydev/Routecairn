import { createHash } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { MutationJournal } from "./MutationJournal.js";
import { MutationJournalRegistry } from "./MutationJournalRegistry.js";
import type { MutationJournalEntry, MutationJournalStage, MutationOutcome, OffensiveExecutionMode } from "./ControlledMutationTypes.js";

export type MutationCleanupStage = MutationJournalStage | "MUTATION_STATE_UNCERTAIN";

export interface MutationCleanupCase {
  journalId: string;
  caseId: string;
  stage: MutationCleanupStage;
  timestamp: string;
  mode?: OffensiveExecutionMode | undefined;
  targetOrigin?: string | undefined;
  targetIdentityFingerprint?: string | undefined;
  requestMethod?: string | undefined;
  requestUrl?: string | undefined;
  requestBodyAttestation?: string | undefined;
  responseStatus?: number | undefined;
  responseHash?: string | undefined;
  outcome?: MutationOutcome | undefined;
  note?: string | undefined;
  recoveryBundleAvailable: boolean;
  operatorActionRequired: true;
  warning: string;
}

export interface MutationCleanupStatus {
  modes: Record<OffensiveExecutionMode, "AVAILABLE" | "PLANNED_UNAVAILABLE">;
  globalMutationActive: boolean;
  cleanupRequired: number;
  cases: MutationCleanupCase[];
}

const obligationStages = new Set<MutationJournalStage>(["MUTATION_ARMED", "MUTATION_SENT", "IMPACT_VERIFIED", "ROLLBACK_SENT", "CLEANUP_REQUIRED", "CLEANUP_FAILED"]);

export async function readMutationCleanupStatus(primaryDirectory: string, registryPath: string): Promise<MutationCleanupStatus> {
  const registered = await new MutationJournalRegistry(registryPath).directories().catch(() => []);
  const directories = [...new Set([resolve(primaryDirectory), ...registered.map((directory) => resolve(directory))])];
  const cases = (await Promise.all(directories.map(readDirectoryStatus))).flat().sort((left, right) => right.timestamp.localeCompare(left.timestamp));
  return {
    modes: { OBSERVE: "AVAILABLE", SAFE_ACTIVE: "AVAILABLE", CONTROLLED_MUTATION: "AVAILABLE", CONTROLLED_DELETION: "PLANNED_UNAVAILABLE", LAB_DESTRUCTIVE: "PLANNED_UNAVAILABLE" },
    globalMutationActive: cases.length > 0,
    cleanupRequired: cases.length,
    cases
  };
}

async function readDirectoryStatus(directory: string): Promise<MutationCleanupCase[]> {
  const journalId = createHash("sha256").update(resolve(directory)).digest("hex").slice(0, 16);
  const entries = await new MutationJournal(join(directory, "mutation-journal.json")).read().catch(() => []);
  const latest = new Map<string, MutationJournalEntry>();
  for (const entry of entries) latest.set(entry.caseId, entry);
  const bundles = await recoveryBundles(directory);
  const cases: MutationCleanupCase[] = [];

  for (const entry of latest.values()) {
    if (!obligationStages.has(entry.stage)) continue;
    cases.push(fromEntry(journalId, entry, bundles.has(entry.caseId)));
  }

  for (const [caseId, modifiedAt] of bundles) {
    const entry = latest.get(caseId);
    if (entry && obligationStages.has(entry.stage)) continue;
    if (entry?.stage === "ROLLBACK_VERIFIED") continue;
    cases.push({
      journalId,
      caseId,
      stage: "MUTATION_STATE_UNCERTAIN",
      timestamp: modifiedAt,
      recoveryBundleAvailable: true,
      operatorActionRequired: true,
      warning: "Encrypted recovery material exists without a durable post-mutation journal state. Treat the target as potentially modified until explicit recovery verifies restoration.",
      ...(entry?.targetOrigin ? { targetOrigin: entry.targetOrigin } : {}),
      ...(entry?.targetIdentityFingerprint ? { targetIdentityFingerprint: entry.targetIdentityFingerprint } : {})
    });
  }
  return cases;
}

function fromEntry(journalId: string, entry: MutationJournalEntry, bundleAvailable: boolean): MutationCleanupCase {
  const { recoveryBundleRef: _recoveryBundleRef, sequence: _sequence, ...safe } = entry;
  return {
    ...safe,
    journalId,
    recoveryBundleAvailable: bundleAvailable,
    operatorActionRequired: true,
    warning: entry.stage === "CLEANUP_FAILED"
      ? "UNRESOLVED CLEANUP — RouteCairn cannot prove the original target state was restored."
      : "MUTATION STATE UNRESOLVED — the target may still be modified until restoration is independently verified."
  };
}

async function recoveryBundles(directory: string): Promise<Map<string, string>> {
  const names = await readdir(directory).catch(() => []);
  const bundles = new Map<string, string>();
  for (const name of names) {
    const match = /^(?<caseId>[a-zA-Z0-9._-]+)\.recovery\.enc$/.exec(name);
    if (!match?.groups?.caseId) continue;
    const metadata = await stat(join(directory, name)).catch(() => undefined);
    bundles.set(match.groups.caseId, metadata?.mtime.toISOString() ?? new Date(0).toISOString());
  }
  return bundles;
}
