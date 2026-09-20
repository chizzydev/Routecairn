import type { Command } from "commander";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { loadScope } from "../../config/loadConfig.js";
import { AppError } from "../../core/errors/AppError.js";
import { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import type { RequestAuditEntry } from "../../core/http/HttpTypes.js";
import { ControlledMutationExecutor } from "../../core/offensive/ControlledMutationExecutor.js";
import { controlledMutationContractSchema, type ControlledMutationContract, type ControlledMutationResult } from "../../core/offensive/ControlledMutationTypes.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { createLogger } from "../../core/logging/Logger.js";
import { MutationJournalRegistry } from "../../core/offensive/MutationJournalRegistry.js";
import { resolveDashboardPaths } from "../../dashboard/services/DashboardPaths.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";

const logger = createLogger();

interface RunOptions { contract: string; scope: string; journalDir?: string; approve: string; output?: string }
interface RecoverOptions { bundle: string; caseId: string; target: string; scope: string; journalDir?: string; output?: string }

export function registerOffensiveCommand(program: Command): void {
  const offensive = program.command("offensive").description("Run explicitly authorized controlled mutation and recovery workflows.");
  offensive.command("run")
    .requiredOption("--contract <file>", "Controlled mutation contract JSON.")
    .requiredOption("--scope <file>", "Scope file that explicitly permits the declared methods.")
    .option("--journal-dir <dir>", "Private durable journal and recovery directory. Defaults to the dashboard-controlled directory.")
    .requiredOption("--approve <case-id>", "Re-confirm the exact case identifier at execution time.")
    .option("--output <file>", "Redacted execution result JSON.")
    .action(async (options: RunOptions) => {
      const report = await runControlledMutation(options);
      logger.success(`Controlled mutation finished: ${report.result.securityOutcome}; cleanup: ${report.result.cleanupOutcome}.`);
    });
  offensive.command("recover")
    .requiredOption("--bundle <file>", "Encrypted recovery bundle emitted by an unfinished mutation.")
    .requiredOption("--case-id <id>", "Case identifier bound to the encrypted recovery bundle.")
    .requiredOption("--target <origin>", "Exact authorized target origin.")
    .requiredOption("--scope <file>", "Scope file that explicitly permits rollback methods.")
    .option("--journal-dir <dir>", "Private durable journal and recovery directory. Defaults to the dashboard-controlled directory.")
    .option("--output <file>", "Redacted recovery result JSON.")
    .action(async (options: RecoverOptions) => {
      const report = await recoverControlledMutation(options);
      logger.success(`Recovery finished: ${report.result.cleanupOutcome}.`);
    });
}

export async function runControlledMutation(options: RunOptions): Promise<{ result: ControlledMutationResult; requestAudit: RequestAuditEntry[] }> {
  const contract = await loadContract(resolve(options.contract));
  if (options.approve !== contract.caseId) throw new AppError("--approve must exactly match the controlled mutation contract caseId.", "CONTROLLED_MUTATION_APPROVAL_MISMATCH");
  const journalDirectory = await registeredJournalDirectory(options.journalDir);
  const dashboardPaths = resolveDashboardPaths();
  const cleanupStatus = await readMutationCleanupStatus(dashboardPaths.mutationJournalDir, dashboardPaths.mutationJournalRegistryPath);
  if (cleanupStatus.cleanupRequired > 0) throw new AppError(`Controlled mutation blocked: ${cleanupStatus.cleanupRequired} unresolved cleanup obligation(s) require explicit recovery.`, "CONTROLLED_MUTATION_CLEANUP_REQUIRED");
  const audit: RequestAuditEntry[] = [];
  const broker = await createBroker(contract.targetOrigin, resolve(options.scope), audit);
  const executor = new ControlledMutationExecutor(broker, { journalDirectory, globalLockPath: join(dashboardPaths.mutationJournalDir, "global-mutation.lock") });
  try {
    const result = await executor.execute(contract);
    const report = { result, requestAudit: audit };
    if (options.output) await writeReport(resolve(options.output), report);
    return report;
  } finally {
    await broker.close();
  }
}

export async function recoverControlledMutation(options: RecoverOptions): Promise<{ result: ControlledMutationResult; requestAudit: RequestAuditEntry[] }> {
  const audit: RequestAuditEntry[] = [];
  const journalDirectory = await registeredJournalDirectory(options.journalDir);
  const dashboardPaths = resolveDashboardPaths();
  const broker = await createBroker(options.target, resolve(options.scope), audit);
  const executor = new ControlledMutationExecutor(broker, { journalDirectory, globalLockPath: join(dashboardPaths.mutationJournalDir, "global-mutation.lock") });
  try {
    const result = await executor.recover(resolve(options.bundle), options.caseId);
    const report = { result, requestAudit: audit };
    if (options.output) await writeReport(resolve(options.output), report);
    return report;
  } finally {
    await broker.close();
  }
}

async function registeredJournalDirectory(explicitDirectory: string | undefined): Promise<string> {
  const paths = resolveDashboardPaths();
  const directory = resolve(explicitDirectory ?? paths.mutationJournalDir);
  await new MutationJournalRegistry(paths.mutationJournalRegistryPath).register(directory);
  return directory;
}

async function createBroker(target: string, scopePath: string, audit: RequestAuditEntry[]): Promise<RequestSafetyBroker> {
  const scope = await loadScope(scopePath);
  return new RequestSafetyBroker({
    userAgent: scope.userAgent,
    timeoutMs: 15_000,
    bodyPreviewBytes: 64 * 1024,
    maxResponseBytes: 64 * 1024,
    rateLimitPerSecond: Math.min(scope.rateLimitPerSecond, 3),
    concurrency: 1,
    maxRequests: 100,
    retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1, retryStatusCodes: [] },
    controlledMutationEnabled: true
  }, new ScopeMatcher(target, scope), (entry) => audit.push(entry));
}

async function loadContract(path: string): Promise<ControlledMutationContract> {
  const parsed = controlledMutationContractSchema.safeParse(JSON.parse(await readFile(path, "utf8")) as unknown);
  if (!parsed.success) throw new AppError(`Invalid controlled mutation contract: ${parsed.error.message}`, "CONTROLLED_MUTATION_CONTRACT_INVALID");
  return parsed.data;
}

async function writeReport(path: string, report: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}
