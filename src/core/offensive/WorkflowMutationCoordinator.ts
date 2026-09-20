import { createHash, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { ScanContextOptions } from "../engine/ScanContext.js";
import type { AuthProfile } from "../auth/AuthProfile.js";
import { GlobalMutationLock, MutationJournal } from "./MutationJournal.js";
import { MutationRecoveryVault } from "./MutationRecoveryVault.js";

export const workflowKeys = ["authenticationLifecycle", "businessInvariant", "controlledRace", "protocolSecurity", "linkPortalSecurity", "operationalEndpointSecurity", "billingEntitlement"] as const;
export type RecoverableWorkflow = typeof workflowKeys[number];
export interface WorkflowCheckpoint {
  kind: "WORKFLOW_CLEANUP_V1";
  caseId: string;
  sourceCaseId: string;
  workflow: RecoverableWorkflow;
  targetOrigin: string;
  digest: string;
  revision: string;
  createdAt: string;
  updatedAt: string;
  sourceOutputDir: string;
  scope: ScanContextOptions["scope"];
  config: ScanContextOptions["config"];
  plan: ScanContextOptions["plan"];
  actorBindings: Record<string, string>;
  state: Record<string, Array<[string, unknown]>>;
}

export function defaultMutationDirectory(): string {
  return resolve(process.env.ROUTECAIRN_MUTATION_DIR ?? join(process.env.ROUTECAIRN_DASHBOARD_DIR ?? join(homedir(), ".routecairn", "dashboard"), "controlled-mutations"));
}

/** Credentials never enter checkpoints. Captured restoration values and exact
 * cleanup contracts are encrypted, and only cleanup-mode adapters may reopen them. */
export class WorkflowMutationCoordinator {
  public readonly directory: string;
  public readonly journal: MutationJournal;
  private readonly vault: MutationRecoveryVault;
  private readonly cases = new Map<string, { checkpoint: WorkflowCheckpoint; snapshot: () => WorkflowCheckpoint["state"]; armed: boolean }>();

  public constructor(private readonly options: ScanContextOptions) {
    this.directory = resolve(options.mutationJournalDir ?? defaultMutationDirectory());
    this.vault = new MutationRecoveryVault(this.directory);
    this.journal = new MutationJournal(join(this.directory, "mutation-journal.json"), async (entry) => {
      // Expanded paths can contain captured session, reset, or signed-link
      // values. Keep exact URLs only inside the encrypted checkpoint; the
      // journal already identifies the target, workflow case, and method.
      const safeEntry = { ...entry, ...(entry.requestUrl ? { requestUrl: "redacted://workflow-request" } : {}) };
      const current = this.cases.get(entry.caseId);
      if (!current) return safeEntry;
      const configured = current.checkpoint.plan[current.checkpoint.workflow]?.cases[0];
      const authorizedDisposal = configured && "cleanupRequired" in configured && configured.cleanupRequired === false && entry.outcome === "SECURE_FOR_CASE";
      if (current.armed && entry.stage === "SEALED" && !authorizedDisposal) throw new Error("RECOVERY_REQUIRES_VERIFIED_CLEANUP");
      if (entry.stage === "MUTATION_ARMED" || entry.stage === "ROLLBACK_SENT") current.armed = true;
      if (current.armed && entry.stage !== "ROLLBACK_VERIFIED") await this.checkpoint(entry.caseId);
      return safeEntry;
    }, async (entry) => {
      if (entry.stage === "ROLLBACK_VERIFIED" || entry.stage === "SEALED") {
        await this.vault.remove(join(this.directory, `${entry.caseId}.recovery.enc`));
        this.cases.delete(entry.caseId);
      }
      await this.options.checkpointReport?.();
    });
  }

  public lock(): GlobalMutationLock {
    const lock = new GlobalMutationLock(join(this.directory, "global-mutation.lock"));
    if (!this.options.workflowRecovery) return lock;
    const acquire = lock.acquire.bind(lock);
    lock.acquire = async (caseId) => {
      if (caseId !== this.options.workflowRecovery!.caseId) throw new Error("RECOVERY_CASE_MISMATCH");
      await acquire(caseId, true);
      try {
        const current = await this.vault.open<WorkflowCheckpoint>(join(this.directory, `${caseId}.recovery.enc`), caseId);
        if (current.digest !== this.options.workflowRecovery!.digest || current.revision !== this.options.workflowRecovery!.revision) throw new Error("RECOVERY_CHECKPOINT_CHANGED");
      } catch (error) { await lock.release(); throw error; }
    };
    return lock;
  }

  public register(workflow: RecoverableWorkflow, caseId: string, testCase: { id: string }, maps: Record<string, Map<string, unknown>>): boolean {
    const recovery = this.options.workflowRecovery;
    if (recovery && (recovery.caseId !== caseId || recovery.workflow !== workflow || recovery.sourceCaseId !== testCase.id)) throw new Error("RECOVERY_CASE_MISMATCH");
    if (recovery) for (const [name, map] of Object.entries(maps)) for (const [key, value] of recovery.state[name] ?? []) map.set(key, value);
    const selected = this.options.plan[workflow];
    if (!selected) throw new Error("RECOVERY_PLAN_REQUIRED");
    const plan = { ...this.options.plan, [workflow]: { ...selected, cases: [testCase] } };
    for (const key of workflowKeys) if (key !== workflow) delete plan[key];
    const bindings = actorBindings(this.options);
    if (recovery && JSON.stringify(bindings) !== JSON.stringify(recovery.actorBindings)) throw new Error("RECOVERY_ACTOR_MISMATCH");
    const immutable = { instanceId: randomUUID(), workflow, sourceCaseId: testCase.id, targetOrigin: new URL(this.options.target).origin, scope: this.options.scope, config: this.options.config, plan, actorBindings: bindings };
    const now = new Date().toISOString();
    const checkpoint: WorkflowCheckpoint = recovery ?? { kind: "WORKFLOW_CLEANUP_V1", caseId, revision: randomUUID(), ...immutable, plan: plan as ScanContextOptions["plan"], digest: createHash("sha256").update(JSON.stringify(immutable)).digest("hex"), createdAt: now, updatedAt: now, sourceOutputDir: this.options.outputDir, state: {} };
    this.cases.set(caseId, { checkpoint, snapshot: () => Object.fromEntries(Object.entries(maps).map(([name, map]) => [name, [...map]])), armed: Boolean(recovery) });
    return Boolean(recovery);
  }

  public async checkpoint(caseId: string): Promise<void> {
    const current = this.cases.get(caseId);
    if (!current?.armed) return;
    const value = { ...current.checkpoint, revision: randomUUID(), state: current.snapshot(), updatedAt: new Date().toISOString() };
    if (Buffer.byteLength(JSON.stringify(value)) > 16 * 1024 * 1024) throw new Error("RECOVERY_CHECKPOINT_LIMIT_EXCEEDED");
    await this.vault.seal(value);
  }
}

function actorBindings(options: ScanContextOptions): Record<string, string> {
  const entries: Array<[string, AuthProfile | undefined]> = [["primary", options.authProfile], ["account_a", options.authProfileSet?.accountA], ["account_b", options.authProfileSet?.accountB]];
  return Object.fromEntries(entries.filter((entry): entry is [string, AuthProfile] => Boolean(entry[1])).map(([slot, profile]) => [slot, createHash("sha256").update(JSON.stringify(profile.principalId ? { principal: profile.principalId, tenant: profile.tenantId, role: profile.role } : { headers: profile.headers, cookies: profile.cookies })).digest("hex")]));
}
