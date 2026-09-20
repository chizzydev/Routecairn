import { ScanContext } from "../engine/ScanContext.js";
import type { ScanContextOptions } from "../engine/ScanContext.js";
import type { WorkflowCheckpoint } from "./WorkflowMutationCoordinator.js";
import { executeAuthenticationLifecycle } from "../../modules/authenticationLifecycle/AuthenticationLifecycleModule.js";
import { executeBusinessInvariant } from "../../modules/businessInvariant/BusinessInvariantModule.js";
import { executeControlledRace } from "../../modules/controlledRace/ControlledRaceModule.js";
import { executeLinkPortalSecurity } from "../../modules/linkPortalSecurity/LinkPortalSecurityModule.js";
import { executeOperationalEndpointSecurity } from "../../modules/operationalEndpointSecurity/OperationalEndpointSecurityModule.js";
import { executeBillingEntitlement } from "../../modules/billingEntitlement/BillingEntitlementModule.js";
import { executeProtocolSecurity } from "../../modules/protocolSecurity/ProtocolSecurityModule.js";
import { recoveryOnlyPlan } from "./RecoveryRequestBudget.js";

/** This dispatch never enters the scan runner or any main/action phase. */
export async function recoverWorkflow(checkpoint: WorkflowCheckpoint, options: Pick<ScanContextOptions, "mutationJournalDir" | "authProfile" | "authProfileSet" | "recoveryScope">): Promise<{ caseId: string; cleanupOutcome: "ROLLBACK_VERIFIED" | "CLEANUP_FAILED"; notes: string[] }> {
  const selected = checkpoint.plan[checkpoint.workflow];
  if (checkpoint.kind !== "WORKFLOW_CLEANUP_V1" || !selected || selected.cases.length !== 1 || selected.cases[0]?.id !== checkpoint.sourceCaseId) throw new Error("RECOVERY_PLAN_INVALID");
  const plan = structuredClone(checkpoint.plan);
  // Learned cases have already been compiled and sealed; never compile them again.
  if (plan.authenticationLifecycle) {
    const { automation: _automation, ...explicit } = plan.authenticationLifecycle;
    plan.authenticationLifecycle = explicit;
  }
  const context = new ScanContext({ ...options, target: checkpoint.targetOrigin, scope: checkpoint.scope, config: checkpoint.config, plan: recoveryOnlyPlan(plan), outputDir: checkpoint.sourceOutputDir, workflowRecovery: checkpoint });
  const executors = { authenticationLifecycle: executeAuthenticationLifecycle, businessInvariant: executeBusinessInvariant, controlledRace: executeControlledRace, protocolSecurity: executeProtocolSecurity, linkPortalSecurity: executeLinkPortalSecurity, operationalEndpointSecurity: executeOperationalEndpointSecurity, billingEntitlement: executeBillingEntitlement };
  const report = await executors[checkpoint.workflow](context).finally(() => context.dispose());
  const observation = report.observations.find((item) => item.caseId === checkpoint.sourceCaseId);
  return { caseId: checkpoint.caseId, cleanupOutcome: observation?.cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED", notes: [observation?.cleanupOutcome === "ROLLBACK_VERIFIED" ? "Stored cleanup and verification completed; no attack actions were replayed." : "Restoration remains unproven. The encrypted checkpoint and cleanup obligation are retained."] };
}
