import {CleanupAttemptLedger,cleanupDigest} from "../recovery/CleanupAttemptLedger.js";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { recoveryControlledCleanupSchema } from "../contracts/RecoveryCenterContracts.js";
import { requireCredentialUsePermission, requireSelectedResource } from "./DashboardApiContext.js";
import { hasPermission } from "../auth/Permissions.js";
import type { RecoveryScope } from "../contracts/RecoveryCenterContracts.js";
import { recoveryKindSchema } from "../contracts/RecoveryCenterContracts.js";
import { RecoveryCenterService, RecoveryOperationError } from "../recovery/RecoveryCenterService.js";
import { HttpError } from "./DashboardHttpSupport.js";
import { requirePermission, resourceOrganization, readJson, sendJson, type ApiContext } from "./DashboardApiContext.js";

export function recoveryCenter(context: ApiContext) {
  return new RecoveryCenterService(context.database, context.workflowRecovery);
}
export function recoveryScope(context: ApiContext): RecoveryScope {
  requirePermission(context, "recovery.read");
  requirePermission(context, "scans.read");
  const organizationId = resourceOrganization(context),
    actor = context.principal!.userId;
  const permission = (p: Parameters<typeof hasPermission>[1]) =>
    context.mode === "local" || hasPermission(context.principal!.role, p);
  const orgPermission = (p: "resources.use" | "workers.manage") => {
    try {
      context.organizations.require(organizationId, actor, p, context.mode === "local");
      return true;
    } catch {
      return false;
    }
  };
  const use = orgPermission("resources.use");
  return {
    organizationId,
    actor,
    canReview: permission("recovery.review") && use,
    canManageWorkers: permission("workers.manage") && orgPermission("workers.manage"),
    canRecover: permission("controlledMutation.recover") && permission("credentials.use") && use,
    canRecompute: permission("comparisons.create") && permission("comparisons.recompute") && use
  };
}
export async function handleRecoveryCenter(context: ApiContext): Promise<boolean> {
  if (!context.url.pathname.startsWith("/api/recovery-center")) return false;
  try {
    const scope = recoveryScope(context),
      service = recoveryCenter(context);
    context.response.setHeader("Cache-Control", "no-store");
    const attemptDetail=/^\/api\/recovery-center\/attempts\/(?<id>[a-f0-9-]{36})$/.exec(context.url.pathname);
    if(context.request.method==="GET"&&attemptDetail?.groups?.id){const ledger=CleanupAttemptLedger.for(context.database),a=ledger.get(attemptDetail.groups.id);if(!a||a.organization_id!==scope.organizationId)throw new HttpError(404,"Cleanup attempt not found in this organization.");const h=ledger.history(a.id);sendJson(context.response,200,{attemptId:a.id,jobId:a.job_id,caseId:a.case_id,kind:a.kind,phase:h.phase,immutableBindingDigest:a.binding_digest,history:h.events.map(e=>({sequence:e.sequence,kind:e.kind,at:e.created_at,hash:e.event_hash,previousHash:e.previous_hash})),automaticReplay:false,authorizationReusable:false});return true;}
    if (context.request.method === "GET" && context.url.pathname === "/api/recovery-center") {
      const kind = context.url.searchParams.get("kind"),
        page = context.url.searchParams.get("page"),
        size = context.url.searchParams.get("pageSize");
      const diagnostics = context.execution.workerDiagnostics();
      sendJson(
        context.response,
        200,
        await service.snapshot(scope, diagnostics.dispatchState, {
          ownedResourceIds: diagnostics.ownedResourceIds,
          ...(kind ? { kind: recoveryKindSchema.parse(kind) } : {}),
          ...(page ? { page: Number(page) } : {}),
          ...(size ? { pageSize: Number(size) } : {})
        })
      );
      return true;
    }
    if (context.request.method === "POST" && context.url.pathname === "/api/recovery-center/reviews") {
      sendJson(context.response, 201, await service.review(scope, await readJson(context.request)));
      return true;
    }
    if (context.request.method === "POST" && context.url.pathname === "/api/recovery-center/comparison-recompute") {
      sendJson(context.response, 200, await service.recompute(scope, await readJson(context.request)));
      return true;
    }
    if (context.request.method === "POST" && context.url.pathname === "/api/recovery-center/controlled-cleanup") {
      if (!scope.canRecover) throw new HttpError(403, "Cleanup recovery permission and credential use are required.");
      const input = recoveryControlledCleanupSchema.parse(await readJson(context.request));
      const {requestId:_requestId,...submission}=input,submissionDigest=cleanupDigest(submission),prior=CleanupAttemptLedger.for(context.database).lookup(input.requestId,scope.organizationId,scope.actor,submissionDigest);
      if(prior){sendJson(context.response,202,{jobId:prior.job_id,attemptId:prior.id,status:CleanupAttemptLedger.for(context.database).history(prior.id).phase,replayed:false,alreadyRecorded:true,restorationVerified:false});return true;}
      const issue = (
        await service.snapshot(scope, "UNKNOWN", { kind: "CLEANUP", subjectId: input.subjectId })
      ).issues.find((i) => i.subjectId === input.subjectId);
      if (!issue || !issue.actions.cleanup)
        throw new HttpError(409, "Bound cleanup evidence is unavailable for recovery.");
      if (issue.snapshotDigest !== input.snapshotDigest)
        throw new HttpError(409, "Cleanup evidence changed. Refresh before authorization.");
      const approval = context.mutationApprovals.get(input.subjectId.slice("approval:".length));
      if (!approval) throw new HttpError(404, "Cleanup approval not found.");
      requireSelectedResource(context, "target", approval.targetId, "resources.use");
      requireCredentialUsePermission(context, input);
      const credential = context.vault.getSummary(input.credentialProfileId, scope.organizationId);
      if (!credential?.enabled || credential.targetId !== approval.targetId)
        throw new HttpError(409, "A fresh enabled credential bound to this exact target is required.");
      const target = context.targets.get(approval.targetId)!;
      if (!service.originOwned(target.baseOrigin, scope.organizationId))
        throw new HttpError(409, "Cleanup origin attribution is uncertain.");
      const jobId = randomUUID();
      const accepted = await context.mutationRecovery.startRecovery({
        requestedBy:scope.actor,submissionDigest,...(input.requestId?{requestId:input.requestId}:{}),
        recoveryJobId: jobId,
        approvalId: approval.id,
        caseId: approval.caseId,
        targetId: approval.targetId,
        credentialProfileId: input.credentialProfileId,
        bundlePath: join(context.paths.mutationJournalDir, approval.caseId + ".recovery.enc"),
        workerRequest: {
          target: target.baseOrigin,
          targetId: target.id,
          profile: "authenticated",
          credentialProfileId: input.credentialProfileId,
          recoveryScope: scopeSchema.parse(target.approvedScope),
          authorizationDeclaration: "Explicitly authorized bound cleanup recovery only.",
          studio: {
            version: 1,
            scanName: "Bound cleanup recovery",
            authorization: { category: "OWNED", confirmed: true },
            scope: scopeSchema.parse(target.approvedScope),
            authentication: {
              mode: "primary",
              primary: { source: "saved", credentialProfileId: input.credentialProfileId }
            },
            outputs: { json: true, markdown: true, html: true },
            moduleSettings: {},
            workflows: [],
            workflowSummary: []
          }
        }
      });
      if(accepted.completion) void accepted.completion
        .then((result) =>
          context.audit.append({
            actorLabel: scope.actor,
            action: "OPERATOR_CONTROLLED_CLEANUP_COMPLETED",
            resourceType: "RECOVERY_JOB",
            resourceId: jobId,
            summary: "Bound cleanup finished; inspect verified restoration outcome.",
            metadata: { cleanupOutcome: result.cleanupOutcome }
          })
        )
        .catch(() =>
          context.audit.append({
            actorLabel: scope.actor,
            action: "OPERATOR_CONTROLLED_CLEANUP_UNRESOLVED",
            resourceType: "RECOVERY_JOB",
            resourceId: jobId,
            summary: "Cleanup restoration remains unresolved. Review retained evidence."
          })
        );
      context.audit.append({
        actorLabel: scope.actor,
        action: "OPERATOR_CONTROLLED_CLEANUP_REQUESTED",
        resourceType: "RECOVERY_JOB",
        resourceId: jobId,
        summary: "Explicit bound cleanup requested with fresh credentials; no original action replay.",
        metadata: { snapshotDigest: input.snapshotDigest, approvalId: approval.id }
      });
      sendJson(context.response, 202, { jobId:accepted.attempt.job_id,attemptId:accepted.attempt.id, status: "REQUESTED", restorationVerified: false,alreadyRecorded:accepted.replayed });
      return true;
    }
    throw new HttpError(404, "Recovery operation not found.");
  } catch (error) {
    if (error instanceof RecoveryOperationError) throw new HttpError(error.status, error.message);
    throw error;
  }
}
