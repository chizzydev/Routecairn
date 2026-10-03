import { createHash,randomUUID } from "node:crypto";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { adaptiveAnalyzeSchema,adaptiveBaselineSchema,adaptivePolicyInputSchema,adaptiveRecommendationDecisionSchema,adaptiveRecommendationLinkSchema } from "../contracts/AdaptiveSecuritySchemas.js";
import { advancedEngineValidationRequestSchema,validateAdvancedEngineInput } from "../contracts/AdvancedEngineSchemas.js";
import { continuousAssuranceNotificationAckSchema,continuousAssurancePolicyInputSchema,continuousAssuranceReviewSchema,continuousAssuranceRunSchema,continuousAssuranceStateSchema,continuousAssuranceTokenRotationSchema,evidenceExportSchema,evidenceGovernancePolicySchema,evidencePurgeSchema } from "../contracts/ContinuousAssuranceSchemas.js";
import { controlledMutationRecoverySchema } from "../contracts/ControlledMutationRecoverySchemas.js";
import { controlledMutationApprovalSchema } from "../contracts/ControlledMutationSchemas.js";
import { compareRequestSchema,credentialDependencyAcknowledgementSchema,credentialHealthTestSchema,credentialMetadataSchema,credentialProfileSchema,credentialRenewalSchema,credentialReplacementSchema,dashboardScanCreateSchema,dashboardSettingsUpdateSchema,importReportSchema,projectSchema,proofPackCreateSchema,savedConfigurationSchema,targetSchema,userCreateSchema,userUpdateSchema } from "../contracts/DashboardSchemas.js";
import {
findingBulkNoteSchema,
findingBulkRemediationSchema,
findingBulkReviewSchema,
findingNoteSchema,
findingRemediationSchema,
findingRetestSchema,
findingReviewSchema,
findingSeveritySchema,
findingVerifySchema,
savedFindingViewDefaultSchema,
savedFindingViewDeleteSchema,
savedFindingViewSchema
} from "../contracts/FindingSchemas.js";
import { liveAcceptanceExecuteSchema,liveAcceptancePlanInputSchema,liveAcceptanceReviewSchema } from "../contracts/LiveAcceptanceSchemas.js";
import { backupCreateSchema,backupRestoreSchema,cloudSyncMembershipBindSchema,cloudSyncPeerSchema,integrationExportSchema,notificationChannelSchema,notificationEnqueueSchema,organizationCreateSchema,organizationMemberSchema,remoteEnrollmentSchema,remoteJobSchema,remoteWorkerStateSchema,ssoProviderSchema,thirdPartyModuleExecuteSchema,thirdPartyModuleRegisterSchema } from "../contracts/OperationalScaleSchemas.js";
import { productionMutationApprovalSchema } from "../contracts/ProductionMutationApprovalSchemas.js";
import { productionMutationCaseSchema } from "../contracts/ProductionMutationCaseSchemas.js";
import { providerAdapterInputSchema,providerAdapterReviewSchema,providerAdapterStateSchema } from "../contracts/ProviderAdapterSchemas.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { compileProductionMutationCase,productionMutationPlanIdentity } from "../execution/ProductionMutationCaseCompiler.js";
import { workflowRecoveryRequestSchema } from "../execution/WorkflowRecoveryService.js";
import { AssistedReviewService } from "../reviews/AssistedReviewService.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { assertProviderAdapterExecution,enforceTenantMutationBoundary,identityResultCategories,mutableSettings,normalizeSavedConfiguration,operationalOrganization,readJson,requireCredentialUsePermission,requireOrg,requirePermission,requireSelectedComparison,requireSelectedResource,requireSelectedResources,resetSettings,resourceOrganization,sendJson,updateSettings,validateScanReferences,validateTargetDefaults,type ApiContext } from "./DashboardApiContext.js";
import {
HttpError,
correlationId,
reviewAuditAction
} from "./DashboardHttpSupport.js";

export async function handleApiMutation(context: ApiContext): Promise<void> {
  const { request, response, url, execution, findingCommandCenter, comparison, proofPacks, importer, configurations, projects, targets, audit, mutationApprovals, mutationRecovery } = context;
  enforceTenantMutationBoundary(context);
  if (request.method === "POST" && url.pathname === "/api/operations/organizations") {
    requirePermission(context, "organizations.manage"); const parsed = organizationCreateSchema.parse(await readJson(request)); const id = context.organizations.create(parsed, context.principal!.userId); context.cloudSync.record(id,"organization",id,"UPSERT",{name:parsed.name,slug:parsed.slug,status:"ACTIVE"}); audit.append({ actorLabel: context.principal?.userId, action: "ORGANIZATION_CREATED", resourceType: "ORGANIZATION", resourceId: id, summary: "Organization created." }); sendJson(response, 201, { organizationId: id }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/mutation-coordination/orphan") {
    requirePermission(context, "controlledMutation.recover"); if (!context.mutationCoordinator) throw new HttpError(404, "Distributed mutation coordination is not configured."); const body=await readJson(request); const result=context.mutationCoordinator.orphan(body); audit.append({actorLabel:context.principal?.userId,action:"DISTRIBUTED_MUTATION_LEASE_ORPHANED",resourceType:"CONTROLLED_MUTATION",resourceId:result.caseId,summary:"A stale distributed mutation lease was marked state-uncertain; the namespace remains blocked pending recovery."}); sendJson(response,200,result); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/mutation-coordination/resolve") {
    requirePermission(context, "controlledMutation.recover"); if (!context.mutationCoordinator) throw new HttpError(404, "Distributed mutation coordination is not configured."); const body=await readJson(request); const result=context.mutationCoordinator.resolve(body); audit.append({actorLabel:context.principal?.userId,action:"DISTRIBUTED_MUTATION_OBLIGATION_RESOLVED",resourceType:"CONTROLLED_MUTATION",resourceId:result.caseId,summary:"An operator explicitly verified distributed mutation state before clearing the coordination obligation."}); sendJson(response,200,result); return;
  }
  const orgMember = /^\/api\/operations\/organizations\/(?<id>[0-9a-f-]+)\/members$/.exec(url.pathname);
  if (request.method === "POST" && orgMember?.groups?.id) {
    requirePermission(context, "operations.read"); requireOrg(context, orgMember.groups.id, "members.manage"); const parsed = organizationMemberSchema.parse(await readJson(request)); context.organizations.setMember(orgMember.groups.id, parsed, context.principal!.userId, context.mode === "local"); context.cloudSync.record(orgMember.groups.id,"organization-membership",parsed.userId,"UPSERT",{userId:parsed.userId,role:parsed.role}); audit.append({ actorLabel: context.principal?.userId, action: "ORGANIZATION_MEMBER_UPDATED", resourceType: "ORGANIZATION", resourceId: orgMember.groups.id, summary: "Organization membership updated.", metadata: { userId: parsed.userId, role: parsed.role } }); sendJson(response, 200, { ok: true }); return;
  }
  const orgMemberRemove = /^\/api\/operations\/organizations\/(?<id>[0-9a-f-]+)\/members\/(?<userId>[0-9a-f-]+)\/remove$/.exec(url.pathname);
  if (request.method === "POST" && orgMemberRemove?.groups?.id && orgMemberRemove.groups.userId) {
    requirePermission(context, "operations.read"); requireOrg(context, orgMemberRemove.groups.id, "members.manage"); context.organizations.removeMember(orgMemberRemove.groups.id, orgMemberRemove.groups.userId, context.principal!.userId, context.mode === "local"); context.cloudSync.record(orgMemberRemove.groups.id,"organization-membership",orgMemberRemove.groups.userId,"DELETE",{userId:orgMemberRemove.groups.userId}); audit.append({ actorLabel: context.principal?.userId, action: "ORGANIZATION_MEMBER_REMOVED", resourceType: "ORGANIZATION", resourceId: orgMemberRemove.groups.id, summary: "Organization member removed." }); sendJson(response, 200, { ok: true }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/sso") {
    requirePermission(context, "operations.read"); const parsed = ssoProviderSchema.parse(await readJson(request)); requireOrg(context, parsed.organizationId, "sso.manage"); const id = context.sso.create(parsed, context.principal!.userId); context.cloudSync.record(parsed.organizationId,"sso-provider",id,"UPSERT",{name:parsed.name,issuer:parsed.issuer,enabled:parsed.enabled}); audit.append({ actorLabel: context.principal?.userId, action: "SSO_PROVIDER_CREATED", resourceType: "SSO_PROVIDER", resourceId: id, summary: "OIDC provider configured using an environment-backed client secret." }); sendJson(response, 201, { providerId: id }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/notifications/channels") {
    requirePermission(context, "operations.read"); const parsed = notificationChannelSchema.parse(await readJson(request)); requireOrg(context, parsed.organizationId, "notifications.manage"); const id = context.notifications.create(parsed, context.principal!.userId); context.cloudSync.record(parsed.organizationId,"notification-channel",id,"UPSERT",{name:parsed.name,kind:parsed.kind,enabled:parsed.enabled}); audit.append({ actorLabel: context.principal?.userId, action: "NOTIFICATION_CHANNEL_CREATED", resourceType: "NOTIFICATION_CHANNEL", resourceId: id, summary: "External notification channel configured with environment-backed secret material." }); sendJson(response, 201, { channelId: id }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/notifications/deliveries") {
    requirePermission(context, "operations.read"); const parsed = notificationEnqueueSchema.parse(await readJson(request)); const organizationId=context.notifications.organizationForChannels(parsed.channelIds); requireOrg(context, organizationId, "notifications.manage"); const ids = context.notifications.enqueue(parsed); context.cloudSync.record(organizationId,"notification-delivery",parsed.idempotencyKey,"UPSERT",{eventType:parsed.eventType,resourceType:parsed.resourceType,resourceId:parsed.resourceId??"",deliveryCount:ids.length}); audit.append({ actorLabel: context.principal?.userId, action: "NOTIFICATION_ENQUEUED", resourceType: parsed.resourceType, resourceId: parsed.resourceId, summary: "External notification delivery queued.", metadata: { eventType: parsed.eventType, deliveryCount: ids.length } }); sendJson(response, 202, { deliveryIds: ids }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/remote-workers/enrollments") {
    requirePermission(context, "operations.read"); const parsed = remoteEnrollmentSchema.parse(await readJson(request)); requireOrg(context, parsed.organizationId, "workers.manage"); const enrollment = await context.remoteWorkers.createEnrollment({ organizationId: parsed.organizationId, expiresInMinutes: parsed.expiresInMinutes, ...(parsed.nameHint ? { nameHint: parsed.nameHint } : {}), ...(parsed.workloadIdentity ? { workloadIdentity: parsed.workloadIdentity } : {}) }, context.principal!.userId); context.cloudSync.record(parsed.organizationId,"remote-worker-enrollment",enrollment.enrollmentId,"UPSERT",{nameHint:parsed.nameHint??"",expiresAt:enrollment.expiresAt}); audit.append({ actorLabel: context.principal?.userId, action: "REMOTE_WORKER_ENROLLMENT_CREATED", resourceType: "REMOTE_WORKER", resourceId: enrollment.enrollmentId, summary: "One-time remote worker enrollment created." }); sendJson(response, 201, enrollment); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/remote-jobs") {
    requirePermission(context, "operations.read"); const parsed = remoteJobSchema.parse(await readJson(request)); requireOrg(context, parsed.organizationId, "workers.manage"); const id = await context.remoteWorkers.enqueue({ organizationId: parsed.organizationId, kind: parsed.kind, payload: parsed.payload, requiredCapabilities: parsed.requiredCapabilities, priority: parsed.priority, maxAttempts: parsed.maxAttempts, ...(parsed.networkZone ? { networkZone: parsed.networkZone } : {}) }, context.principal!.userId); context.cloudSync.record(parsed.organizationId,"remote-job",id,"UPSERT",{kind:parsed.kind,priority:parsed.priority,requiredCapabilities:parsed.requiredCapabilities,networkZone:parsed.networkZone??"any"}); audit.append({ actorLabel: context.principal?.userId, action: "REMOTE_JOB_QUEUED", resourceType: "REMOTE_JOB", resourceId: id, summary: "Signed remote-worker job queued.", metadata: { kind: parsed.kind, networkZone: parsed.networkZone ?? "any" } }); sendJson(response, 202, { jobId: id }); return;
  }
  const remoteWorkerState = /^\/api\/operations\/remote-workers\/(?<id>[0-9a-f-]+)\/state$/.exec(url.pathname);
  if (request.method === "POST" && remoteWorkerState?.groups?.id) {
    requirePermission(context, "operations.read"); const organizationId=await context.remoteWorkers.organizationForWorker(remoteWorkerState.groups.id); requireOrg(context, organizationId, "workers.manage"); const parsed = remoteWorkerStateSchema.parse(await readJson(request)); await context.remoteWorkers.setStatus(remoteWorkerState.groups.id, parsed.status); context.cloudSync.record(organizationId,"remote-worker",remoteWorkerState.groups.id,"UPSERT",{status:parsed.status}); audit.append({ actorLabel: context.principal?.userId, action: "REMOTE_WORKER_STATE_CHANGED", resourceType: "REMOTE_WORKER", resourceId: remoteWorkerState.groups.id, summary: `Remote worker changed to ${parsed.status}.` }); sendJson(response, 200, { ok: true }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/cloud-sync/peers") {
    requirePermission(context, "operations.read"); const parsed = cloudSyncPeerSchema.parse(await readJson(request)); requireOrg(context, parsed.organizationId, "org.manage"); const id = context.cloudSync.createPeer({ organizationId: parsed.organizationId, ...(parsed.remoteOrganizationId ? { remoteOrganizationId: parsed.remoteOrganizationId } : {}), name: parsed.name, endpoint: parsed.endpoint, sharedSecretEnv: parsed.sharedSecretEnv, enabled: parsed.enabled, syncMode: parsed.syncMode }, context.principal!.userId); context.cloudSync.record(parsed.organizationId,"cloud-sync-peer",id,"UPSERT",{name:parsed.name,enabled:parsed.enabled,syncMode:parsed.syncMode,remoteOrganizationId:parsed.remoteOrganizationId??parsed.organizationId}); audit.append({ actorLabel: context.principal?.userId, action: "CLOUD_SYNC_PEER_CREATED", resourceType: "CLOUD_SYNC_PEER", resourceId: id, summary: "Signed cloud synchronization peer configured." }); sendJson(response, 201, { peerId: id }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/cloud-sync/synchronize") {
    requirePermission(context, "operations.read"); const organizationId=operationalOrganization(context); requireOrg(context,organizationId,"org.manage"); await readJson(request); const result=await context.cloudSync.synchronizeOrganization(organizationId); audit.append({actorLabel:context.principal?.userId,action:"CLOUD_SYNC_COMPLETED",resourceType:"ORGANIZATION",resourceId:organizationId,summary:"Automatic legacy snapshot and signed peer synchronization completed.",metadata:{snapshotEvents:result.snapshotEvents,pushedEvents:result.pushedEvents,failureCount:result.failures.length}});sendJson(response,result.failures.length?207:200,result);return;
  }
  if(request.method==="POST"&&url.pathname==="/api/operations/cloud-sync/memberships/bind"){
    requirePermission(context,"operations.read");const parsed=cloudSyncMembershipBindSchema.parse(await readJson(request));requireOrg(context,parsed.organizationId,"members.manage");
    context.cloudSync.bindMembership(parsed.organizationId,parsed.originInstallationId,parsed.sourceUserId,parsed.localUserId);
    audit.append({actorLabel:context.principal?.userId,action:"CLOUD_SYNC_MEMBERSHIP_BOUND",resourceType:"ORGANIZATION",resourceId:parsed.organizationId,summary:"Operator bound a peer membership to a local user.",metadata:{originInstallationId:parsed.originInstallationId,sourceUserId:parsed.sourceUserId,localUserId:parsed.localUserId}});
    sendJson(response,200,{ok:true});return;
  }
  const cloudPush = /^\/api\/operations\/cloud-sync\/(?<id>[0-9a-f-]+)\/push$/.exec(url.pathname);
  if (request.method === "POST" && cloudPush?.groups?.id) {
    requirePermission(context, "operations.read"); requireOrg(context, context.cloudSync.organizationForPeer(cloudPush.groups.id), "org.manage"); await readJson(request); const result = await context.cloudSync.push(cloudPush.groups.id); audit.append({ actorLabel: context.principal?.userId, action: "CLOUD_SYNC_PUSHED", resourceType: "CLOUD_SYNC_PEER", resourceId: cloudPush.groups.id, summary: "Signed cloud synchronization batch pushed.", metadata: result }); sendJson(response, 200, result); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/backups") {
    requirePermission(context, "backups.manage"); const parsed = backupCreateSchema.parse(await readJson(request)); const id = await context.backups.create(parsed.encrypted, context.principal!.userId); audit.append({ actorLabel: context.principal?.userId, action: "BACKUP_CREATED", resourceType: "BACKUP", resourceId: id, summary: "Consistent dashboard backup created." }); sendJson(response, 201, { backupId: id }); return;
  }
  const backupVerify = /^\/api\/operations\/backups\/(?<id>[0-9a-f-]+)\/verify$/.exec(url.pathname);
  if (request.method === "POST" && backupVerify?.groups?.id) { requirePermission(context, "backups.manage"); await readJson(request); sendJson(response, 200, context.backups.verify(backupVerify.groups.id)); return; }
  if (request.method === "POST" && url.pathname === "/api/operations/backups/stage-restore") {
    requirePermission(context, "backups.manage"); const parsed = backupRestoreSchema.parse(await readJson(request)); context.backups.stageRestore(parsed.backupId); audit.append({ actorLabel: context.principal?.userId, action: "BACKUP_RESTORE_STAGED", resourceType: "BACKUP", resourceId: parsed.backupId, summary: "Verified backup staged for restore on restart." }); sendJson(response, 202, { restartRequired: true }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/integrations/exports") {
    requirePermission(context, "integrations.manage"); const parsed = integrationExportSchema.parse(await readJson(request)); requireOrg(context, parsed.organizationId, "integrations.manage"); if(!context.scans.get(parsed.scanId,parsed.organizationId))throw new HttpError(404,"Scan not found in the selected organization."); const result = context.integrationExports.create(parsed, context.principal!.userId); context.cloudSync.record(parsed.organizationId,"integration-export",result.exportId,"UPSERT",{scanId:parsed.scanId,format:parsed.format,artifactId:result.artifactId}); audit.append({ actorLabel: context.principal?.userId, action: "INTEGRATION_EXPORT_CREATED", resourceType: "SCAN", resourceId: parsed.scanId, summary: `${parsed.format} integration export created.` }); sendJson(response, 201, result); return;
  }
  if (request.method === "POST" && url.pathname === "/api/operations/modules") {
    requirePermission(context, "operations.read"); const parsed = thirdPartyModuleRegisterSchema.parse(await readJson(request)); requireOrg(context, parsed.organizationId, "modules.manage"); const id = context.thirdPartyModules.register(parsed.organizationId, parsed.packageDirectory, context.principal!.userId, parsed.bundlePath); context.cloudSync.record(parsed.organizationId,"third-party-module",id,"UPSERT",{status:"REGISTERED"}); audit.append({ actorLabel: context.principal?.userId, action: "THIRD_PARTY_MODULE_REGISTERED", resourceType: "THIRD_PARTY_MODULE", resourceId: id, summary: "Third-party module package registered for separate approval." }); sendJson(response, 201, { moduleId: id }); return;
  }
  const moduleApprove = /^\/api\/operations\/modules\/(?<id>[0-9a-f-]+)\/approve$/.exec(url.pathname);
  if (request.method === "POST" && moduleApprove?.groups?.id) { requirePermission(context, "operations.read"); const organizationId=context.thirdPartyModules.organizationForModule(moduleApprove.groups.id); requireOrg(context, organizationId, "modules.manage"); await readJson(request); context.thirdPartyModules.approve(moduleApprove.groups.id, context.principal!.userId); context.cloudSync.record(organizationId,"third-party-module",moduleApprove.groups.id,"UPSERT",{status:"APPROVED"}); audit.append({ actorLabel: context.principal?.userId, action: "THIRD_PARTY_MODULE_APPROVED", resourceType: "THIRD_PARTY_MODULE", resourceId: moduleApprove.groups.id, summary: "Exact third-party module package approved." }); sendJson(response, 200, { ok: true }); return; }
  const moduleDisable = /^\/api\/operations\/modules\/(?<id>[0-9a-f-]+)\/disable$/.exec(url.pathname);
  if (request.method === "POST" && moduleDisable?.groups?.id) { requirePermission(context, "operations.read"); const organizationId = context.thirdPartyModules.organizationForModule(moduleDisable.groups.id); requireOrg(context, organizationId, "modules.manage"); await readJson(request); context.thirdPartyModules.disable(moduleDisable.groups.id); audit.append({ actorLabel: context.principal?.userId, action: "THIRD_PARTY_MODULE_DISABLED", resourceType: "THIRD_PARTY_MODULE", resourceId: moduleDisable.groups.id, summary: "Module disabled for subsequent executions." }); sendJson(response, 200, { ok: true }); return; }
  const moduleExecute = /^\/api\/operations\/modules\/(?<id>[0-9a-f-]+)\/execute$/.exec(url.pathname);
  if (request.method === "POST" && moduleExecute?.groups?.id) { requirePermission(context, "operations.read"); requireOrg(context, context.thirdPartyModules.organizationForModule(moduleExecute.groups.id), "modules.manage"); const parsed = thirdPartyModuleExecuteSchema.parse(await readJson(request)); const result = await context.thirdPartyModules.execute(moduleExecute.groups.id, parsed.input, parsed.broker); const capability = (result as { capabilitySummary?: Record<string, unknown> } | undefined)?.capabilitySummary; audit.append({ actorLabel: context.principal?.userId, action: "THIRD_PARTY_MODULE_EXECUTED", resourceType: "THIRD_PARTY_MODULE", resourceId: moduleExecute.groups.id, summary: parsed.broker ? "Approved third-party module executed through the capability request broker." : "Approved third-party module executed in the restricted SDK host.", metadata: { brokered: Boolean(parsed.broker), ...(parsed.broker ? { targetOrigin: parsed.broker.approval.targetOrigin, packageDigest: parsed.broker.approval.packageDigest } : {}), ...(capability ? { capability } : {}) } }); sendJson(response, 200, { result }); return; }
  if (request.method === "POST" && url.pathname === "/api/provider-adapters/preview") {
    requirePermission(context, "scans.create");
    const parsed = providerAdapterInputSchema.parse(await readJson(request));
    const preview = await context.providerAdapters.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_PREVIEWED", resourceType: "TARGET", resourceId: parsed.targetId, summary: "Reusable fixture/provider adapter previewed without executing requests.", metadata: { engineId: parsed.engineId, provider: parsed.provider, adapterDigest: preview.adapterDigest, blockerCount: preview.blockers.length } });
    sendJson(response, 200, { preview });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/provider-adapters") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterInputSchema.parse(await readJson(request));
    const adapter = await context.providerAdapters.create(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_CREATED", resourceType: "PROVIDER_ADAPTER", resourceId: String(adapter.id), summary: "Encrypted reusable fixture/provider adapter draft created.", metadata: { targetId: parsed.targetId, engineId: parsed.engineId, provider: parsed.provider } });
    sendJson(response, 201, { adapter });
    return;
  }
  const providerAdapterUpdate = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && providerAdapterUpdate?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterInputSchema.parse(await readJson(request));
    const adapter = await context.providerAdapters.update(providerAdapterUpdate.groups.id, parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_VERSION_CREATED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterUpdate.groups.id, summary: "A new immutable provider-adapter draft version was created; the reviewed version remains unchanged until review.", metadata: { engineId: parsed.engineId, provider: parsed.provider } });
    sendJson(response, 200, { adapter });
    return;
  }
  const providerAdapterReview = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterReview?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterReviewSchema.parse(await readJson(request));
    const adapter = await context.providerAdapters.review(providerAdapterReview.groups.id, parsed.versionId, parsed.adapterDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_REVIEWED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterReview.groups.id, summary: "Exact encrypted provider-adapter version reviewed and activated.", metadata: { versionId: parsed.versionId, adapterDigest: parsed.adapterDigest } });
    sendJson(response, 200, { adapter });
    return;
  }
  const providerAdapterState = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/state$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterState?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterStateSchema.parse(await readJson(request));
    const adapter = context.providerAdapters.setEnabled(providerAdapterState.groups.id, parsed.enabled, parsed.impactDigest);
    audit.append({ actorLabel: context.principal?.userId, action: parsed.enabled ? "PROVIDER_ADAPTER_ENABLED" : "PROVIDER_ADAPTER_DISABLED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterState.groups.id, summary: `Provider adapter ${parsed.enabled ? "enabled" : "disabled"} after dependency-impact verification.`, metadata: { impactDigest: parsed.impactDigest } });
    sendJson(response, 200, { adapter });
    return;
  }
  const providerAdapterMaterialize = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/materialize$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterMaterialize?.groups?.id) {
    requirePermission(context, "scans.create");
    const materialized = context.providerAdapters.materialize(providerAdapterMaterialize.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_MATERIALIZED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterMaterialize.groups.id, summary: "Reviewed adapter materialized into a dashboard Scan Studio draft; execution remains separately previewed and authorized." });
    sendJson(response, 200, { materialized });
    return;
  }
  const providerAdapterRecommendation = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/recommendation$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterRecommendation?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const body = await readJson(request) as { recommendationId?: unknown };
    if (typeof body.recommendationId !== "string") throw new HttpError(400, "recommendationId is required.");
    context.providerAdapters.bindRecommendation(providerAdapterRecommendation.groups.id, body.recommendationId, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_RECOMMENDATION_BOUND", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterRecommendation.groups.id, summary: "Reviewed adapter bound to an exact approved adaptive recommendation.", metadata: { recommendationId: body.recommendationId } });
    sendJson(response, 200, { adapter: context.providerAdapters.get(providerAdapterRecommendation.groups.id) });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/continuous-assurance/preview") {
    requirePermission(context, "scans.create");
    const parsed = continuousAssurancePolicyInputSchema.parse(await readJson(request));
    const preview = await context.continuousAssurance.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CONTINUOUS_ASSURANCE_PREVIEWED", resourceType: "TARGET", resourceId: parsed.targetId, summary: "Continuous assurance policy previewed without execution.", metadata: { policyDigest: preview.policyDigest, blockers: preview.blockers.length, adapters: preview.adapterBindings.length } });
    sendJson(response, 200, { preview }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/continuous-assurance/policies") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = continuousAssurancePolicyInputSchema.parse(await readJson(request));
    const result = await context.continuousAssurance.create(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "CONTINUOUS_ASSURANCE_POLICY_CREATED", resourceType: "CONTINUOUS_ASSURANCE_POLICY", resourceId: String((result.policy as {id?:unknown}).id), summary: "Continuous assurance draft created; deployment token issued once.", metadata: { targetId: parsed.targetId } });
    sendJson(response, 201, result); return;
  }
  const assurancePolicyUpdate = /^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && assurancePolicyUpdate?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = continuousAssurancePolicyInputSchema.parse(await readJson(request));
    const policy = await context.continuousAssurance.update(assurancePolicyUpdate.groups.id, parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "CONTINUOUS_ASSURANCE_POLICY_UPDATED", resourceType: "CONTINUOUS_ASSURANCE_POLICY", resourceId: assurancePolicyUpdate.groups.id, summary: "Policy updated as a new immutable draft; execution paused pending review." });
    sendJson(response, 200, { policy }); return;
  }
  const assuranceReview = /^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "POST" && assuranceReview?.groups?.id) {
    requirePermission(context, "controlledMutation.approve"); const parsed=continuousAssuranceReviewSchema.parse(await readJson(request));
    const policy=await context.continuousAssurance.review(assuranceReview.groups.id,parsed.versionId,parsed.policyDigest,context.principal?.userId??"local-operator");
    audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_POLICY_REVIEWED",resourceType:"CONTINUOUS_ASSURANCE_POLICY",resourceId:assuranceReview.groups.id,summary:"Exact policy, target revision, adapters, actors, budgets, authorization, baselines, and gates reviewed and activated.",metadata:{versionId:parsed.versionId,policyDigest:parsed.policyDigest}}); sendJson(response,200,{policy});return;
  }
  const assuranceState=/^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/state$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceState?.groups?.id){requirePermission(context,"controlledMutation.approve");const parsed=continuousAssuranceStateSchema.parse(await readJson(request));const policy=context.continuousAssurance.setEnabled(assuranceState.groups.id,parsed.enabled,parsed.impactDigest);audit.append({actorLabel:context.principal?.userId,action:parsed.enabled?"CONTINUOUS_ASSURANCE_ENABLED":"CONTINUOUS_ASSURANCE_DISABLED",resourceType:"CONTINUOUS_ASSURANCE_POLICY",resourceId:assuranceState.groups.id,summary:`Continuous assurance ${parsed.enabled?"enabled":"disabled"} after dependency-impact verification.`});sendJson(response,200,{policy});return;}
  const assuranceRun=/^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/run$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceRun?.groups?.id){requirePermission(context,"controlledMutation.approve");continuousAssuranceRunSchema.parse(await readJson(request));const run=await context.continuousAssurance.runNow(assuranceRun.groups.id,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_RUN_STARTED",resourceType:"CONTINUOUS_ASSURANCE_RUN",resourceId:String(run.id),summary:"Reviewed continuous assurance run queued."});sendJson(response,202,{run});return;}
  const assuranceToken=/^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/rotate-token$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceToken?.groups?.id){requirePermission(context,"settings.manage");continuousAssuranceTokenRotationSchema.parse(await readJson(request));const result=context.continuousAssurance.rotateTriggerToken(assuranceToken.groups.id,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_TOKEN_ROTATED",resourceType:"CONTINUOUS_ASSURANCE_POLICY",resourceId:assuranceToken.groups.id,summary:"Deployment trigger token rotated; prior token invalidated."});sendJson(response,200,result);return;}
  const assuranceAck=/^\/api\/continuous-assurance\/notifications\/(?<id>[0-9a-f-]+)\/acknowledge$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceAck?.groups?.id){requirePermission(context,"controlledMutation.approve");continuousAssuranceNotificationAckSchema.parse(await readJson(request));context.continuousAssurance.acknowledge(assuranceAck.groups.id,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_NOTIFICATION_ACKNOWLEDGED",resourceType:"CONTINUOUS_ASSURANCE_NOTIFICATION",resourceId:assuranceAck.groups.id,summary:"Continuous assurance operator notification acknowledged."});sendJson(response,200,{ok:true});return;}
  if(request.method==="PUT"&&url.pathname==="/api/evidence-governance/policy"){requirePermission(context,"settings.manage");const parsed=evidenceGovernancePolicySchema.parse(await readJson(request));const policy=context.evidenceGovernance.updatePolicy(parsed,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_GOVERNANCE_POLICY_UPDATED",resourceType:"EVIDENCE_GOVERNANCE_POLICY",summary:"Retention policy updated; failed, cleanup, and unreviewed evidence remain protected."});sendJson(response,200,{policy});return;}
  if(request.method==="POST"&&url.pathname==="/api/evidence-governance/exports"){requirePermission(context,"proofPacks.create");const parsed=evidenceExportSchema.parse(await readJson(request));const exported=context.evidenceGovernance.createExport(parsed.scanIds,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_EXPORT_CREATED",resourceType:"EVIDENCE_EXPORT",resourceId:String(exported.id),summary:"Encrypted, integrity-signed evidence export created.",metadata:{scanCount:parsed.scanIds.length}});sendJson(response,201,{export:exported});return;}
  const evidenceVerify=/^\/api\/evidence-governance\/exports\/(?<id>[0-9a-f-]+)\/verify$/.exec(url.pathname);
  if(request.method==="POST"&&evidenceVerify?.groups?.id){requirePermission(context,"artifacts.download");const value=context.evidenceGovernance.verifyExport(evidenceVerify.groups.id);audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_EXPORT_VERIFIED",resourceType:"EVIDENCE_EXPORT",resourceId:evidenceVerify.groups.id,summary:"Evidence export authenticity, installation binding, decryption, manifest, and embedded artifact digests verified."});sendJson(response,200,{export:value});return;}
  if(request.method==="POST"&&url.pathname==="/api/evidence-governance/purge-preview"){requirePermission(context,"settings.manage");sendJson(response,200,context.evidenceGovernance.purgePreview());return;}
  if(request.method==="POST"&&url.pathname==="/api/evidence-governance/purge"){requirePermission(context,"settings.manage");const parsed=evidencePurgeSchema.parse(await readJson(request));const result=context.evidenceGovernance.purge(parsed.previewDigest,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_RETENTION_PURGE_EXECUTED",resourceType:"EVIDENCE_GOVERNANCE_POLICY",summary:`Purged ${result.purgedCount} eligible artifact(s); ${result.failedCount} failed.`,metadata:result});sendJson(response,200,result);return;}
  if (request.method === "POST" && url.pathname === "/api/adaptive-security/analyze") {
    requirePermission(context, "scans.create");
    const parsed = adaptiveAnalyzeSchema.parse(await readJson(request));
    const snapshot = await context.adaptiveSecurity.analyze(parsed.targetId, parsed.scanId);
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_SECURITY_MODEL_ANALYZED", resourceType: "SCAN", resourceId: parsed.scanId, summary: "Completed scan evidence analyzed into an adaptive security model.", metadata: { targetId: parsed.targetId, snapshotId: snapshot.id, modelDigest: snapshot.modelDigest } });
    sendJson(response, 201, { snapshot });
    return;
  }
  if (request.method === "PUT" && url.pathname === "/api/adaptive-security/policy") {
    requirePermission(context, "settings.manage");
    const parsed = adaptivePolicyInputSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.setPolicy(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_SECURITY_POLICY_UPDATED", resourceType: "TARGET", resourceId: parsed.targetId, summary: "Adaptive coverage and drift policy updated.", metadata: { requiredLanes: parsed.requiredLanes, requireEvidenceForNotApplicable: parsed.requireEvidenceForNotApplicable, detectRemovedSurfaces: parsed.detectRemovedSurfaces } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveBaseline = /^\/api\/adaptive-security\/snapshots\/(?<id>[0-9a-f-]+)\/accept$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveBaseline?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = adaptiveBaselineSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.acceptBaseline(adaptiveBaseline.groups.id, parsed.modelDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_SECURITY_BASELINE_ACCEPTED", resourceType: "ADAPTIVE_SECURITY_SNAPSHOT", resourceId: adaptiveBaseline.groups.id, summary: "Exact observed target security model accepted as the expected baseline.", metadata: { modelDigest: parsed.modelDigest } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveRecommendation = /^\/api\/adaptive-security\/recommendations\/(?<id>[0-9a-f-]+)\/decision$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveRecommendation?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = adaptiveRecommendationDecisionSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.decideRecommendation(adaptiveRecommendation.groups.id, parsed.decision, parsed.rationale, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: `ADAPTIVE_RECOMMENDATION_${parsed.decision}`, resourceType: "ADAPTIVE_SECURITY_RECOMMENDATION", resourceId: adaptiveRecommendation.groups.id, summary: `Adaptive test recommendation ${parsed.decision.toLowerCase()}; no execution was implied.`, metadata: { rationale: parsed.rationale } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveLink = /^\/api\/adaptive-security\/recommendations\/(?<id>[0-9a-f-]+)\/link$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveLink?.groups?.id) {
    requirePermission(context, context.adaptiveSecurity.recommendationRequiresApproval(adaptiveLink.groups.id) ? "controlledMutation.approve" : "scans.create");
    const parsed = adaptiveRecommendationLinkSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.linkRecommendation(adaptiveLink.groups.id, parsed.scanId, parsed.caseFingerprint, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_RECOMMENDATION_EXECUTION_LINKED", resourceType: "ADAPTIVE_SECURITY_RECOMMENDATION", resourceId: adaptiveLink.groups.id, summary: "An explicitly approved recommendation was linked to an exact same-target workflow case for verification.", metadata: { scanId: parsed.scanId, caseFingerprint: parsed.caseFingerprint } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveMaterialize = /^\/api\/adaptive-security\/recommendations\/(?<id>[0-9a-f-]+)\/materialize$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveMaterialize?.groups?.id) {
    requirePermission(context, "scans.create");
    const materialized = context.adaptiveSecurity.materializeRecommendation(adaptiveMaterialize.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_CASE_MATERIALIZED", resourceType: "ADAPTIVE_RECOMMENDATION", resourceId: adaptiveMaterialize.groups.id, summary: "Evidence-bound recommendation materialized into an executable Scan Studio contract; no target request was sent.", metadata: { engineId: materialized.engineId, automationState: (materialized.automation as { state?: string }).state, executionFingerprint: (materialized.binding as { executionFingerprint: string }).executionFingerprint } });
    sendJson(response, 200, { materialized });
    return;
  }
  const adaptiveRefresh = /^\/api\/adaptive-security\/recommendations\/(?<id>[0-9a-f-]+)\/refresh$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveRefresh?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const adaptiveSecurity = context.adaptiveSecurity.refreshRecommendation(adaptiveRefresh.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_RECOMMENDATION_VERIFICATION_REFRESHED", resourceType: "ADAPTIVE_SECURITY_RECOMMENDATION", resourceId: adaptiveRefresh.groups.id, summary: "Linked recommendation verification refreshed from durable scan evidence." });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/live-acceptance/preview") {
    requirePermission(context, "scans.create");
    const parsed = liveAcceptancePlanInputSchema.parse(await readJson(request));
    const preview = await context.liveAcceptance.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_PREVIEWED", resourceType: "TARGET", resourceId: parsed.targetId, summary: `Live acceptance plan previewed with ${parsed.lanes.length} lane(s).`, metadata: { planDigest: preview.planDigest, laneCount: parsed.lanes.length, blockerCount: preview.blockers.length } });
    sendJson(response, 200, { preview });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/live-acceptance/plans") {
    requirePermission(context, "scans.create");
    const parsed = liveAcceptancePlanInputSchema.parse(await readJson(request));
    const result = await context.liveAcceptance.create(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_CREATED", resourceType: "LIVE_ACCEPTANCE_PLAN", resourceId: String(result.plan.id), summary: `Encrypted live acceptance plan created with ${parsed.lanes.length} lane(s).`, metadata: { targetId: parsed.targetId, planDigest: result.preview.planDigest } });
    sendJson(response, 201, result);
    return;
  }
  const liveAcceptancePlanUpdate = /^\/api\/live-acceptance\/plans\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && liveAcceptancePlanUpdate?.groups?.id) {
    requirePermission(context, "scans.create");
    const body = await readJson(request) as { input?: unknown; expectedVersion?: unknown };
    if (!Number.isInteger(body.expectedVersion)) throw new HttpError(400, "Live acceptance update requires expectedVersion.");
    const result = await context.liveAcceptance.update(liveAcceptancePlanUpdate.groups.id, body.input, Number(body.expectedVersion));
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_UPDATED", resourceType: "LIVE_ACCEPTANCE_PLAN", resourceId: liveAcceptancePlanUpdate.groups.id, summary: "Live acceptance plan updated; prior review was invalidated.", metadata: { planDigest: result.preview.planDigest } });
    sendJson(response, 200, result);
    return;
  }
  const liveAcceptanceReview = /^\/api\/live-acceptance\/plans\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "POST" && liveAcceptanceReview?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = liveAcceptanceReviewSchema.parse(await readJson(request));
    const plan = await context.liveAcceptance.review(liveAcceptanceReview.groups.id, parsed.planDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_REVIEWED", resourceType: "LIVE_ACCEPTANCE_PLAN", resourceId: liveAcceptanceReview.groups.id, summary: "Exact live acceptance plan reviewed and bound.", metadata: { planDigest: parsed.planDigest } });
    sendJson(response, 200, { plan });
    return;
  }
  const liveAcceptanceExecute = /^\/api\/live-acceptance\/plans\/(?<id>[0-9a-f-]+)\/execute$/.exec(url.pathname);
  if (request.method === "POST" && liveAcceptanceExecute?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = liveAcceptanceExecuteSchema.parse(await readJson(request));
    const run = await context.liveAcceptance.execute(liveAcceptanceExecute.groups.id, parsed.planDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_RUN_STARTED", resourceType: "LIVE_ACCEPTANCE_RUN", resourceId: String(run.id), summary: "Reviewed live acceptance run started.", metadata: { planId: liveAcceptanceExecute.groups.id, planDigest: parsed.planDigest } });
    sendJson(response, 202, { run });
    return;
  }
  const liveAcceptanceCancel = /^\/api\/live-acceptance\/runs\/(?<id>[0-9a-f-]+)\/cancel$/.exec(url.pathname);
  if (request.method === "POST" && liveAcceptanceCancel?.groups?.id) {
    requirePermission(context, "scans.cancel");
    const run = context.liveAcceptance.cancelRun(liveAcceptanceCancel.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_RUN_CANCELLED", resourceType: "LIVE_ACCEPTANCE_RUN", resourceId: liveAcceptanceCancel.groups.id, summary: "Live acceptance run cancellation requested." });
    sendJson(response, 202, { run });
    return;
  }
  const assistedPublication = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/assisted-review\/publish$/.exec(url.pathname);
  if (request.method === "POST" && assistedPublication?.groups?.id) {
    requirePermission(context, "proofPacks.create");
    try {
      const published = new AssistedReviewService(context.database, context.paths).publish(assistedPublication.groups.id, context.principal!.userId);
      audit.append({ actorLabel: context.principal!.userId, action: "ASSISTED_REVIEW_PUBLISHED", resourceType: "SCAN", resourceId: assistedPublication.groups.id, summary: "Published human-reviewed customer report.", metadata: published });
      sendJson(response, 201, published);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("ASSISTED_REVIEW_NOT_READY:")) sendJson(response, 409, { error: error.message });
      else if (error instanceof Error && error.message === "ASSISTED_REVIEW_NOT_FOUND") sendJson(response, 404, { error: "No assisted review exists for this scan." });
      else throw error;
    }
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/production-mutations/preview") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = productionMutationCaseSchema.parse(await readJson(request));
    const target = targets.get(parsed.targetId);
    if (!target) throw new HttpError(404, "Production target not found.");
    const compiled = compileProductionMutationCase(parsed, target, nowIso(), context.principal?.userId ?? "local-operator");
    const planIdentity = productionMutationPlanIdentity(parsed, target);
    sendJson(response, 200, { preview: compiled.preview, planIdentity });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/production-mutations/approvals") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = productionMutationApprovalSchema.parse(await readJson(request));
    const target = targets.get(parsed.case.targetId);
    if (!target) throw new HttpError(404, "Production target not found.");
    const compiled = compileProductionMutationCase(parsed.case, target, nowIso(), context.principal?.userId ?? "local-operator");
    const planIdentity = productionMutationPlanIdentity(parsed.case, target);
    const targetIdentityFingerprint = createHash("sha256").update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`).digest("hex");
    const scopeDigest = createHash("sha256").update(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())).digest("hex");
    const id = mutationApprovals.create({ caseId: parsed.case.caseId, targetId: parsed.case.targetId, targetOrigin: target.baseOrigin, targetIdentityFingerprint, scopeDigest, planIdentity, authorizationSummary: parsed.authorizationDeclaration, expiresAt: parsed.case.authorizationExpiresAt });
    audit.append({ actorLabel: context.principal?.userId, action: "PRODUCTION_MUTATION_APPROVAL_CREATED", resourceType: "MUTATION_APPROVAL", resourceId: id, summary: "Production controlled-mutation approval created from an explicit case.", metadata: { caseId: parsed.case.caseId, targetId: parsed.case.targetId, planIdentity } });
    sendJson(response, 201, { approval: mutationApprovals.get(id), preview: compiled.preview });
    return;
  }
  const productionExecute = /^\/api\/production-mutations\/approvals\/(?<id>[0-9a-f-]+)\/execute$/.exec(url.pathname);
  if (request.method === "POST" && productionExecute?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = productionMutationCaseSchema.parse(await readJson(request));
    const approval = mutationApprovals.get(productionExecute.groups.id);
    const target = targets.get(parsed.targetId);
    if (!approval || approval.status !== "APPROVED" || !target) throw new HttpError(409, "PRODUCTION_MUTATION_APPROVAL_REQUIRED");
    const compiled = compileProductionMutationCase(parsed, target, nowIso(), context.principal?.userId ?? "local-operator");
    const planIdentity = productionMutationPlanIdentity(parsed, target);
    if (approval.caseId !== parsed.caseId || approval.targetId !== parsed.targetId || approval.planIdentity !== planIdentity) throw new HttpError(409, "PRODUCTION_MUTATION_PLAN_MISMATCH");
    const requestForWorker: DashboardScanCreateRequest = { target: target.baseOrigin, targetId: target.id, profile: "authenticated", credentialProfileId: parsed.actorCredentialProfileId, authorizationDeclaration: "Approved production controlled-mutation case.", studio: { version: 1, scanName: `Production mutation ${parsed.caseId}`, authorization: { category: "OWNED", confirmed: true }, scope: scopeSchema.parse(target.approvedScope), authentication: { mode: "primary", primary: { source: "saved", credentialProfileId: parsed.actorCredentialProfileId } }, outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] }, includeModules: ["privilege-mutation-testing"] };
    const contract = { ...compiled.contract, approvalBinding: { planIdentity: approval.planIdentity, targetIdentityFingerprint: approval.targetIdentityFingerprint, scopeDigest: approval.scopeDigest } };
    const scanId = await execution.enqueue(requestForWorker, [contract], approval.id);
    audit.append({ actorLabel: context.principal?.userId, action: "PRODUCTION_MUTATION_EXECUTION_QUEUED", resourceType: "SCAN", resourceId: scanId, summary: "Approved production controlled-mutation case queued through the isolated worker.", metadata: { caseId: parsed.caseId, targetId: parsed.targetId, approvalId: productionExecute.groups.id } });
    sendJson(response, 202, { scanId, approvalId: productionExecute.groups.id, status: "QUEUED", preview: compiled.preview });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/controlled-mutations/approvals") {
    // Legacy controlled-contract approvals remain distinct from workflow cleanup authorization.
    requirePermission(context, "controlledMutation.approve");
    const parsed = controlledMutationApprovalSchema.parse(await readJson(request));
    const target = targets.get(parsed.targetId);
    if (!target || target.baseOrigin !== new URL(parsed.targetOrigin).origin) throw new HttpError(400, "Mutation approval target does not match the registered target origin.");
    const targetIdentityFingerprint = createHash("sha256").update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`).digest("hex");
    const scopeDigest = createHash("sha256").update(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())).digest("hex");
    const id = mutationApprovals.create({ ...parsed, authorizationSummary: parsed.authorizationDeclaration, targetIdentityFingerprint, scopeDigest });
    audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_PREVIEWED", resourceType: "MUTATION_APPROVAL", resourceId: id, summary: "Controlled mutation approval preview persisted.", metadata: { caseId: parsed.caseId, targetId: parsed.targetId, planIdentity: parsed.planIdentity } });
    sendJson(response, 201, { approval: mutationApprovals.get(id) });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/workflow-mutations/recovery") {
    requirePermission(context, "controlledMutation.recover");
    const parsed = workflowRecoveryRequestSchema.parse(await readJson(request));
    const jobId = await context.workflowRecovery.enqueue(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "WORKFLOW_CLEANUP_AUTHORIZED", resourceType: "RECOVERY_JOB", resourceId: jobId, summary: "Operator authorized stored cleanup and verification only.", metadata: { caseId: parsed.caseId, checkpointDigest: parsed.checkpointDigest } });
    sendJson(response, 202, { jobId });
    return;
  }
  const approval = /^\/api\/controlled-mutations\/approvals\/(?<id>[0-9a-f-]+)\/approve$/.exec(url.pathname);
  if (request.method === "POST" && approval?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const approved = mutationApprovals.approve(approval.groups.id, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_APPROVED", resourceType: "MUTATION_APPROVAL", resourceId: approval.groups.id, summary: "Controlled mutation case approved for exact execution.", metadata: { caseId: approved.caseId, targetId: approved.targetId, planIdentity: approved.planIdentity } });
    sendJson(response, 200, { approval: approved });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/controlled-mutations/recover") {
    requirePermission(context, "controlledMutation.recover");
    const parsed = controlledMutationRecoverySchema.parse(await readJson(request));
    const target = targets.get(parsed.targetId);
    if (!target) throw new HttpError(404, "Controlled mutation recovery target not found.");
    if (!parsed.credentialProfileId) throw new HttpError(400, "Controlled mutation recovery requires a fresh credential profile.");
    const jobId = randomUUID();
    void mutationRecovery.queueRecovery({ recoveryJobId: jobId, approvalId: parsed.approvalId, bundlePath: parsed.bundlePath, caseId: parsed.caseId, targetId: parsed.targetId, credentialProfileId: parsed.credentialProfileId, workerRequest: { target: target.baseOrigin, targetId: target.id, profile: "authenticated", authorizationDeclaration: "Approved controlled-mutation recovery operation.", includeModules: ["privilege-mutation-testing"], studio: { version: 1, scanName: `Recovery ${parsed.caseId}`, authorization: { category: "OWNED", confirmed: true }, scope: scopeSchema.parse(target.approvedScope), authentication: { mode: "primary", primary: { source: "saved", credentialProfileId: parsed.credentialProfileId } }, outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] } } }).then((result) => audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_RECOVERY_COMPLETED", resourceType: "MUTATION_APPROVAL", resourceId: parsed.approvalId, summary: `Controlled mutation recovery completed with ${result.cleanupOutcome}.`, metadata: { caseId: parsed.caseId, targetId: parsed.targetId, cleanupOutcome: result.cleanupOutcome } })).catch((error: unknown) => audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_RECOVERY_FAILED", resourceType: "MUTATION_APPROVAL", resourceId: parsed.approvalId, summary: "Controlled mutation recovery failed; operator action remains required.", metadata: { caseId: parsed.caseId, targetId: parsed.targetId, error: error instanceof Error ? error.message.slice(0, 200) : "unknown" } }));
    sendJson(response, 202, { recoveryJobId: jobId, status: "QUEUED" });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/session/logout") {
    if (context.mode === "local") context.localSessions?.destroy(response);
    else context.serverSessions?.logout(request, response);
    audit.append({ action: "LOGOUT", resourceType: "SESSION", summary: "Local session ended." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/auth/logout") {
    context.serverSessions?.logout(request, response);
    audit.append({ actorLabel: context.principal?.userId, action: "LOGOUT", resourceType: "SESSION", summary: "Server session logged out." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/auth/revoke-all") {
    requirePermission(context, "scans.read");
    if (context.principal?.mode === "server") context.serverSessions?.revokeUserSessions(context.principal.userId);
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/credential-profiles") {
    requirePermission(context, "credentials.create");
    const parsed = credentialProfileSchema.parse(await readJson(request));
    const organizationId = resourceOrganization(context, "resources.use");
    if (parsed.projectId && !context.projects.get(parsed.projectId, true, organizationId)) throw new HttpError(400, "Credential project is outside the selected organization.");
    if (parsed.targetId && !context.targets.get(parsed.targetId, true, organizationId)) throw new HttpError(400, "Credential target is outside the selected organization.");
    const profileId = context.vault.create({ ...parsed, organizationId, createdByUserId: context.principal?.userId });
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_CREATED", resourceType: "CREDENTIAL_PROFILE", resourceId: profileId, summary: `Credential profile created: ${parsed.safeAlias}.` });
    sendJson(response, 201, { profileId });
    return;
  }
  const credential = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && credential?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialProfileSchema.parse(await readJson(request));
    context.vault.update(credential.groups.id, parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_UPDATED", resourceType: "CREDENTIAL_PROFILE", resourceId: credential.groups.id, summary: `Credential profile updated: ${parsed.safeAlias}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialMetadata = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/metadata$/.exec(url.pathname);
  if (request.method === "PATCH" && credentialMetadata?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialMetadataSchema.parse(await readJson(request));
    context.vault.updateMetadata(credentialMetadata.groups.id, parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_METADATA_UPDATED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialMetadata.groups.id, summary: `Credential metadata updated: ${parsed.safeAlias}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialSecret = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/replace-secret$/.exec(url.pathname);
  if (request.method === "POST" && credentialSecret?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialReplacementSchema.parse(await readJson(request));
    context.vault.assertImpactDigest(credentialSecret.groups.id, parsed.impactDigest);
    context.vault.replaceSecret(credentialSecret.groups.id, parsed.secret);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_SECRET_REPLACED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialSecret.groups.id, summary: "Credential secret material replaced after dependency-impact review; no secret value was retained in audit output.", metadata: { dependencyImpactDigest: parsed.impactDigest } });
    sendJson(response, 200, { ok: true, profile: context.vault.getSummary(credentialSecret.groups.id) });
    return;
  }
  const credentialRenew = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/renew$/.exec(url.pathname);
  if (request.method === "POST" && credentialRenew?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialRenewalSchema.parse(await readJson(request));
    const profile = context.vault.renew(credentialRenew.groups.id, parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_RENEWED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialRenew.groups.id, summary: "Credential renewed after dependency-impact review; a fresh health test is required.", metadata: { dependencyImpactDigest: parsed.impactDigest, expiresAt: parsed.expiresAt, secretVersion: profile.secretVersion } });
    sendJson(response, 200, { ok: true, profile });
    return;
  }
  const credentialEnable = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/enable$/.exec(url.pathname);
  if (request.method === "POST" && credentialEnable?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialDependencyAcknowledgementSchema.parse(await readJson(request));
    context.vault.setEnabled(credentialEnable.groups.id, true, parsed.impactDigest);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_ENABLED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialEnable.groups.id, summary: "Credential profile enabled after dependency-impact review; a fresh health test is required.", metadata: { dependencyImpactDigest: parsed.impactDigest } });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialDisable = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/disable$/.exec(url.pathname);
  if (request.method === "POST" && credentialDisable?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialDependencyAcknowledgementSchema.parse(await readJson(request));
    context.vault.setEnabled(credentialDisable.groups.id, false, parsed.impactDigest);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_DISABLED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialDisable.groups.id, summary: "Credential profile disabled after dependency-impact review.", metadata: { dependencyImpactDigest: parsed.impactDigest } });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialDelete = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/delete$/.exec(url.pathname);
  if (request.method === "POST" && credentialDelete?.groups?.id) {
    requirePermission(context, "credentials.delete");
    context.vault.delete(credentialDelete.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_DELETED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialDelete.groups.id, summary: "Credential profile deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialTest = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/test$/.exec(url.pathname);
  if (request.method === "POST" && credentialTest?.groups?.id) {
    requirePermission(context, "credentials.test");
    const parsed = credentialHealthTestSchema.parse(await readJson(request));
    const result = await context.execution.testCredentialProfile(credentialTest.groups.id, parsed.targetId);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_TEST_EXECUTED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialTest.groups.id, summary: "Bounded credential identity and structure validation completed; no secret value was retained.", metadata: { classification: (result.health as { classification?: unknown } | undefined)?.classification, targetId: parsed.targetId } });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/users") {
    requirePermission(context, "users.manage");
    const parsed = userCreateSchema.parse(await readJson(request));
    const userId = await context.serverSessions!.createUser({ ...parsed, createdByUserId: context.principal?.userId });
    audit.append({ actorLabel: context.principal?.userId, action: "USER_CREATED", resourceType: "USER", resourceId: userId, summary: `User created with role ${parsed.role}.` });
    sendJson(response, 201, { userId });
    return;
  }
  const userUpdate = /^\/api\/users\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && userUpdate?.groups?.id) {
    requirePermission(context, "users.manage");
    const parsed = userUpdateSchema.parse(await readJson(request));
    if (parsed.role) {
      context.serverSessions!.setRole(userUpdate.groups.id, parsed.role);
      audit.append({ actorLabel: context.principal?.userId, action: "ROLE_CHANGED", resourceType: "USER", resourceId: userUpdate.groups.id, summary: `User role changed to ${parsed.role}.` });
    }
    if (typeof parsed.enabled === "boolean") {
      context.serverSessions!.setEnabled(userUpdate.groups.id, parsed.enabled);
      audit.append({ actorLabel: context.principal?.userId, action: parsed.enabled ? "USER_ENABLED" : "USER_DISABLED", resourceType: "USER", resourceId: userUpdate.groups.id, summary: parsed.enabled ? "User enabled." : "User disabled." });
    }
    if (parsed.password) {
      await context.serverSessions!.resetPassword(userUpdate.groups.id, parsed.password);
      audit.append({ actorLabel: context.principal?.userId, action: "PASSWORD_RESET", resourceType: "USER", resourceId: userUpdate.groups.id, summary: "User password reset and sessions revoked." });
    }
    sendJson(response, 200, { ok: true });
    return;
  }
  const userRevoke = /^\/api\/users\/(?<id>[0-9a-f-]+)\/revoke-sessions$/.exec(url.pathname);
  if (request.method === "POST" && userRevoke?.groups?.id) {
    requirePermission(context, "users.manage");
    context.serverSessions!.revokeUserSessions(userRevoke.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "SESSIONS_REVOKED", resourceType: "USER", resourceId: userRevoke.groups.id, summary: "All active sessions revoked." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/scans/plan-preview") {
    requirePermission(context, "scans.create");
    const parsed = dashboardScanCreateSchema.parse(await readJson(request));
    validateScanReferences(context, parsed);
    requireCredentialUsePermission(context, parsed);
    await assertProviderAdapterExecution(context, parsed);
    context.adaptiveSecurity.assertExecutionBinding(parsed);
    const preview = await execution.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "SCAN_STUDIO_PLAN_PREVIEW", resourceType: "TARGET", resourceId: parsed.targetId, summary: `Plan preview resolved for ${new URL(parsed.target).origin}.`, metadata: { projectId: parsed.projectId, profile: parsed.profile, moduleCount: preview.modules.length, studioVersion: parsed.studio?.version } });
    sendJson(response, 200, preview);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/advanced-engines/validate") {
    requirePermission(context, "scans.create");
    const parsed = advancedEngineValidationRequestSchema.parse(await readJson(request));
    const result = validateAdvancedEngineInput(parsed.engineId, parsed.value);
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/scans/identity-test") {
    requirePermission(context, "scans.create");
    const parsed = dashboardScanCreateSchema.parse(await readJson(request));
    validateScanReferences(context, parsed);
    requireCredentialUsePermission(context, parsed);
    const result = await execution.testIdentity(parsed);
    audit.append({
      actorLabel: context.principal?.userId,
      action: "SCAN_STUDIO_IDENTITY_TEST",
      resourceType: "TARGET",
      resourceId: parsed.targetId,
      summary: `Identity test completed for ${new URL(parsed.target).origin}.`,
      metadata: { projectId: parsed.projectId, profile: parsed.profile, authMode: parsed.studio?.authentication.mode ?? "legacy", categories: identityResultCategories(result) }
    });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/scans") {
    requirePermission(context, "scans.create");
    const parsed = dashboardScanCreateSchema.parse(await readJson(request));
    validateScanReferences(context, parsed);
    requireCredentialUsePermission(context, parsed);
    if (parsed.studio?.retestContext) findingCommandCenter.validateRetestContext(parsed.studio.retestContext);
    await assertProviderAdapterExecution(context, parsed);
    context.adaptiveSecurity.assertExecutionBinding(parsed);
    const scanId = await execution.enqueue(parsed, undefined, undefined, resourceOrganization(context, "resources.use"));
    if (parsed.providerAdapterBinding) context.providerAdapters.bindScan(scanId, parsed.providerAdapterBinding);
    if (parsed.studio?.retestContext) {
      findingCommandCenter.recordRetestLaunch({ context: parsed.studio.retestContext, newScanId: scanId, principal: context.principal! });
    }
    audit.append({
      action: "SCAN_CREATED",
      resourceType: "SCAN",
      resourceId: scanId,
      summary: `Queued ${parsed.profile} scan for ${new URL(parsed.target).origin}.`,
      metadata: { projectId: parsed.projectId, targetId: parsed.targetId, hasAuthorizationDeclaration: Boolean(parsed.authorizationDeclaration), retestFindingId: parsed.studio?.retestContext?.findingId }
    });
    sendJson(response, 202, { scanId });
    return;
  }
  const cancel = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/cancel$/.exec(url.pathname);
  if (request.method === "POST" && cancel?.groups?.id) {
    requirePermission(context, "scans.cancel");
    execution.cancel(cancel.groups.id);
    audit.append({ action: "SCAN_CANCELLED", resourceType: "SCAN", resourceId: cancel.groups.id, summary: "Scan cancellation requested." });
    sendJson(response, 202, { ok: true });
    return;
  }
  const rerun = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/rerun$/.exec(url.pathname);
  if (request.method === "POST" && rerun?.groups?.id) {
    requirePermission(context, "scans.create");
    const scanId = await execution.rerun(rerun.groups.id);
    audit.append({ action: "SCAN_RERUN", resourceType: "SCAN", resourceId: scanId, summary: `Created rerun from ${rerun.groups.id}.`, metadata: { sourceScanId: rerun.groups.id } });
    sendJson(response, 202, { scanId });
    return;
  }
  const archive = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && archive?.groups?.id) {
    requirePermission(context, "scans.cancel");
    context.scans.markArchived(archive.groups.id);
    audit.append({ action: "SCAN_ARCHIVED", resourceType: "SCAN", resourceId: archive.groups.id, summary: "Scan archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const deleteScan = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/delete$/.exec(url.pathname);
  if (request.method === "POST" && deleteScan?.groups?.id) {
    requirePermission(context, "scans.cancel");
    context.scans.markDeleted(deleteScan.groups.id);
    audit.append({ action: "SCAN_DELETED", resourceType: "SCAN", resourceId: deleteScan.groups.id, summary: "Scan metadata marked deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const review = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "PATCH" && review?.groups?.id) {
    requirePermission(context, "findings.review");
    const parsed = findingReviewSchema.parse(await readJson(request));
    if (parsed.newStatus === "DUPLICATE") requirePermission(context, "findings.markDuplicate");
    const finding = findingCommandCenter.review({ findingId: review.groups.id, ...parsed,
      principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.takeover ? "FINDING_REVIEW_TAKEN_OVER" : reviewAuditAction(parsed.newStatus), resourceType: "FINDING", resourceId: review.groups.id, summary: parsed.takeover ? "Finding review ownership taken over cooperatively." : `Finding review changed to ${parsed.newStatus}.`, metadata: { newStatus: parsed.newStatus, takeover: parsed.takeover, hasReason: Boolean(parsed.reason), hasNote: Boolean(parsed.note), correlationId: correlationId(request) } });
    sendJson(response, 200, { finding });
    return;
  }
  const remediation = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/remediation$/.exec(url.pathname);
  if (request.method === "PATCH" && remediation?.groups?.id) {
    requirePermission(context, "findings.remediate");
    const parsed = findingRemediationSchema.parse(await readJson(request));
    if (parsed.assigneeUserId !== undefined) requirePermission(context, "findings.assign");
    const finding = findingCommandCenter.remediation({ findingId: remediation.groups.id, ...parsed,
      principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.assigneeUserId !== undefined ? "FINDING_REMEDIATION_ASSIGNED" : "FINDING_REMEDIATION_CHANGED", resourceType: "FINDING", resourceId: remediation.groups.id, summary: `Finding remediation changed to ${parsed.newState}.`, metadata: { newState: parsed.newState, hasNote: Boolean(parsed.note), hasTargetDate: Boolean(parsed.targetFixDate) } });
    sendJson(response, 200, { finding });
    return;
  }
  const note = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/notes$/.exec(url.pathname);
  if (request.method === "POST" && note?.groups?.id) {
    requirePermission(context, "notes.create");
    const parsed = findingNoteSchema.parse(await readJson(request));
    const noteId = findingCommandCenter.addNote({ findingId: note.groups.id, text: parsed.text, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_NOTE_ADDED", resourceType: "FINDING", resourceId: note.groups.id, summary: "Safe analyst note added." });
    sendJson(response, 201, { noteId });
    return;
  }
  const retest = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/retest$/.exec(url.pathname);
  if (request.method === "POST" && retest?.groups?.id) {
    requirePermission(context, "findings.linkRetest");
    const parsed = findingRetestSchema.parse(await readJson(request));
    requireSelectedResource(context,"scan",parsed.scanId,"resources.use");
    const result = findingCommandCenter.linkRetest({ findingId: retest.groups.id, ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_RETEST_LINKED", resourceType: "FINDING", resourceId: retest.groups.id, summary: `Retest linked with state ${result.state}.`, metadata: { scanId: parsed.scanId, compatible: result.compatible, reasonCount: result.reasons.length } });
    sendJson(response, 200, result);
    return;
  }
  const verify = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/verify-fixed$/.exec(url.pathname);
  if (request.method === "POST" && verify?.groups?.id) {
    requirePermission(context, "findings.remediate");
    const parsed = findingVerifySchema.parse(await readJson(request));
    if (parsed.ownerOverride) requirePermission(context, "findings.ownerOverride");
    const finding = findingCommandCenter.verifyFixed({ findingId: verify.groups.id, ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.ownerOverride ? "FINDING_OWNER_VERIFICATION_OVERRIDE" : "FINDING_FIXED_VERIFIED", resourceType: "FINDING", resourceId: verify.groups.id, summary: parsed.ownerOverride ? "Owner override verified finding remediation." : "Compatible retest verified finding remediation.", metadata: { ownerOverride: parsed.ownerOverride } });
    sendJson(response, 200, { finding });
    return;
  }
  const severityOverride = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/severity$/.exec(url.pathname);
  if (request.method === "PATCH" && severityOverride?.groups?.id) {
    requirePermission(context, "findings.overrideSeverity");
    const parsed = findingSeveritySchema.parse(await readJson(request));
    const finding = findingCommandCenter.overrideSeverity({ findingId: severityOverride.groups.id, ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_SEVERITY_OVERRIDDEN", resourceType: "FINDING", resourceId: severityOverride.groups.id, summary: `Effective finding severity changed to ${parsed.severity}.`, metadata: { severity: parsed.severity } });
    sendJson(response, 200, { finding });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/findings/bulk-review") {
    requirePermission(context, "findings.bulkReview");
    const parsed = findingBulkReviewSchema.parse(await readJson(request));
    requireSelectedResources(context,"finding",parsed.findingIds,"resources.use");
    const result = findingCommandCenter.bulkReview({ ...parsed, principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDINGS_BULK_REVIEWED", resourceType: "FINDING_BATCH", summary: `Bulk review applied to ${result.succeeded.length} finding(s); ${result.failed.length} failed.`, metadata: { requested: parsed.findingIds.length, succeeded: result.succeeded.length, failed: result.failed.length, newStatus: parsed.newStatus } });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/findings/bulk-remediation") {
    requirePermission(context, "findings.remediate");
    const parsed = findingBulkRemediationSchema.parse(await readJson(request));
    requireSelectedResources(context,"finding",parsed.findingIds,"resources.use");
    if (parsed.assigneeUserId !== undefined) requirePermission(context, "findings.assign");
    const result = findingCommandCenter.bulkRemediation({ ...parsed, principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDINGS_BULK_REMEDIATED", resourceType: "FINDING_BATCH", summary: `Bulk remediation updated ${result.succeeded.length} finding(s); ${result.failed.length} failed.`, metadata: { requested: parsed.findingIds.length, succeeded: result.succeeded.length, failed: result.failed.length, newState: parsed.newState } });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/findings/bulk-note") {
    requirePermission(context, "notes.create");
    const parsed = findingBulkNoteSchema.parse(await readJson(request));
    requireSelectedResources(context,"finding",parsed.findingIds,"resources.use");
    const result = findingCommandCenter.bulkNote({ ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDINGS_BULK_NOTE_ADDED", resourceType: "FINDING_BATCH", summary: `Bulk note added to ${result.succeeded.length} finding(s); ${result.failed.length} failed.`, metadata: { requested: parsed.findingIds.length, succeeded: result.succeeded.length, failed: result.failed.length } });
    sendJson(response, 200, result);
    return;
  }
  if ((request.method === "POST" || request.method === "PATCH") && url.pathname === "/api/finding-views") {
    requirePermission(context, "savedViews.manage");
    const parsed = savedFindingViewSchema.parse(await readJson(request));
    const viewId = findingCommandCenter.saveView({ ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.shared ? "FINDING_VIEW_SHARED" : "FINDING_VIEW_SAVED", resourceType: "SAVED_FINDING_VIEW", resourceId: viewId, summary: `Finding view saved: ${parsed.name}.`, metadata: { shared: parsed.shared, isDefault: parsed.isDefault } });
    sendJson(response, parsed.id ? 200 : 201, { viewId });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/finding-views/delete") {
    requirePermission(context, "savedViews.manage");
    const parsed = savedFindingViewDeleteSchema.parse(await readJson(request));
    findingCommandCenter.deleteView(parsed.id, context.principal!);
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_VIEW_DELETED", resourceType: "SAVED_FINDING_VIEW", resourceId: parsed.id, summary: "Saved finding view deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/finding-views/default") {
    requirePermission(context, "savedViews.manage");
    const parsed = savedFindingViewDefaultSchema.parse(await readJson(request));
    findingCommandCenter.setDefaultView(parsed.id, context.principal!);
    audit.append({ actorLabel: context.principal?.userId, action: parsed.id ? "FINDING_VIEW_DEFAULT_SET" : "FINDING_VIEW_DEFAULT_CLEARED", resourceType: "SAVED_FINDING_VIEW", resourceId: parsed.id ?? undefined, summary: parsed.id ? "Personal default finding view set." : "Personal default finding view cleared." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/compare") {
    requirePermission(context, "comparisons.create");
    const parsed = compareRequestSchema.parse(await readJson(request));
    requireSelectedResources(context,"scan",[parsed.oldScanId,parsed.newScanId],"resources.use");
    if (parsed.recompute) requirePermission(context, "comparisons.recompute");
    const result = comparison.compare(parsed.oldScanId, parsed.newScanId, { ...(context.principal?.userId ? { createdByUserId: context.principal.userId } : {}), ...(parsed.recompute === undefined ? {} : { recompute: parsed.recompute }) });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.recompute ? "COMPARISON_RECOMPUTED" : "COMPARISON_CREATED", resourceType: "SCAN_COMPARISON", resourceId: result.comparisonId, summary: parsed.recompute ? "Scan comparison recomputed with a traceable engine version." : "Scan comparison created.", metadata: { oldScanId: parsed.oldScanId, newScanId: parsed.newScanId, engineVersion: result.engineVersion } });
    sendJson(response, parsed.recompute ? 200 : 201, comparison.get(result.comparisonId, { page: 1, pageSize: 25 }));
    return;
  }
  const comparisonDelete = /^\/api\/comparisons\/(?<id>[0-9a-f-]+)\/delete$/.exec(url.pathname);
  if (request.method === "POST" && comparisonDelete?.groups?.id) {
    requirePermission(context, "comparisons.delete");
    requireSelectedComparison(context,comparisonDelete.groups.id);
    comparison.delete(comparisonDelete.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "COMPARISON_DELETED", resourceType: "SCAN_COMPARISON", resourceId: comparisonDelete.groups.id, summary: "Scan comparison soft-deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/proof-packs") {
    requirePermission(context, "proofPacks.create");
    const parsed = proofPackCreateSchema.parse(await readJson(request));
    requireSelectedResources(context,"finding",parsed.findingIds,"resources.use");
    const proofPackId = proofPacks.generate(parsed.title, parsed.description, parsed.findingIds,resourceOrganization(context,"resources.use"));
    audit.append({ action: "PROOF_PACK_GENERATED", resourceType: "PROOF_PACK", resourceId: proofPackId, summary: `Generated proof pack with ${parsed.findingIds.length} finding(s).` });
    sendJson(response, 201, { proofPackId });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/import/report") {
    requirePermission(context, "imports.create");
    const parsed = importReportSchema.parse(await readJson(request));
    const result = importer.importReport(parsed.reportPath,resourceOrganization(context,"resources.use"));
    audit.append({ action: "HISTORICAL_REPORT_IMPORTED", resourceType: "SCAN", resourceId: result.scanId, summary: "Imported historical report from approved report root.", metadata: { warningCount: result.warnings.length } });
    sendJson(response, 201, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/projects") {
    requirePermission(context, "projects.manage");
    const parsed = projectSchema.parse(await readJson(request));
    const organizationId = resourceOrganization(context, "resources.use");
    const projectId = projects.create({ ...parsed, organizationId, createdBy: context.principal?.userId });
    audit.append({ action: "PROJECT_CREATED", resourceType: "PROJECT", resourceId: projectId, summary: `Project created: ${parsed.name}.` });
    sendJson(response, 201, { projectId });
    return;
  }
  const projectUpdate = /^\/api\/projects\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && projectUpdate?.groups?.id) {
    requirePermission(context, "projects.manage");
    const parsed = projectSchema.parse(await readJson(request));
    const organizationId = resourceOrganization(context, "resources.use");
    projects.update(projectUpdate.groups.id, { ...parsed, organizationId });
    audit.append({ action: "PROJECT_UPDATED", resourceType: "PROJECT", resourceId: projectUpdate.groups.id, summary: `Project updated: ${parsed.name}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const projectArchive = /^\/api\/projects\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && projectArchive?.groups?.id) {
    requirePermission(context, "projects.manage");
    projects.archive(projectArchive.groups.id, resourceOrganization(context, "resources.use"));
    audit.append({ action: "PROJECT_ARCHIVED", resourceType: "PROJECT", resourceId: projectArchive.groups.id, summary: "Project archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const projectRestore = /^\/api\/projects\/(?<id>[0-9a-f-]+)\/restore$/.exec(url.pathname);
  if (request.method === "POST" && projectRestore?.groups?.id) {
    requirePermission(context, "projects.manage");
    projects.restore(projectRestore.groups.id, resourceOrganization(context, "resources.use"));
    audit.append({ action: "PROJECT_RESTORED", resourceType: "PROJECT", resourceId: projectRestore.groups.id, summary: "Project restored." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/targets") {
    requirePermission(context, "targets.manage");
    const parsed = targetSchema.parse(await readJson(request));
    const organizationId = resourceOrganization(context, "resources.use");
    if (parsed.projectId && !projects.get(parsed.projectId, true, organizationId)) throw new HttpError(400, "Target project is outside the selected organization.");
    validateTargetDefaults(context, parsed);
    const targetId = targets.create({ ...parsed, organizationId, createdBy: context.principal?.userId });
    audit.append({ action: "TARGET_CREATED", resourceType: "TARGET", resourceId: targetId, summary: `Target created: ${parsed.displayName}.`, metadata: { projectId: parsed.projectId, authorizationType: parsed.authorizationType } });
    sendJson(response, 201, { targetId });
    return;
  }
  const targetUpdate = /^\/api\/targets\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && targetUpdate?.groups?.id) {
    requirePermission(context, "targets.manage");
    const parsed = targetSchema.parse(await readJson(request));
    const organizationId = resourceOrganization(context, "resources.use");
    if (parsed.projectId && !projects.get(parsed.projectId, true, organizationId)) throw new HttpError(400, "Target project is outside the selected organization.");
    validateTargetDefaults(context, parsed);
    targets.update(targetUpdate.groups.id, { ...parsed, organizationId });
    audit.append({ action: "TARGET_UPDATED", resourceType: "TARGET", resourceId: targetUpdate.groups.id, summary: `Target updated: ${parsed.displayName}.`, metadata: { projectId: parsed.projectId, authorizationType: parsed.authorizationType } });
    sendJson(response, 200, { ok: true });
    return;
  }
  const targetArchive = /^\/api\/targets\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && targetArchive?.groups?.id) {
    requirePermission(context, "targets.manage");
    targets.archive(targetArchive.groups.id, resourceOrganization(context, "resources.use"));
    audit.append({ action: "TARGET_ARCHIVED", resourceType: "TARGET", resourceId: targetArchive.groups.id, summary: "Target archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const targetRestore = /^\/api\/targets\/(?<id>[0-9a-f-]+)\/restore$/.exec(url.pathname);
  if (request.method === "POST" && targetRestore?.groups?.id) {
    requirePermission(context, "targets.manage");
    targets.restore(targetRestore.groups.id, resourceOrganization(context, "resources.use"));
    audit.append({ action: "TARGET_RESTORED", resourceType: "TARGET", resourceId: targetRestore.groups.id, summary: "Target restored." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/configurations") {
    requirePermission(context, "configurations.manage");
    const parsed = savedConfigurationSchema.parse(await readJson(request));
    const configurationId = configurations.create({...normalizeSavedConfiguration(parsed),organizationId:resourceOrganization(context,"resources.use")});
    audit.append({ action: "CONFIGURATION_CHANGED", resourceType: "SAVED_CONFIGURATION", resourceId: configurationId, summary: `Configuration created: ${parsed.name}.` });
    sendJson(response, 201, { configurationId });
    return;
  }
  const configUpdate = /^\/api\/configurations\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && configUpdate?.groups?.id) {
    requirePermission(context, "configurations.manage");
    const parsed = savedConfigurationSchema.parse(await readJson(request));
    configurations.update(configUpdate.groups.id, normalizeSavedConfiguration(parsed),resourceOrganization(context,"resources.use"));
    audit.append({ action: "CONFIGURATION_CHANGED", resourceType: "SAVED_CONFIGURATION", resourceId: configUpdate.groups.id, summary: `Configuration updated: ${parsed.name}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const configArchive = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && configArchive?.groups?.id) {
    requirePermission(context, "configurations.manage");
    configurations.archive(configArchive.groups.id,resourceOrganization(context,"resources.use"));
    audit.append({ action: "CONFIGURATION_ARCHIVED", resourceType: "SAVED_CONFIGURATION", resourceId: configArchive.groups.id, summary: "Configuration archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const configRestore = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/restore$/.exec(url.pathname);
  if (request.method === "POST" && configRestore?.groups?.id) {
    requirePermission(context, "configurations.manage");
    configurations.restore(configRestore.groups.id,resourceOrganization(context,"resources.use"));
    audit.append({ action: "CONFIGURATION_RESTORED", resourceType: "SAVED_CONFIGURATION", resourceId: configRestore.groups.id, summary: "Configuration restored." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const configClone = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/clone$/.exec(url.pathname);
  if (request.method === "POST" && configClone?.groups?.id) {
    requirePermission(context, "configurations.manage");
    const body = await readJson(request) as { name?: unknown };
    const name = typeof body.name === "string" && body.name.trim() ? body.name.trim().slice(0, 160) : "Configuration copy";
    const configurationId = configurations.clone(configClone.groups.id, name,resourceOrganization(context,"resources.use"));
    audit.append({ action: "CONFIGURATION_CLONED", resourceType: "SAVED_CONFIGURATION", resourceId: configurationId, summary: `Configuration cloned: ${name}.`, metadata: { sourceId: configClone.groups.id } });
    sendJson(response, 201, { configurationId });
    return;
  }
  if (request.method === "PATCH" && url.pathname === "/api/settings") {
    requirePermission(context, "settings.manage");
    const parsed = dashboardSettingsUpdateSchema.parse(await readJson(request));
    updateSettings(context, parsed.values, parsed.expectedVersions, context.principal?.userId);
    audit.append({ actorLabel: context.principal?.userId, action: "SETTINGS_CHANGED", resourceType: "DASHBOARD_SETTINGS", summary: `Updated ${Object.keys(parsed.values).length} dashboard setting(s).`, metadata: { keys: Object.keys(parsed.values) } });
    sendJson(response, 200, { mutable: mutableSettings(context) });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/settings/reset") {
    requirePermission(context, "settings.manage");
    const body = await readJson(request) as { keys?: unknown };
    const keys = Array.isArray(body.keys) ? body.keys.filter((key): key is string => typeof key === "string") : [];
    resetSettings(context, keys);
    audit.append({ actorLabel: context.principal?.userId, action: "SETTINGS_RESET", resourceType: "DASHBOARD_SETTINGS", summary: `Reset ${keys.length || "all"} mutable setting(s).`, metadata: { keys } });
    sendJson(response, 200, { mutable: mutableSettings(context) });
    return;
  }
  const workerRestart = /^\/api\/workers\/(?<id>[0-9a-f-]+)\/restart$/.exec(url.pathname);
  if (request.method === "POST" && workerRestart?.groups?.id) {
    requirePermission(context, "workers.manage");
    context.execution.restartWorker(workerRestart.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_RESTART_REQUESTED", resourceType: "WORKER", resourceId: workerRestart.groups.id, summary: "Operator requested graceful restart of a job-scoped worker." });
    sendJson(response, 202, { ok: true });
    return;
  }
  const workerQuarantine = /^\/api\/workers\/(?<id>[0-9a-f-]+)\/quarantine$/.exec(url.pathname);
  if (request.method === "POST" && workerQuarantine?.groups?.id) {
    requirePermission(context, "workers.manage");
    const body = await readJson(request) as { reason?: unknown };
    const reason = typeof body.reason === "string" && body.reason.trim().length >= 8 ? body.reason.trim().slice(0, 500) : "Manual operator quarantine";
    context.execution.quarantineWorker(workerQuarantine.groups.id, reason);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_QUARANTINED", resourceType: "WORKER", resourceId: workerQuarantine.groups.id, summary: "Operator quarantined a worker.", metadata: { reason } });
    sendJson(response, 202, { ok: true });
    return;
  }
  const workerRelease = /^\/api\/workers\/(?<id>[0-9a-f-]+)\/release$/.exec(url.pathname);
  if (request.method === "POST" && workerRelease?.groups?.id) {
    requirePermission(context, "workers.manage");
    context.execution.releaseWorker(workerRelease.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_QUARANTINE_RELEASED", resourceType: "WORKER", resourceId: workerRelease.groups.id, summary: "Operator released an individual worker quarantine record." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/workers/fleet/quarantine") {
    requirePermission(context, "workers.manage");
    const body = await readJson(request) as { reason?: unknown };
    const reason = typeof body.reason === "string" && body.reason.trim().length >= 8 ? body.reason.trim().slice(0, 500) : "Manual operator quarantine";
    context.execution.quarantineWorkerFleet(reason);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_FLEET_QUARANTINED", resourceType: "WORKER_FLEET", summary: "Operator blocked new worker dispatch.", metadata: { reason } });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/workers/fleet/release") {
    requirePermission(context, "workers.manage");
    context.execution.releaseWorkerFleet();
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_FLEET_RELEASED", resourceType: "WORKER_FLEET", summary: "Operator released worker dispatch and reset crash-loop state." });
    sendJson(response, 200, { ok: true });
    return;
  }
  throw new HttpError(404, "API route not found.");
}
