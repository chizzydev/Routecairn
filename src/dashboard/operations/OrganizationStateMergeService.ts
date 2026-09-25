import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { CredentialProfileSecret, CredentialVault } from "../credentials/CredentialVault.js";

export interface OrganizationStateEntity {
  entityType: StateEntityType;
  entityId: string;
  originInstallationId: string;
  updatedAt: string;
  rowVersion: number;
  payloadDigest: string;
  data: Record<string, unknown>;
}

export interface OrganizationStateSnapshot {
  schemaVersion: 1;
  generatedAt: string;
  sourceInstallationId: string;
  stateDigest: string;
  entities: OrganizationStateEntity[];
  fullStateDigest?: string|undefined;
  nextCursor?: string|undefined;
}

export interface OrganizationMergeResult { applied: number; ignored: number; conflicts: number }

type StateEntityType = "project" | "target" | "scan" | "scan-plan" | "scan-module" | "scan-event" | "finding" | "finding-occurrence" | "evidence" | "finding-review" | "finding-note" | "finding-remediation" | "finding-retest" | "credential" | "configuration" | "configuration-version" | "proof-pack" | "proof-pack-finding" | "artifact" | "artifact-chunk" | "comparison" | "comparison-module" | "comparison-workflow" | "comparison-case" | "comparison-finding" | "membership";

type PrimaryEntityType="project"|"target"|"scan"|"finding"|"configuration"|"proof-pack";
const definitions: Record<PrimaryEntityType, { table: string; columns: readonly string[]; updated: string; version?: string }> = {
  project: { table: "projects", updated: "updated_at", version: "row_version", columns: ["name","description","tags_json","default_profile","default_scope_json","created_by","created_at","updated_at","archived_at","row_version"] },
  target: { table: "targets", updated: "updated_at", version: "row_version", columns: ["project_id","display_name","base_origin","description","tags_json","classification","authorization_type","authorization_summary","approved_scope_json","default_profile","created_by","created_at","updated_at","archived_at","row_version","default_configuration_id","default_credential_profile_id","default_evidence_level","default_auth_template_json","production_mutation_enabled"] },
  scan: { table: "scans", updated: "created_at", columns: ["display_sequence","source","status","target_origin","safe_target_label","profile","legacy_mode","evidence_level","created_at","queued_at","started_at","completed_at","cancelled_at","duration_ms","current_module","planned_module_count","completed_module_count","failed_module_count","blocked_module_count","finding_count","observation_count","error_summary","safe_configuration_summary","import_limitation_summary","archived_at","deleted_at","project_id","target_id","authorization_declaration"] },
  finding: { table: "findings", updated: "updated_at", version: "row_version", columns: ["fingerprint","target_identity","module","finding_category","safe_endpoint_identity","safe_authorization_boundary_identity","canonical_title","current_scanner_severity","current_scanner_confidence","human_review_status","remediation_status","first_seen_at","last_seen_at","last_occurrence_scan_id","occurrence_count","duplicate_of_finding_id","assignee_label","archived_at","project_id","target_id","http_method","canonical_description","effective_severity","severity_override_reason","remediation_state_v2","target_fix_date","review_started_at","retest_state","retest_at","verification_reason","verification_owner_override","new_occurrence_kind","proof_readiness","row_version","created_at","updated_at"] },
  configuration: { table:"saved_scan_configurations",updated:"updated_at",version:"row_version",columns:["name","description","target_template","profile","modules_json","limits_json","scope_settings_json","browser_policy_settings_json","evidence_level","non_secret_controlled_workflow_refs_json","created_at","updated_at","archived_at","row_version","current_version"] },
  "proof-pack":{table:"proof_packs",updated:"generated_at",columns:["safe_title","description","status","version","created_at","generated_at","source_scan_ids_json","scope_summary","included_finding_count","output_artifact_ids_json","generation_error","immutable_snapshot_metadata_json"]}
};

const credentialColumns = ["name","description","safe_alias","enabled","project_id","target_id","safe_identity_summary_json","expires_at","created_by_user_id","created_at","updated_at","deleted_at"] as const;
const artifactColumns=["scan_id","proof_pack_id","artifact_type","safe_display_name","size","content_type","scoped_or_full_safe_hash","created_at","retention_state","missing_file_flag"] as const;
const dependentDefinitions:Record<Exclude<StateEntityType,"project"|"target"|"scan"|"finding"|"credential"|"configuration"|"proof-pack"|"artifact"|"artifact-chunk"|"membership">,{table:string;columns:readonly string[];updated:string;query:string}>={
  comparison:{table:"scan_comparisons",updated:"completed_at",columns:["project_id","target_id","older_scan_id","newer_scan_id","state","compatibility_state","source_quality_older","source_quality_newer","created_by_user_id","created_at","completed_at","engine_version","coverage_algorithm_version","finding_fingerprint_version","older_plan_fingerprint","newer_plan_fingerprint","summary_json","coverage_summary_json","warning_json","failure_category","supersedes_comparison_id","deleted_at"],query:"SELECT c.* FROM scan_comparisons c JOIN scans s ON s.id=c.older_scan_id WHERE s.organization_id=? ORDER BY c.id"},
  "comparison-module":{table:"scan_comparison_module_coverage",updated:"",columns:["comparison_id","module_id","older_state","newer_state","comparable","reason_code","safe_reason"],query:"SELECT c.comparison_id||':'||c.module_id AS id,c.* FROM scan_comparison_module_coverage c JOIN scan_comparisons p ON p.id=c.comparison_id JOIN scans s ON s.id=p.older_scan_id WHERE s.organization_id=? ORDER BY c.comparison_id,c.module_id"},
  "comparison-workflow":{table:"scan_comparison_workflow_coverage",updated:"",columns:["comparison_id","workflow_id","older_configured","newer_configured","older_case_count","newer_case_count","matched_case_count","missing_case_count","changed_case_count","executed_matched_case_count","comparable","safe_reason"],query:"SELECT c.comparison_id||':'||c.workflow_id AS id,c.* FROM scan_comparison_workflow_coverage c JOIN scan_comparisons p ON p.id=c.comparison_id JOIN scans s ON s.id=p.older_scan_id WHERE s.organization_id=? ORDER BY c.comparison_id,c.workflow_id"},
  "comparison-case":{table:"scan_comparison_case_coverage",updated:"",columns:["comparison_id","workflow_id","safe_case_fingerprint","safe_case_alias","state","compatibility","reason_code","safe_reason","older_execution_id","newer_execution_id"],query:"SELECT c.comparison_id||':'||c.workflow_id||':'||c.safe_case_fingerprint AS id,c.* FROM scan_comparison_case_coverage c JOIN scan_comparisons p ON p.id=c.comparison_id JOIN scans s ON s.id=p.older_scan_id WHERE s.organization_id=? ORDER BY c.comparison_id,c.workflow_id,c.safe_case_fingerprint"},
  "comparison-finding":{table:"scan_comparison_findings",updated:"created_at",columns:["comparison_id","finding_id","older_occurrence_id","newer_occurrence_id","classification","coverage_state","reason_code","safe_explanation","material_changes_json","regression_flags_json","safe_evidence_delta_json","created_at"],query:"SELECT c.* FROM scan_comparison_findings c JOIN scan_comparisons p ON p.id=c.comparison_id JOIN scans s ON s.id=p.older_scan_id WHERE s.organization_id=? ORDER BY c.id"},
  "configuration-version":{table:"saved_scan_configuration_versions",updated:"created_at",columns:["configuration_id","version","snapshot_json","change_summary","created_by","created_at"],query:"SELECT c.* FROM saved_scan_configuration_versions c JOIN saved_scan_configurations p ON p.id=c.configuration_id WHERE p.organization_id=? ORDER BY c.id"},
  "proof-pack-finding":{table:"proof_pack_findings",updated:"created_at",columns:["proof_pack_id","finding_id","selected_occurrence_id","sort_order","included_evidence_ids_json","snapshot_content_json","created_at"],query:"SELECT c.proof_pack_id||':'||c.finding_id||':'||c.selected_occurrence_id AS id,c.* FROM proof_pack_findings c JOIN proof_packs p ON p.id=c.proof_pack_id WHERE p.organization_id=? ORDER BY c.proof_pack_id,c.sort_order"},
  "scan-plan":{table:"scan_plan_snapshots",updated:"created_at",columns:["scan_id","planner_version","profile","modules_json","limits_json","evidence_policy_json","browser_policy_summary_json","scope_summary_json","authentication_summary_json","controlled_workflow_summary_json","redacted_plan_json","created_at"],query:"SELECT c.* FROM scan_plan_snapshots c JOIN scans p ON p.id=c.scan_id WHERE p.organization_id=? ORDER BY c.id"},
  "scan-module":{table:"scan_module_executions",updated:"completed_at",columns:["scan_id","module_id","module_label","planned_order","status","started_at","completed_at","duration_ms","planned_request_count","executed_request_count","finding_count","observation_count","safe_failure_category","safe_failure_summary"],query:"SELECT c.* FROM scan_module_executions c JOIN scans p ON p.id=c.scan_id WHERE p.organization_id=? ORDER BY c.id"},
  "scan-event":{table:"scan_events",updated:"created_at",columns:["seq","scan_id","event_type","module_id","safe_message","safe_metadata_json","created_at"],query:"SELECT c.* FROM scan_events c JOIN scans p ON p.id=c.scan_id WHERE p.organization_id=? ORDER BY c.id"},
  "finding-occurrence":{table:"finding_occurrences",updated:"created_at",columns:["finding_id","scan_id","module","finding_category","severity","confidence","title","safe_endpoint","safe_actor_relationship","safe_tenant_or_role_boundary","safe_state_boundary","description","impact","reproduction_steps","remediation","limitations","evidence_summary","finding_source_json","created_at","project_id","target_id","source_kind","workflow_case_alias","coverage_reference_json","safe_reproduction_json"],query:"SELECT c.* FROM finding_occurrences c JOIN findings p ON p.id=c.finding_id WHERE p.organization_id=? ORDER BY c.id"},
  evidence:{table:"evidence_records",updated:"created_at",columns:["finding_occurrence_id","evidence_type","evidence_level","safe_summary","safe_structured_data_json","scoped_fingerprint","artifact_id","byte_count","retention_classification","created_at"],query:"SELECT c.* FROM evidence_records c JOIN finding_occurrences o ON o.id=c.finding_occurrence_id JOIN findings p ON p.id=o.finding_id WHERE p.organization_id=? ORDER BY c.id"},
  "finding-review":{table:"finding_reviews",updated:"created_at",columns:["finding_id","previous_review_status","new_review_status","reason","review_note","duplicate_target_finding_id","created_at","local_reviewer_label","source","user_id","correlation_id","safe_metadata_json"],query:"SELECT c.* FROM finding_reviews c JOIN findings p ON p.id=c.finding_id WHERE p.organization_id=? ORDER BY c.id"},
  "finding-note":{table:"finding_notes",updated:"updated_at",columns:["finding_id","user_id","safe_text","created_at","updated_at"],query:"SELECT c.* FROM finding_notes c JOIN findings p ON p.id=c.finding_id WHERE p.organization_id=? ORDER BY c.id"},
  "finding-remediation":{table:"finding_remediation_history",updated:"created_at",columns:["finding_id","user_id","previous_state","new_state","assignee_user_id","target_fix_date","safe_note","related_scan_id","owner_override","source","correlation_id","created_at"],query:"SELECT c.* FROM finding_remediation_history c JOIN findings p ON p.id=c.finding_id WHERE p.organization_id=? ORDER BY c.id"},
  "finding-retest":{table:"finding_retests",updated:"updated_at",columns:["finding_id","scan_id","occurrence_id","state","compatible","compatibility_reasons_json","linked_by_user_id","verified_by_user_id","verification_reason","owner_override","created_at","updated_at"],query:"SELECT c.* FROM finding_retests c JOIN findings p ON p.id=c.finding_id WHERE p.organization_id=? ORDER BY c.id"}
};
const typeOrder: Record<StateEntityType, number> = { project:0,target:1,scan:2,"scan-plan":3,"scan-module":3,"scan-event":3,finding:4,"finding-occurrence":5,evidence:6,"finding-review":6,"finding-note":6,"finding-remediation":6,"finding-retest":6,credential:2,configuration:0,"configuration-version":1,"proof-pack":10,"proof-pack-finding":11,artifact:12,"artifact-chunk":13,comparison:7,"comparison-module":8,"comparison-workflow":8,"comparison-case":8,"comparison-finding":8,membership:14 };

export class OrganizationStateMergeService {
  public constructor(private readonly database: DashboardDatabase, private readonly vault?: CredentialVault) {}

  public snapshot(organizationId: string, peerSecret: string, envelopeOrganizationId = organizationId): OrganizationStateSnapshot {
    this.assertOrganization(organizationId);
    const installationId = this.meta("installation_id");
    const entities: OrganizationStateEntity[] = [];
    for (const entityType of ["project", "target", "scan", "finding", "configuration", "proof-pack"] as const) {
      const definition = definitions[entityType];
      const rows = this.database.db.prepare(`SELECT id,${definition.columns.join(",")} FROM ${definition.table} WHERE organization_id=? ORDER BY id`).all(organizationId) as Array<Record<string, unknown>>;
      for (const row of rows) entities.push(this.localEntity(organizationId, entityType, row, definition.updated, definition.version, installationId));
    }
    for(const [entityType,definition] of Object.entries(dependentDefinitions) as Array<[keyof typeof dependentDefinitions,(typeof dependentDefinitions)[keyof typeof dependentDefinitions]]>){
      const rows=this.database.db.prepare(definition.query).all(organizationId) as Array<Record<string,unknown>>;
      for(const row of rows)entities.push(this.localDependentEntity(organizationId,entityType,row,definition,installationId));
    }
    const credentialRows = this.database.db.prepare(`SELECT id,${credentialColumns.join(",")} FROM credential_profiles WHERE organization_id=? ORDER BY id`).all(organizationId) as Array<Record<string, unknown>>;
    if (credentialRows.length && !this.vault?.status().enabled) throw new Error("CLOUD_SYNC_VAULT_REQUIRED_FOR_CREDENTIAL_STATE");
    for (const row of credentialRows) {
      const id = String(row.id); const metadata = withoutId(row);
      metadata.created_by_user_id=null;
      const exported = this.vault!.exportForSynchronization(id, organizationId);
      const digest = hash(canonical({ metadata, secret: exported.secret }));
      const provenance = this.provenance(organizationId, "credential", id, digest, String(row.updated_at), Number((exported.summary.secretVersion ?? 1)), installationId);
      entities.push({ entityType: "credential", entityId: id, ...provenance, payloadDigest: digest, data: { ...metadata, sealedMaterial: seal(exported.secret, peerSecret, envelopeOrganizationId, id) } });
    }
    const artifactTotal=this.database.db.prepare("SELECT COALESCE(SUM(CASE WHEN missing_file_flag=0 THEN size ELSE 0 END),0) AS bytes FROM artifacts WHERE organization_id=?").get(organizationId) as {bytes:number};
    if(artifactTotal.bytes>128*1024*1024)throw new Error("CLOUD_SYNC_ARTIFACT_AGGREGATE_LIMIT_EXCEEDED");
    const artifactRows=this.database.db.prepare(`SELECT id,canonical_path,${artifactColumns.join(",")} FROM artifacts a WHERE organization_id=? AND NOT EXISTS(SELECT 1 FROM cloud_sync_artifact_pending p WHERE p.organization_id=a.organization_id AND p.artifact_id=a.id) ORDER BY id`).all(organizationId) as Array<Record<string,unknown>>;
    for(const row of artifactRows)entities.push(...this.localArtifactEntities(organizationId,envelopeOrganizationId,row,peerSecret,installationId));
    const membershipRows=this.database.db.prepare(`SELECT m.user_id,m.role,m.updated_at,
      (SELECT p.issuer FROM sso_identities i JOIN sso_providers p ON p.id=i.provider_id WHERE i.user_id=m.user_id AND p.organization_id=m.organization_id ORDER BY p.issuer,i.subject LIMIT 1) AS issuer,
      (SELECT i.subject FROM sso_identities i JOIN sso_providers p ON p.id=i.provider_id WHERE i.user_id=m.user_id AND p.organization_id=m.organization_id ORDER BY p.issuer,i.subject LIMIT 1) AS subject
      FROM organization_memberships m WHERE m.organization_id=?
      AND NOT EXISTS(SELECT 1 FROM cloud_sync_membership_bindings b WHERE b.organization_id=m.organization_id AND b.local_user_id=m.user_id)
      ORDER BY m.user_id`).all(organizationId) as Array<{user_id:string;role:string;updated_at:string;issuer:string|null;subject:string|null}>;
    for(const row of membershipRows)entities.push(this.localMembershipEntity(organizationId,installationId,row.user_id,row.updated_at,{sourceUserId:row.user_id,role:row.role,active:1,issuer:row.issuer,subject:row.subject}));
    const tombstones=this.database.db.prepare(`SELECT t.user_id,t.deleted_at FROM cloud_sync_membership_tombstones t WHERE t.organization_id=?
      AND NOT EXISTS(SELECT 1 FROM cloud_sync_membership_bindings b WHERE b.organization_id=t.organization_id AND b.local_user_id=t.user_id) ORDER BY t.user_id`).all(organizationId) as Array<{user_id:string;deleted_at:string}>;
    for(const row of tombstones)entities.push(this.localMembershipEntity(organizationId,installationId,row.user_id,row.deleted_at,{sourceUserId:row.user_id,role:null,active:0,issuer:null,subject:null}));
    entities.sort((a,b)=>typeOrder[a.entityType]-typeOrder[b.entityType]||a.entityType.localeCompare(b.entityType)||a.entityId.localeCompare(b.entityId));
    const stateDigest = hash(canonical(entities.map(({ entityType,entityId,originInstallationId,updatedAt,rowVersion,payloadDigest }) => ({ entityType,entityId,originInstallationId,updatedAt,rowVersion,payloadDigest }))));
    return { schemaVersion: 1, generatedAt: nowIso(), sourceInstallationId: installationId, stateDigest, entities };
  }

  public page(snapshot:OrganizationStateSnapshot,cursor:string|null,maxBytes=12*1024*1024):OrganizationStateSnapshot{
    const entities:OrganizationStateEntity[]=[];
    let bytes=512,lastKey:string|undefined;
    for(const entity of snapshot.entities){
      const key=entityKey(entity);
      if(cursor&&key<=cursor)continue;
      const cost=Buffer.byteLength(canonical(entity))+1;
      if(entities.length>=9_000||bytes+cost>maxBytes){
        if(entities.length===0)throw new Error("CLOUD_SYNC_SINGLE_ENTITY_TOO_LARGE");
        break;
      }
      entities.push(entity);bytes+=cost;lastKey=key;
    }
    const hasMore=Boolean(lastKey&&snapshot.entities.some((entity)=>entityKey(entity)>lastKey!));
    const stateDigest=hash(canonical(entities.map(({entityType,entityId,originInstallationId,updatedAt,rowVersion,payloadDigest})=>({entityType,entityId,originInstallationId,updatedAt,rowVersion,payloadDigest}))));
    return{schemaVersion:1,generatedAt:snapshot.generatedAt,sourceInstallationId:snapshot.sourceInstallationId,stateDigest,fullStateDigest:snapshot.stateDigest,...(hasMore&&lastKey?{nextCursor:lastKey}:{}),entities};
  }

  public merge(organizationId: string, snapshot: OrganizationStateSnapshot, peerSecret: string): OrganizationMergeResult {
    validateSnapshot(snapshot);
    this.assertOrganization(organizationId);
    const expectedStateDigest = hash(canonical(snapshot.entities.map(({ entityType,entityId,originInstallationId,updatedAt,rowVersion,payloadDigest }) => ({ entityType,entityId,originInstallationId,updatedAt,rowVersion,payloadDigest }))));
    if (expectedStateDigest !== snapshot.stateDigest) throw new Error("CLOUD_SYNC_STATE_DIGEST_REJECTED");
    // Establish provenance for pre-existing local rows before considering a peer value.
    // This prevents the first inbound merge from blindly replacing an untracked local edit.
    this.snapshot(organizationId,peerSecret,organizationId);
    let applied=0,ignored=0,conflicts=0;
    const ordered=[...snapshot.entities].sort((a,b)=>typeOrder[a.entityType]-typeOrder[b.entityType]||a.entityId.localeCompare(b.entityId));
    this.database.transaction(() => {
      for (const entity of ordered) {
        try {
          const material = this.verifyEntity(organizationId, entity, peerSecret);
          if (!this.shouldApply(organizationId, entity)) { ignored+=1; continue; }
          this.assertNoTenantCollision(organizationId, entity);
          if (entity.entityType === "credential") this.applyCredential(organizationId, entity, material as CredentialProfileSecret);
          else if(entity.entityType==="artifact")this.applyArtifact(organizationId,entity,material as Buffer);
          else if(entity.entityType==="artifact-chunk")this.applyArtifactChunk(organizationId,entity,material as Buffer);
          else if(entity.entityType==="membership")this.applyMembership(organizationId,entity);
          else this.applyRow(organizationId, entity);
          this.saveVersion(organizationId,entity);
          applied+=1;
        } catch (error) {
          if (error instanceof Error && error.message === "CLOUD_SYNC_ENTITY_ID_TENANT_CONFLICT") { conflicts+=1; continue; }
          throw error;
        }
      }
    });
    return { applied, ignored, conflicts };
  }

  private localEntity(organizationId:string,entityType:PrimaryEntityType,row:Record<string,unknown>,updatedColumn:string,versionColumn:string|undefined,installationId:string):OrganizationStateEntity {
    const entityId=String(row.id),data=withoutId(row);
    if(entityType==="project"||entityType==="target")data.created_by=null;
    if(entityType==="finding"&&typeof data.fingerprint==="string"&&data.fingerprint.startsWith(`${organizationId}:`))data.fingerprint=data.fingerprint.slice(organizationId.length+1);
    const digest=hash(canonical(data));
    const provenance=this.provenance(organizationId,entityType,entityId,digest,String(row[updatedColumn]??nowIso()),Number(versionColumn?row[versionColumn]??1:1),installationId);
    return {entityType,entityId,...provenance,payloadDigest:digest,data};
  }

  private localDependentEntity(organizationId:string,entityType:keyof typeof dependentDefinitions,row:Record<string,unknown>,definition:(typeof dependentDefinitions)[keyof typeof dependentDefinitions],installationId:string):OrganizationStateEntity{
    const rawId=String(row.id),entityId=(["proof-pack-finding","comparison-module","comparison-workflow","comparison-case"] as string[]).includes(entityType)?stableUuid(rawId):rawId,data=withoutId(row);for(const key of ["user_id","assignee_user_id","linked_by_user_id","verified_by_user_id","artifact_id","created_by","created_by_user_id","supersedes_comparison_id","older_execution_id","newer_execution_id"])if(key in data)data[key]=null;const digest=hash(canonical(data));const provenance=this.provenance(organizationId,entityType,entityId,digest,String(row[definition.updated]??row.created_at??nowIso()),1,installationId);return{entityType,entityId,...provenance,payloadDigest:digest,data};
  }

  private localArtifactEntities(organizationId:string,envelopeOrganizationId:string,row:Record<string,unknown>,peerSecret:string,installationId:string):OrganizationStateEntity[]{
    const entityId=String(row.id),metadata=Object.fromEntries(artifactColumns.map((column)=>[column,row[column]??null]));
    const missing=Number(row.missing_file_flag)===1;
    const bytes=missing?undefined:this.readPortableArtifact(String(row.canonical_path),Number(row.size));
    const contentDigest=bytes?createHash("sha256").update(bytes).digest("hex"):null;
    const chunkCount=bytes&&bytes.length>8*1024*1024?Math.ceil(bytes.length/(4*1024*1024)):0;
    const digest=hash(canonical({metadata,contentDigest,chunkCount}));
    const provenance=this.provenance(organizationId,"artifact",entityId,digest,String(row.created_at),1,installationId);
    const artifact:OrganizationStateEntity={entityType:"artifact",entityId,...provenance,payloadDigest:digest,data:{...metadata,contentDigest,chunkCount,sealedContent:bytes&&chunkCount===0?sealBytes(bytes,peerSecret,envelopeOrganizationId,entityId):null}};
    const chunks:OrganizationStateEntity[]=[];
    if(bytes&&chunkCount>0)for(let index=0;index<chunkCount;index++){
      const part=bytes.subarray(index*4*1024*1024,Math.min((index+1)*4*1024*1024,bytes.length));
      const chunkId=stableUuid(`${entityId}:${contentDigest}:${index}`),chunkDigest=createHash("sha256").update(part).digest("hex");
      const chunkMetadata={artifactId:entityId,index,chunkCount,contentDigest,chunkDigest};
      const payloadDigest=hash(canonical(chunkMetadata));
      const chunkProvenance=this.provenance(organizationId,"artifact-chunk",chunkId,payloadDigest,String(row.created_at),1,installationId);
      chunks.push({entityType:"artifact-chunk",entityId:chunkId,...chunkProvenance,payloadDigest,data:{...chunkMetadata,sealedContent:sealBytes(part,peerSecret,envelopeOrganizationId,chunkId)}});
    }
    return[artifact,...chunks];
  }

  private localMembershipEntity(organizationId:string,installationId:string,userId:string,updatedAt:string,data:Record<string,unknown>):OrganizationStateEntity{
    const entityId=stableUuid(`${installationId}:${userId}`),digest=hash(canonical(data));
    const provenance=this.provenance(organizationId,"membership",entityId,digest,updatedAt,1,installationId);
    return{entityType:"membership",entityId,...provenance,payloadDigest:digest,data};
  }

  private provenance(organizationId:string,entityType:StateEntityType,entityId:string,payloadDigest:string,updatedAt:string,rowVersion:number,installationId:string):Pick<OrganizationStateEntity,"originInstallationId"|"updatedAt"|"rowVersion"> {
    const prior=this.database.db.prepare("SELECT origin_installation_id,source_updated_at,source_row_version,payload_digest FROM cloud_sync_entity_versions WHERE organization_id=? AND entity_type=? AND entity_id=?").get(organizationId,entityType,entityId) as {origin_installation_id:string;source_updated_at:string;source_row_version:number;payload_digest:string}|undefined;
    if(prior?.payload_digest===payloadDigest)return{originInstallationId:prior.origin_installation_id,updatedAt:prior.source_updated_at,rowVersion:prior.source_row_version};
    // Some dashboard rows (notably scans and append-only history) have no
    // updated_at/row_version. A changed payload is nevertheless a new local
    // revision and must outrank the revision we last accepted from a peer.
    const sourceTime = Date.parse(validDate(updatedAt));
    const priorTime = prior ? Date.parse(prior.source_updated_at) : 0;
    const revisionTime = prior
      ? Math.max(Date.now(), sourceTime, priorTime + 1)
      : sourceTime;
    const current={
      originInstallationId:installationId,
      updatedAt:new Date(revisionTime).toISOString(),
      rowVersion:Math.max(1,Math.trunc(rowVersion)||1,prior ? prior.source_row_version+1 : 1)
    };
    this.database.db.prepare(`INSERT INTO cloud_sync_entity_versions (organization_id,entity_type,entity_id,origin_installation_id,source_updated_at,source_row_version,payload_digest,applied_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,entity_type,entity_id) DO UPDATE SET origin_installation_id=excluded.origin_installation_id,source_updated_at=excluded.source_updated_at,source_row_version=excluded.source_row_version,payload_digest=excluded.payload_digest,applied_at=excluded.applied_at`).run(organizationId,entityType,entityId,current.originInstallationId,current.updatedAt,current.rowVersion,payloadDigest,nowIso());
    return current;
  }

  private verifyEntity(organizationId:string,entity:OrganizationStateEntity,peerSecret:string):CredentialProfileSecret|Buffer|undefined {
    if(!definitions[entity.entityType as keyof typeof definitions]&&!dependentDefinitions[entity.entityType as keyof typeof dependentDefinitions]&&entity.entityType!=="credential"&&entity.entityType!=="artifact"&&entity.entityType!=="artifact-chunk"&&entity.entityType!=="membership")throw new Error("CLOUD_SYNC_STATE_TYPE_REJECTED");
    if(!/^(?:[0-9a-f-]{36}|[0-9a-f]{32})$/i.test(entity.entityId)||!/^[0-9a-f-]{36}$/i.test(entity.originInstallationId))throw new Error("CLOUD_SYNC_STATE_ID_REJECTED");
    validDate(entity.updatedAt); if(!Number.isInteger(entity.rowVersion)||entity.rowVersion<1)throw new Error("CLOUD_SYNC_STATE_VERSION_REJECTED");
    if(entity.entityType==="credential"){
      if(!this.vault?.status().enabled)throw new Error("CLOUD_SYNC_VAULT_REQUIRED_FOR_CREDENTIAL_STATE");
      const {sealedMaterial,...metadata}=entity.data;if(typeof sealedMaterial!=="string")throw new Error("CLOUD_SYNC_CREDENTIAL_ENVELOPE_REJECTED");
      const secret=unseal(sealedMaterial,peerSecret,organizationId,entity.entityId);
      if(hash(canonical({metadata,secret}))!==entity.payloadDigest)throw new Error("CLOUD_SYNC_STATE_ENTITY_DIGEST_REJECTED");
      return secret;
    }
    if(entity.entityType==="artifact"){
      const {sealedContent,contentDigest,chunkCount,...metadata}=entity.data;
      const allowed=new Set<string>(artifactColumns);for(const field of Object.keys(metadata))if(!allowed.has(field))throw new Error("CLOUD_SYNC_STATE_FIELD_REJECTED");
      if(typeof metadata.safe_display_name!=="string"||metadata.safe_display_name.length>200||/[\x00-\x1f\\/]/.test(metadata.safe_display_name)||
        typeof metadata.content_type!=="string"||metadata.content_type.length>200||/[\x00-\x1f]/.test(metadata.content_type)||
        typeof metadata.size!=="number"||!Number.isSafeInteger(metadata.size)||metadata.size<0||metadata.size>128*1024*1024||typeof metadata.missing_file_flag!=="number"||![0,1].includes(metadata.missing_file_flag)||
        !Number.isInteger(chunkCount)||Number(chunkCount)<0||Number(chunkCount)>32)throw new Error("CLOUD_SYNC_ARTIFACT_METADATA_REJECTED");
      if(hash(canonical({metadata,contentDigest,chunkCount}))!==entity.payloadDigest)throw new Error("CLOUD_SYNC_STATE_ENTITY_DIGEST_REJECTED");
      if(Number(metadata.missing_file_flag)===1){if(sealedContent!==null||contentDigest!==null||chunkCount!==0)throw new Error("CLOUD_SYNC_ARTIFACT_METADATA_REJECTED");return Buffer.alloc(0);}
      if(Number(chunkCount)>0&&sealedContent===null&&typeof contentDigest==="string"&&chunkCount===Math.ceil(Number(metadata.size)/(4*1024*1024)))return Buffer.alloc(0);
      if(typeof sealedContent!=="string"||typeof contentDigest!=="string")throw new Error("CLOUD_SYNC_ARTIFACT_ENVELOPE_REJECTED");
      const bytes=unsealBytes(sealedContent,peerSecret,organizationId,entity.entityId);
      if(bytes.length!==Number(metadata.size)||createHash("sha256").update(bytes).digest("hex")!==contentDigest)throw new Error("CLOUD_SYNC_ARTIFACT_DIGEST_REJECTED");
      return bytes;
    }
    if(entity.entityType==="artifact-chunk"){
      const {sealedContent,...metadata}=entity.data;
      if(Object.keys(metadata).sort().join(",")!=="artifactId,chunkCount,chunkDigest,contentDigest,index"||
        typeof metadata.artifactId!=="string"||!/^[0-9a-f-]{36}$/i.test(metadata.artifactId)||
        typeof metadata.contentDigest!=="string"||!/^[a-f0-9]{64}$/.test(metadata.contentDigest)||
        typeof metadata.chunkDigest!=="string"||!/^[a-f0-9]{64}$/.test(metadata.chunkDigest)||
        !Number.isInteger(metadata.index)||!Number.isInteger(metadata.chunkCount)||Number(metadata.chunkCount)<1||Number(metadata.chunkCount)>32||Number(metadata.index)<0||Number(metadata.index)>=Number(metadata.chunkCount)||
        entity.entityId!==stableUuid(`${metadata.artifactId}:${metadata.contentDigest}:${metadata.index}`)||hash(canonical(metadata))!==entity.payloadDigest||typeof sealedContent!=="string")throw new Error("CLOUD_SYNC_ARTIFACT_CHUNK_REJECTED");
      const bytes=unsealBytes(sealedContent,peerSecret,organizationId,entity.entityId);
      if(bytes.length>4*1024*1024||createHash("sha256").update(bytes).digest("hex")!==metadata.chunkDigest)throw new Error("CLOUD_SYNC_ARTIFACT_CHUNK_DIGEST_REJECTED");
      return bytes;
    }
    if(entity.entityType==="membership"){
      const d=entity.data;
      if(Object.keys(d).sort().join(",")!=="active,issuer,role,sourceUserId,subject"||typeof d.sourceUserId!=="string"||!/^[0-9a-f-]{36}$/i.test(d.sourceUserId)||entity.entityId!==stableUuid(`${entity.originInstallationId}:${d.sourceUserId}`)||typeof d.active!=="number"||![0,1].includes(d.active)||
        (d.active===1&&!(["OWNER","ADMIN","ANALYST","VIEWER"].includes(String(d.role))))||
        (d.issuer!==null&&(typeof d.issuer!=="string"||d.issuer.length>1000))||(d.subject!==null&&(typeof d.subject!=="string"||d.subject.length>1000))||
        hash(canonical(d))!==entity.payloadDigest)throw new Error("CLOUD_SYNC_MEMBERSHIP_REJECTED");
      return undefined;
    }
    if(hash(canonical(entity.data))!==entity.payloadDigest)throw new Error("CLOUD_SYNC_STATE_ENTITY_DIGEST_REJECTED");
    const definition=definitions[entity.entityType as keyof typeof definitions]??dependentDefinitions[entity.entityType as keyof typeof dependentDefinitions];const allowed=new Set(definition.columns);for(const key of Object.keys(entity.data))if(!allowed.has(key))throw new Error("CLOUD_SYNC_STATE_FIELD_REJECTED");
    return undefined;
  }

  private shouldApply(organizationId:string,entity:OrganizationStateEntity):boolean {
    const current=this.database.db.prepare("SELECT source_updated_at,source_row_version,origin_installation_id,payload_digest FROM cloud_sync_entity_versions WHERE organization_id=? AND entity_type=? AND entity_id=?").get(organizationId,entity.entityType,entity.entityId) as {source_updated_at:string;source_row_version:number;origin_installation_id:string;payload_digest:string}|undefined;
    if(!current)return true;if(current.payload_digest===entity.payloadDigest)return false;
    return compareVersion(entity,current)>0;
  }

  private assertNoTenantCollision(organizationId:string,entity:OrganizationStateEntity):void {
    if(entity.entityType==="membership"||entity.entityType==="artifact-chunk")return;
    const table=entity.entityType==="credential"?"credential_profiles":entity.entityType==="artifact"?"artifacts":(definitions[entity.entityType as keyof typeof definitions]??dependentDefinitions[entity.entityType as keyof typeof dependentDefinitions]).table;
    if(entity.entityType==="proof-pack-finding"){
      const d=entity.data;
      const actual=(this.database.db.prepare("SELECT p.organization_id FROM proof_pack_findings c JOIN proof_packs p ON p.id=c.proof_pack_id WHERE c.proof_pack_id=? AND c.finding_id=? AND c.selected_occurrence_id=?").get(d.proof_pack_id,d.finding_id,d.selected_occurrence_id) as {organization_id:string}|undefined)?.organization_id;
      if(actual&&actual!==organizationId)throw new Error("CLOUD_SYNC_ENTITY_ID_TENANT_CONFLICT");return;
    }
    if(entity.entityType.startsWith("comparison-")&&entity.entityType!=="comparison-finding"){
      const parent=(this.database.db.prepare("SELECT s.organization_id FROM scan_comparisons c JOIN scans s ON s.id=c.older_scan_id WHERE c.id=?").get(entity.data.comparison_id) as {organization_id:string}|undefined)?.organization_id;
      if(parent&&parent!==organizationId)throw new Error("CLOUD_SYNC_ENTITY_ID_TENANT_CONFLICT");return;
    }
    if(entity.entityType in dependentDefinitions){const actual=this.dependentOrganization(entity.entityType as keyof typeof dependentDefinitions,entity.entityId);if(actual&&actual!==organizationId)throw new Error("CLOUD_SYNC_ENTITY_ID_TENANT_CONFLICT");return;}
    const row=this.database.db.prepare(`SELECT organization_id FROM ${table} WHERE id=?`).get(entity.entityId) as {organization_id:string}|undefined;
    if(row&&row.organization_id!==organizationId)throw new Error("CLOUD_SYNC_ENTITY_ID_TENANT_CONFLICT");
  }

  private dependentOrganization(entityType:keyof typeof dependentDefinitions,id:string):string|undefined{
    const queries:Record<keyof typeof dependentDefinitions,string>={
      "scan-plan":"SELECT p.organization_id FROM scan_plan_snapshots c JOIN scans p ON p.id=c.scan_id WHERE c.id=?",
      "scan-module":"SELECT p.organization_id FROM scan_module_executions c JOIN scans p ON p.id=c.scan_id WHERE c.id=?",
      "scan-event":"SELECT p.organization_id FROM scan_events c JOIN scans p ON p.id=c.scan_id WHERE c.id=?",
      "finding-occurrence":"SELECT p.organization_id FROM finding_occurrences c JOIN findings p ON p.id=c.finding_id WHERE c.id=?",
      evidence:"SELECT p.organization_id FROM evidence_records c JOIN finding_occurrences o ON o.id=c.finding_occurrence_id JOIN findings p ON p.id=o.finding_id WHERE c.id=?",
      "finding-review":"SELECT p.organization_id FROM finding_reviews c JOIN findings p ON p.id=c.finding_id WHERE c.id=?",
      "finding-note":"SELECT p.organization_id FROM finding_notes c JOIN findings p ON p.id=c.finding_id WHERE c.id=?",
      "finding-remediation":"SELECT p.organization_id FROM finding_remediation_history c JOIN findings p ON p.id=c.finding_id WHERE c.id=?",
      "finding-retest":"SELECT p.organization_id FROM finding_retests c JOIN findings p ON p.id=c.finding_id WHERE c.id=?"
      ,"configuration-version":"SELECT p.organization_id FROM saved_scan_configuration_versions c JOIN saved_scan_configurations p ON p.id=c.configuration_id WHERE c.id=?"
      ,"proof-pack-finding":"SELECT NULL AS organization_id WHERE 0"
      ,comparison:"SELECT s.organization_id FROM scan_comparisons c JOIN scans s ON s.id=c.older_scan_id WHERE c.id=?"
      ,"comparison-module":"SELECT NULL AS organization_id WHERE 0"
      ,"comparison-workflow":"SELECT NULL AS organization_id WHERE 0"
      ,"comparison-case":"SELECT NULL AS organization_id WHERE 0"
      ,"comparison-finding":"SELECT s.organization_id FROM scan_comparison_findings c JOIN scan_comparisons p ON p.id=c.comparison_id JOIN scans s ON s.id=p.older_scan_id WHERE c.id=?"
    };return(this.database.db.prepare(queries[entityType]).get(id) as {organization_id:string}|undefined)?.organization_id;
  }

  private applyRow(organizationId:string,entity:Exclude<OrganizationStateEntity,{entityType:"credential"}>):void {
    const compositeKeys:Partial<Record<StateEntityType,readonly string[]>>={"comparison-module":["comparison_id","module_id"],"comparison-workflow":["comparison_id","workflow_id"],"comparison-case":["comparison_id","workflow_id","safe_case_fingerprint"]};
    const keys=compositeKeys[entity.entityType];
    if(keys){
      const definition=dependentDefinitions[entity.entityType as keyof typeof dependentDefinitions],data={...entity.data};
      for(const key of ["older_execution_id","newer_execution_id"])if(key in data)data[key]=null;
      const parent=this.database.db.prepare("SELECT s.organization_id FROM scan_comparisons c JOIN scans s ON s.id=c.older_scan_id WHERE c.id=?").get(data.comparison_id) as {organization_id:string}|undefined;
      if(parent?.organization_id!==organizationId)throw new Error("CLOUD_SYNC_COMPARISON_PARENT_MISMATCH");
      const columns=definition.columns.filter((column)=>Object.hasOwn(data,column));
      this.database.db.prepare(`INSERT INTO ${definition.table} (${columns.join(",")}) VALUES (${columns.map(()=>"?").join(",")}) ON CONFLICT(${keys.join(",")}) DO UPDATE SET ${columns.filter((column)=>!keys.includes(column)).map((column)=>`${column}=excluded.${column}`).join(",")}`).run(...columns.map((column)=>data[column]??null) as Array<string|number|null>);
      return;
    }
    if(entity.entityType==="proof-pack-finding"){
      const d=entity.data;
      this.database.db.prepare(`INSERT INTO proof_pack_findings (proof_pack_id,finding_id,selected_occurrence_id,sort_order,included_evidence_ids_json,snapshot_content_json,created_at)
        VALUES (?,?,?,?,?,?,?) ON CONFLICT(proof_pack_id,finding_id,selected_occurrence_id) DO UPDATE SET sort_order=excluded.sort_order,included_evidence_ids_json=excluded.included_evidence_ids_json,snapshot_content_json=excluded.snapshot_content_json`)
        .run(d.proof_pack_id,d.finding_id,d.selected_occurrence_id,d.sort_order,d.included_evidence_ids_json,d.snapshot_content_json,d.created_at);
      return;
    }
    const dependent=dependentDefinitions[entity.entityType as keyof typeof dependentDefinitions],definition=definitions[entity.entityType as keyof typeof definitions]??dependent;
    const data={...entity.data};
    if(entity.entityType==="proof-pack"){
      let scanIds:unknown;
      try{scanIds=JSON.parse(String(data.source_scan_ids_json));}catch{throw new Error("CLOUD_SYNC_PROOF_PACK_SCAN_SET_REJECTED");}
      if(!Array.isArray(scanIds)||scanIds.some((id)=>typeof id!=="string"||!(this.database.db.prepare("SELECT 1 FROM scans WHERE id=? AND organization_id=?").get(id,organizationId))))throw new Error("CLOUD_SYNC_PROOF_PACK_SCAN_SET_REJECTED");
    }
    if(entity.entityType==="comparison"){
      for(const field of ["older_scan_id","newer_scan_id"]){if(!this.database.db.prepare("SELECT 1 FROM scans WHERE id=? AND organization_id=?").get(data[field],organizationId))throw new Error("CLOUD_SYNC_COMPARISON_SCAN_MISMATCH");}
      for(const [field,table] of [["project_id","projects"],["target_id","targets"]] as const)if(data[field]&&!this.database.db.prepare(`SELECT 1 FROM ${table} WHERE id=? AND organization_id=?`).get(data[field],organizationId))throw new Error("CLOUD_SYNC_COMPARISON_RESOURCE_MISMATCH");
    }
    if(entity.entityType==="project"||entity.entityType==="target")data.created_by=null;
    if(entity.entityType==="finding"){
      for(const key of ["duplicate_of_finding_id","first_scan_id","latest_occurrence_id","severity_override_user_id","assignee_user_id","assigned_by_user_id","reviewer_user_id","retest_scan_id","retest_occurrence_id","verified_by_user_id"])delete data[key];
      const fingerprint=String(data.fingerprint??"");data.fingerprint=fingerprint.startsWith(`${organizationId}:`)?fingerprint:`${organizationId}:${fingerprint}`;
    }
    if(dependent)for(const key of ["user_id","assignee_user_id","linked_by_user_id","verified_by_user_id","artifact_id","created_by","created_by_user_id","supersedes_comparison_id","older_execution_id","newer_execution_id"])if(key in data)data[key]=null;
    const columns=definition.columns.filter((column)=>Object.hasOwn(data,column));
    const insert=["id",...(dependent?[]:["organization_id"]),...columns],values=[entity.entityId,...(dependent?[]:[organizationId]),...columns.map((column)=>data[column]??null)];
    const updates=columns.filter((column)=>column!=="created_at"&&column!=="created_by"&&column!=="created_by_user_id").map((column)=>`${column}=excluded.${column}`).join(",");
    this.database.db.prepare(`INSERT INTO ${definition.table} (${insert.join(",")}) VALUES (${insert.map(()=>"?").join(",")}) ON CONFLICT(id) DO UPDATE SET ${updates}${dependent?"":",organization_id=excluded.organization_id"}`).run(...values as Array<string|number|null>);
  }

  private applyArtifact(organizationId:string,entity:OrganizationStateEntity,bytes:Buffer):void{
    const d=entity.data;
    for(const [kind,id] of [["scan",d.scan_id],["proof-pack",d.proof_pack_id]] as const){
      if(id===null||id===undefined)continue;
      const table=kind==="scan"?"scans":"proof_packs";
      if(!this.database.db.prepare(`SELECT 1 FROM ${table} WHERE id=? AND organization_id=?`).get(id,organizationId))throw new Error("CLOUD_SYNC_ARTIFACT_PARENT_MISMATCH");
    }
    const digest=typeof d.contentDigest==="string"?d.contentDigest:"missing";
    const destination=resolve(dirname(this.database.databasePath),"artifacts","cloud-sync",organizationId,`${entity.entityId}-${digest}`);
    const chunked=Number(d.chunkCount)>0;
    if(existsSync(destination)&&digest!=="missing"&&createHash("sha256").update(this.readPortableArtifact(destination,Number(d.size))).digest("hex")!==digest)throw new Error("CLOUD_SYNC_ARTIFACT_LOCAL_DIGEST_REJECTED");
    if(Number(d.missing_file_flag)!==1&&!chunked){
      mkdirSync(dirname(destination),{recursive:true});
      if(!existsSync(destination)){
        const temporary=`${destination}.${randomBytes(8).toString("hex")}.tmp`;
        writeFileSync(temporary,bytes,{flag:"wx"});renameSync(temporary,destination);
      }
    }
    const columns=["id","organization_id","canonical_path",...artifactColumns],values=[entity.entityId,organizationId,destination,...artifactColumns.map((column)=>column==="missing_file_flag"&&chunked&&!existsSync(destination)?1:d[column]??null)];
    const updates=["canonical_path",...artifactColumns].map((column)=>`${column}=excluded.${column}`).join(",");
    this.database.db.prepare(`INSERT INTO artifacts (${columns.join(",")}) VALUES (${columns.map(()=>"?").join(",")}) ON CONFLICT(id) DO UPDATE SET ${updates}`).run(...values as Array<string|number|null>);
    if(chunked&&!existsSync(destination)){
      this.database.db.prepare(`INSERT INTO cloud_sync_artifact_pending (organization_id,artifact_id,content_digest,expected_size,chunk_count,created_at) VALUES (?,?,?,?,?,?)
        ON CONFLICT(organization_id,artifact_id) DO UPDATE SET content_digest=excluded.content_digest,expected_size=excluded.expected_size,chunk_count=excluded.chunk_count,created_at=excluded.created_at`).run(organizationId,entity.entityId,digest,d.size,d.chunkCount,nowIso());
      this.database.db.prepare("DELETE FROM cloud_sync_artifact_chunks WHERE organization_id=? AND artifact_id=? AND content_digest<>?").run(organizationId,entity.entityId,digest);
    }else this.database.db.prepare("DELETE FROM cloud_sync_artifact_pending WHERE organization_id=? AND artifact_id=?").run(organizationId,entity.entityId);
  }

  private applyArtifactChunk(organizationId:string,entity:OrganizationStateEntity,bytes:Buffer):void{
    const d=entity.data;
    const pending=this.database.db.prepare("SELECT content_digest,expected_size,chunk_count FROM cloud_sync_artifact_pending WHERE organization_id=? AND artifact_id=?").get(organizationId,d.artifactId) as {content_digest:string;expected_size:number;chunk_count:number}|undefined;
    if(!pending){
      const existing=this.database.db.prepare("SELECT missing_file_flag FROM artifacts WHERE id=? AND organization_id=?").get(d.artifactId,organizationId) as {missing_file_flag:number}|undefined;
      if(existing?.missing_file_flag===0)return;
      throw new Error("CLOUD_SYNC_ARTIFACT_CHUNK_PARENT_MISSING");
    }
    if(pending.content_digest!==d.contentDigest||pending.chunk_count!==d.chunkCount)throw new Error("CLOUD_SYNC_ARTIFACT_CHUNK_SET_MISMATCH");
    this.database.db.prepare(`INSERT INTO cloud_sync_artifact_chunks (organization_id,artifact_id,content_digest,chunk_index,chunk_digest,content) VALUES (?,?,?,?,?,?)
      ON CONFLICT(organization_id,artifact_id,content_digest,chunk_index) DO UPDATE SET chunk_digest=excluded.chunk_digest,content=excluded.content`).run(organizationId,d.artifactId,d.contentDigest,d.index,d.chunkDigest,bytes);
    const rows=this.database.db.prepare("SELECT chunk_index,content FROM cloud_sync_artifact_chunks WHERE organization_id=? AND artifact_id=? AND content_digest=? ORDER BY chunk_index").all(organizationId,d.artifactId,d.contentDigest) as Array<{chunk_index:number;content:Buffer}>;
    if(rows.length!==pending.chunk_count)return;
    if(rows.some((row,index)=>row.chunk_index!==index))throw new Error("CLOUD_SYNC_ARTIFACT_CHUNK_SEQUENCE_REJECTED");
    const content=Buffer.concat(rows.map((row)=>row.content));
    if(content.length!==pending.expected_size||createHash("sha256").update(content).digest("hex")!==pending.content_digest)throw new Error("CLOUD_SYNC_ARTIFACT_ASSEMBLY_REJECTED");
    const destination=resolve(dirname(this.database.databasePath),"artifacts","cloud-sync",organizationId,`${d.artifactId}-${pending.content_digest}`);
    mkdirSync(dirname(destination),{recursive:true});
    if(!existsSync(destination)){const temporary=`${destination}.${randomBytes(8).toString("hex")}.tmp`;writeFileSync(temporary,content,{flag:"wx"});renameSync(temporary,destination);}
    if(createHash("sha256").update(this.readPortableArtifact(destination,pending.expected_size)).digest("hex")!==pending.content_digest)throw new Error("CLOUD_SYNC_ARTIFACT_LOCAL_DIGEST_REJECTED");
    this.database.db.prepare("UPDATE artifacts SET canonical_path=?,missing_file_flag=0 WHERE id=? AND organization_id=?").run(destination,d.artifactId,organizationId);
    this.database.db.prepare("DELETE FROM cloud_sync_artifact_pending WHERE organization_id=? AND artifact_id=?").run(organizationId,d.artifactId);
    this.database.db.prepare("DELETE FROM cloud_sync_artifact_chunks WHERE organization_id=? AND artifact_id=? AND content_digest=?").run(organizationId,d.artifactId,d.contentDigest);
  }

  private applyMembership(organizationId:string,entity:OrganizationStateEntity):void{
    const d=entity.data,sourceUserId=String(d.sourceUserId),origin=entity.originInstallationId,role=String(d.role),active=Number(d.active)===1;
    const prior=this.database.db.prepare("SELECT local_user_id,role,status FROM cloud_sync_membership_bindings WHERE organization_id=? AND origin_installation_id=? AND source_user_id=?").get(organizationId,origin,sourceUserId) as {local_user_id:string|null;role:string;status:string}|undefined;
    let localUserId=prior?.local_user_id??null,status="PENDING";
    if(active&&!localUserId&&typeof d.issuer==="string"&&typeof d.subject==="string"){
      const match=this.database.db.prepare(`SELECT i.user_id FROM sso_identities i JOIN sso_providers p ON p.id=i.provider_id JOIN dashboard_users u ON u.id=i.user_id
        WHERE p.organization_id=? AND p.issuer=? AND i.subject=? AND u.enabled=1 LIMIT 1`).get(organizationId,d.issuer,d.subject) as {user_id:string}|undefined;
      localUserId=match?.user_id??null;
    }
    if(active&&localUserId){
      const current=this.database.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(organizationId,localUserId) as {role:string}|undefined;
      const owned=prior?.status==="BOUND"&&prior.local_user_id===localUserId;
      if(current&&current.role!==role&&(!owned||current.role!==prior.role))status="CONFLICT";
      else if(current?.role==="OWNER"&&role!=="OWNER"&&this.ownerCount(organizationId)<=1)status="CONFLICT";
      else{
        this.database.db.prepare(`INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?)
          ON CONFLICT(organization_id,user_id) DO UPDATE SET role=excluded.role,updated_at=excluded.updated_at`).run(organizationId,localUserId,role,`cloud-sync:${origin}`,nowIso(),nowIso());
        status="BOUND";
      }
    }else if(!active){
      status="REMOVED";
      if(prior?.status==="BOUND"&&localUserId){
        const current=this.database.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(organizationId,localUserId) as {role:string}|undefined;
        if(current&&current.role===prior.role&&!(current.role==="OWNER"&&this.ownerCount(organizationId)<=1))
          this.database.db.prepare("DELETE FROM organization_memberships WHERE organization_id=? AND user_id=?").run(organizationId,localUserId);
        else if(current)status="CONFLICT";
      }
    }
    this.database.db.prepare(`INSERT INTO cloud_sync_membership_bindings (organization_id,origin_installation_id,source_user_id,local_user_id,role,active,status,issuer,subject,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,origin_installation_id,source_user_id) DO UPDATE SET local_user_id=excluded.local_user_id,role=excluded.role,active=excluded.active,status=excluded.status,issuer=excluded.issuer,subject=excluded.subject,updated_at=excluded.updated_at`)
      .run(organizationId,origin,sourceUserId,localUserId,active?role:prior?.role??"VIEWER",active?1:0,status,d.issuer??null,d.subject??null,nowIso());
  }

  public pendingMemberships(organizationId:string):unknown[]{this.assertOrganization(organizationId);return this.database.db.prepare("SELECT origin_installation_id AS originInstallationId,source_user_id AS sourceUserId,role,status,issuer,subject,updated_at AS updatedAt FROM cloud_sync_membership_bindings WHERE organization_id=? AND status IN ('PENDING','CONFLICT') ORDER BY updated_at DESC LIMIT 500").all(organizationId);}
  public bindMembership(organizationId:string,originInstallationId:string,sourceUserId:string,localUserId:string):void{
    this.assertOrganization(organizationId);
    const pending=this.database.db.prepare("SELECT role,active FROM cloud_sync_membership_bindings WHERE organization_id=? AND origin_installation_id=? AND source_user_id=? AND status IN ('PENDING','CONFLICT')").get(organizationId,originInstallationId,sourceUserId) as {role:string;active:number}|undefined;
    if(!pending||pending.active!==1)throw new Error("CLOUD_SYNC_MEMBERSHIP_BINDING_UNAVAILABLE");
    if(!this.database.db.prepare("SELECT 1 FROM dashboard_users WHERE id=? AND enabled=1").get(localUserId))throw new Error("CLOUD_SYNC_MEMBERSHIP_USER_UNAVAILABLE");
    const current=this.database.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(organizationId,localUserId) as {role:string}|undefined;
    if(current?.role==="OWNER"&&pending.role!=="OWNER"&&this.ownerCount(organizationId)<=1)throw new Error("ORGANIZATION_FINAL_OWNER_REQUIRED");
    this.database.transaction(()=>{
      this.database.db.prepare(`INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?)
        ON CONFLICT(organization_id,user_id) DO UPDATE SET role=excluded.role,updated_at=excluded.updated_at`).run(organizationId,localUserId,pending.role,`cloud-sync:approved:${originInstallationId}`,nowIso(),nowIso());
      this.database.db.prepare("UPDATE cloud_sync_membership_bindings SET local_user_id=?,status='BOUND',updated_at=? WHERE organization_id=? AND origin_installation_id=? AND source_user_id=?").run(localUserId,nowIso(),organizationId,originInstallationId,sourceUserId);
    });
  }
  private ownerCount(organizationId:string):number{return(this.database.db.prepare("SELECT COUNT(*) AS count FROM organization_memberships WHERE organization_id=? AND role='OWNER'").get(organizationId) as {count:number}).count;}

  private readPortableArtifact(path:string,expectedSize:number):Buffer{
    if(!isAbsolute(path)||!Number.isSafeInteger(expectedSize)||expectedSize<0||expectedSize>128*1024*1024)throw new Error("CLOUD_SYNC_ARTIFACT_SIZE_OR_PATH_REJECTED");
    const actual=realpathSync(path),stat=lstatSync(actual);
    if(!stat.isFile()||stat.size!==expectedSize)throw new Error("CLOUD_SYNC_ARTIFACT_SIZE_OR_PATH_REJECTED");
    const root=realpathSync(dirname(this.database.databasePath));
    const allowed=["reports","proof-packs","artifacts","integrations"].some((directory)=>{
      const candidate=resolve(root,directory),rel=relative(candidate,actual);
      return rel!==""&&!rel.startsWith(`..${sep}`)&&rel!==".."&&!isAbsolute(rel);
    });
    if(!allowed)throw new Error("CLOUD_SYNC_ARTIFACT_PATH_REJECTED");
    return readFileSync(actual);
  }

  private applyCredential(organizationId:string,entity:OrganizationStateEntity,secret:CredentialProfileSecret):void {
    const d=entity.data;this.vault!.upsertFromSynchronization({id:entity.entityId,organizationId,name:String(d.name),...(d.description?{description:String(d.description)}:{}),safeAlias:String(d.safe_alias),enabled:Number(d.enabled)===1,...(d.project_id?{projectId:String(d.project_id)}:{}),...(d.target_id?{targetId:String(d.target_id)}:{}),...(d.expires_at?{expiresAt:String(d.expires_at)}:{}),safeIdentitySummary:parseObject(d.safe_identity_summary_json),secret,createdAt:String(d.created_at),updatedAt:String(d.updated_at),...(d.deleted_at?{deletedAt:String(d.deleted_at)}:{})});
  }

  private saveVersion(organizationId:string,entity:OrganizationStateEntity):void {this.database.db.prepare(`INSERT INTO cloud_sync_entity_versions (organization_id,entity_type,entity_id,origin_installation_id,source_updated_at,source_row_version,payload_digest,applied_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,entity_type,entity_id) DO UPDATE SET origin_installation_id=excluded.origin_installation_id,source_updated_at=excluded.source_updated_at,source_row_version=excluded.source_row_version,payload_digest=excluded.payload_digest,applied_at=excluded.applied_at`).run(organizationId,entity.entityType,entity.entityId,entity.originInstallationId,entity.updatedAt,entity.rowVersion,entity.payloadDigest,nowIso());}
  private assertOrganization(id:string):void{if(!this.database.db.prepare("SELECT 1 FROM organizations WHERE id=? AND status='ACTIVE'").get(id))throw new Error("CLOUD_SYNC_ORGANIZATION_UNAVAILABLE");}
  private meta(key:string):string{const row=this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as {value:string}|undefined;if(!row)throw new Error(`DASHBOARD_META_MISSING:${key}`);return row.value;}
}

function compareVersion(incoming:OrganizationStateEntity,current:{source_updated_at:string;source_row_version:number;origin_installation_id:string}):number{const a=Date.parse(incoming.updatedAt),b=Date.parse(current.source_updated_at);if(a!==b)return a>b?1:-1;if(incoming.rowVersion!==current.source_row_version)return incoming.rowVersion>current.source_row_version?1:-1;return incoming.originInstallationId.localeCompare(current.origin_installation_id);}
function withoutId(row:Record<string,unknown>):Record<string,unknown>{const{id:_id,...data}=row;return data;}
function canonical(value:unknown):string{return JSON.stringify(sort(value));}
function sort(value:unknown):unknown{if(Array.isArray(value))return value.map(sort);if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b)).map(([key,item])=>[key,sort(item)]));return value;}
function hash(value:string):string{return createHash("sha256").update(value).digest("hex");}
function stableUuid(value:string):string{const digest=hash(value);return`${digest.slice(0,8)}-${digest.slice(8,12)}-${digest.slice(12,16)}-${digest.slice(16,20)}-${digest.slice(20,32)}`;}
function entityKey(entity:OrganizationStateEntity):string{return`${String(typeOrder[entity.entityType]).padStart(2,"0")}:${entity.entityType}:${entity.entityId}`;}
function validDate(value:string):string{if(!Number.isFinite(Date.parse(value)))throw new Error("CLOUD_SYNC_STATE_TIMESTAMP_REJECTED");return value;}
function parseObject(value:unknown):Record<string,unknown>{try{const parsed=typeof value==="string"?JSON.parse(value):value;return parsed&&typeof parsed==="object"&&!Array.isArray(parsed)?parsed as Record<string,unknown>:{};}catch{return{};}}
function key(secret:string):Buffer{return createHmac("sha256",secret).update("routecairn-cloud-sync-credential-envelope-v1").digest();}
function seal(value:CredentialProfileSecret,secret:string,organizationId:string,entityId:string):string{const nonce=randomBytes(12),cipher=createCipheriv("aes-256-gcm",key(secret),nonce);cipher.setAAD(Buffer.from(`${organizationId}\0${entityId}`));const body=Buffer.concat([cipher.update(canonical(value),"utf8"),cipher.final()]);return`v1.${nonce.toString("base64url")}.${body.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}`;}
function unseal(value:string,secret:string,organizationId:string,entityId:string):CredentialProfileSecret{const parts=value.split(".");if(parts.length!==4||parts[0]!=="v1")throw new Error("CLOUD_SYNC_CREDENTIAL_ENVELOPE_REJECTED");try{const decipher=createDecipheriv("aes-256-gcm",key(secret),Buffer.from(parts[1]!,"base64url"));decipher.setAAD(Buffer.from(`${organizationId}\0${entityId}`));decipher.setAuthTag(Buffer.from(parts[3]!,"base64url"));return JSON.parse(Buffer.concat([decipher.update(Buffer.from(parts[2]!,"base64url")),decipher.final()]).toString("utf8")) as CredentialProfileSecret;}catch{throw new Error("CLOUD_SYNC_CREDENTIAL_ENVELOPE_REJECTED");}}
function sealBytes(value:Buffer,secret:string,organizationId:string,entityId:string):string{const nonce=randomBytes(12),cipher=createCipheriv("aes-256-gcm",key(secret),nonce);cipher.setAAD(Buffer.from(`artifact\0${organizationId}\0${entityId}`));const body=Buffer.concat([cipher.update(value),cipher.final()]);return`v1.${nonce.toString("base64url")}.${body.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}`;}
function unsealBytes(value:string,secret:string,organizationId:string,entityId:string):Buffer{const parts=value.split(".");if(parts.length!==4||parts[0]!=="v1")throw new Error("CLOUD_SYNC_ARTIFACT_ENVELOPE_REJECTED");try{const decipher=createDecipheriv("aes-256-gcm",key(secret),Buffer.from(parts[1]!,"base64url"));decipher.setAAD(Buffer.from(`artifact\0${organizationId}\0${entityId}`));decipher.setAuthTag(Buffer.from(parts[3]!,"base64url"));return Buffer.concat([decipher.update(Buffer.from(parts[2]!,"base64url")),decipher.final()]);}catch{throw new Error("CLOUD_SYNC_ARTIFACT_ENVELOPE_REJECTED");}}
function validateSnapshot(value:OrganizationStateSnapshot):void{if(value.schemaVersion!==1||!Array.isArray(value.entities)||value.entities.length>10_000||Buffer.byteLength(canonical(value))>16*1024*1024)throw new Error("CLOUD_SYNC_STATE_REJECTED");validDate(value.generatedAt);if(!/^[0-9a-f-]{36}$/i.test(value.sourceInstallationId)||!/^[a-f0-9]{64}$/.test(value.stateDigest)||(value.fullStateDigest&&!/^[a-f0-9]{64}$/.test(value.fullStateDigest))||(value.nextCursor&&value.nextCursor.length>200))throw new Error("CLOUD_SYNC_STATE_REJECTED");}
