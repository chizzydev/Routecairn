import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ContinuousAssuranceService } from "../../src/dashboard/execution/ContinuousAssuranceService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

const cleanup:string[]=[];afterEach(()=>{while(cleanup.length)rmSync(cleanup.pop()!,{recursive:true,force:true});});

describe("continuous assurance",()=>{
  it("binds review to the full policy semantics and rejects target drift",async()=>{
    const f=fixture();cleanup.push(f.dir);const input=policyInput(f.targetId,f.adapterId,f.baselineId),preview=await f.service.preview(input);expect(preview.blockers).toEqual([]);
    const changed=await f.service.preview({...input,gates:{...input.gates,failOnNewFinding:false}});expect(changed.policyDigest).not.toBe(preview.policyDigest);
    const created=await f.service.create(input,"owner") as any;
    expect(()=>f.service.setEnabled(created.policy.id,true,created.policy.impact.impactDigest)).toThrow("DISABLED_POLICY_REQUIRED");
    f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.targetId);
    await expect(f.service.review(created.policy.id,created.policy.pendingVersionId,preview.policyDigest,"owner")).rejects.toThrow("BINDING_CHANGED");
    f.database.close();
  });

  it("blocks review when authorization cannot cover the next scheduled worst-case run",async()=>{
    const f=fixture();cleanup.push(f.dir);const input=policyInput(f.targetId,f.adapterId,f.baselineId);input.authorization.expiresAt=new Date(Date.now()+30*60_000).toISOString();const preview=await f.service.preview(input);expect(preview.blockers).toEqual(expect.arrayContaining([expect.stringContaining("next scheduled run")]));await expect(f.service.create(input,"owner")).rejects.toThrow("CONTINUOUS_ASSURANCE_INVALID");f.database.close();
  });

  it("runs exact reviewed cases, remains quiet on success, and makes deployment triggers idempotent",async()=>{
    const f=fixture();cleanup.push(f.dir);const input=policyInput(f.targetId,f.adapterId,f.baselineId),preview=await f.service.preview(input),created=await f.service.create(input,"owner") as any;
    await f.service.review(created.policy.id,created.policy.pendingVersionId,preview.policyDigest,"owner");
    const run=await f.service.runNow(created.policy.id,"owner") as any,scanId=run.lanes[0].scanId as string;
    f.database.db.prepare("UPDATE scans SET status='COMPLETED',completed_at=? WHERE id=?").run(new Date().toISOString(),scanId);
    f.database.db.prepare("INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,?,?,?,?,'COMPLETED',1,1,'STRONG','{}','{}',?)").run(randomUUID(),scanId,"api-graphql-authorization","api-graphql-authorization","account-boundary","c".repeat(64),new Date().toISOString());
    await f.service.reconcileNow();
    const state=f.service.get(created.policy.id) as any;expect(state.runs[0]).toMatchObject({status:"COMPLETED",gateStatus:"PASSED",notificationRequired:false});expect(f.service.notifications()).toEqual([]);
    const first=await f.service.deployment(created.policy.id,created.deploymentTriggerToken,"deploy-42","d".repeat(64)) as any,second=await f.service.deployment(created.policy.id,created.deploymentTriggerToken,"deploy-42","d".repeat(64)) as any;
    expect(first.idempotentReplay).toBe(false);expect(second).toMatchObject({idempotentReplay:true,runId:first.runId});
    await expect(f.service.deployment(created.policy.id,"wrong-token-that-is-long-enough-to-be-rejected","deploy-43","d".repeat(64))).rejects.toThrow("TRIGGER_REJECTED");
    f.database.close();
  });

  it("does not allow a weakened or unexecuted case to establish remediation",async()=>{
    const f=fixture();cleanup.push(f.dir);const input=policyInput(f.targetId,f.adapterId,f.baselineId),preview=await f.service.preview(input),created=await f.service.create(input,"owner") as any;await f.service.review(created.policy.id,created.policy.pendingVersionId,preview.policyDigest,"owner");
    const run=await f.service.runNow(created.policy.id,"owner") as any,scanId=run.lanes[0].scanId;f.database.db.prepare("UPDATE scans SET status='COMPLETED',completed_at=? WHERE id=?").run(new Date().toISOString(),scanId);await f.service.reconcileNow();
    const state=f.service.get(created.policy.id) as any;expect(state.runs[0].gateStatus).toBe("INCONCLUSIVE");expect(f.service.notifications()).toEqual([expect.objectContaining({category:"APPROVAL_REQUIRED"})]);
    f.database.close();
  });

  it("durably finalizes a run when every adapter fails before a scan is queued",async()=>{
    const f=fixture({failEnqueue:true});cleanup.push(f.dir);const input=policyInput(f.targetId,f.adapterId,f.baselineId),preview=await f.service.preview(input),created=await f.service.create(input,"owner") as any;await f.service.review(created.policy.id,created.policy.pendingVersionId,preview.policyDigest,"owner");
    const run=await f.service.runNow(created.policy.id,"owner") as any;expect(run).toMatchObject({status:"FAILED",gateStatus:"BLOCKED",notificationRequired:true});expect(run.lanes[0]).toMatchObject({status:"BLOCKED",scanId:null});expect(f.service.notifications()).toEqual(expect.arrayContaining([expect.objectContaining({category:"FAILED"})]));f.database.close();
  });
});

function fixture(options:{failEnqueue?:boolean}={}){
  const dir=mkdtempSync(join(tmpdir(),"routecairn-assurance-")),paths=resolveDashboardPaths(dir),database=new DashboardDatabase(paths.databasePath);database.migrate();
  const targetId=new TargetRepository(database).create({displayName:"Owned fixture",baseOrigin:"https://owned.example.test",tags:[],classification:"PRODUCTION",authorizationType:"OWNED",authorizationSummary:"Authorized",productionEnabled:true,approvedScope:{program:"Owned",allowedDomains:["owned.example.test"],disallowedPaths:["/never"],allowedMethods:["GET"],rateLimitPerSecond:2,concurrency:1,maxDepth:1,sameOriginOnly:true,includeSubdomains:false,respectRobotsTxt:false,userAgent:"RouteCairn/Test"}}),adapterId=randomUUID(),versionId=randomUUID(),now=new Date().toISOString();
  database.db.prepare("INSERT INTO provider_adapters (id,name,target_id,provider,engine_id,enabled,active_version_id,created_by,created_at,updated_at) VALUES (?,?,?,'GENERIC_HTTP','api-graphql-authorization',1,?,'owner',?,?)").run(adapterId,"API fixture",targetId,versionId,now,now);
  database.db.prepare("INSERT INTO provider_adapter_versions (id,profile_id,revision,status,adapter_digest,target_row_version,credential_binding_json,algorithm,key_version,nonce,ciphertext,auth_tag,created_by,created_at,reviewed_by,reviewed_at) VALUES (?,?,1,'REVIEWED',?,1,'[]','aes-256-gcm','one','n','c','t','owner',?,'owner',?)").run(versionId,adapterId,"a".repeat(64),now,now);
  const baselineId=randomUUID();new ScanRepository(database).create({id:baselineId,source:"DASHBOARD",status:"COMPLETED",targetOrigin:"https://owned.example.test",safeTargetLabel:"owned",profile:"full",evidenceLevel:"strong",safeConfigurationSummary:{},targetId});database.db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(baselineId,adapterId,versionId,"a".repeat(64),now);
  database.db.prepare("INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,?,?,?,?,'COMPLETED',1,1,'STRONG','{}','{}',?)").run(randomUUID(),baselineId,"api-graphql-authorization","api-graphql-authorization","account-boundary","c".repeat(64),now);
  const request={target:"https://owned.example.test",targetId,profile:"full"} as any;
  const execution={preview:async()=>({previewIdentity:"p".repeat(64),profile:"full",modules:[],limits:{maxScanDurationMs:60000,maxRequests:10,cleanupReservedRequests:2},evidence:{},skippedModules:[],controlledWorkflowRequests:[],planSnapshot:{},credentialReadiness:{ready:true,checkedAt:now,requiredValidThrough:now,blockers:[],warnings:[],profiles:[]},warnings:[]}),enqueue:async()=>{if(options.failEnqueue)throw new Error("Fixture enqueue failed");const id=randomUUID();new ScanRepository(database).create({id,source:"DASHBOARD",status:"QUEUED",targetOrigin:"https://owned.example.test",safeTargetLabel:"owned",profile:"full",evidenceLevel:"strong",safeConfigurationSummary:{},targetId});return id;}};
  const adapters={materialize:()=>({target:{id:targetId,rowVersion:1},input:{targetId},binding:{profileId:adapterId,versionId,adapterDigest:"a".repeat(64)}}),materializeScanRequest:()=>request,assertExecutionBinding:async()=>undefined,bindScan:(scanId:string,binding:any)=>database.db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(scanId,binding.profileId,binding.versionId,binding.adapterDigest,new Date().toISOString())};
  const comparison={compare:(oldScanId:string,newScanId:string)=>({comparisonId:randomUUID(),summary:{new:0,regressions:0,recurrences:0,persisting:0,changed:0,resolved:0,notRetested:0,incomparable:0,severityIncreases:0},oldScanId,newScanId}) as any},evidence={available:()=>true,createExport:()=>({id:randomUUID()})};
  return{dir,paths,database,targetId,adapterId,baselineId,service:new ContinuousAssuranceService(database,paths,execution as any,adapters as any,comparison as any,evidence,{startTimers:false})};
}
function policyInput(targetId:string,adapterId:string,baselineId:string){return{schemaVersion:1 as const,name:"Continuous API assurance",description:"Exact regression policy",targetId,authorization:{proofReference:"approval://owned/42",proofDigest:"b".repeat(64),validFrom:new Date(Date.now()-60000).toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString()},triggers:{scheduleEnabled:true,intervalMinutes:60,deploymentEnabled:true,quietWhenHealthy:true as const},adapterProfileIds:[adapterId],baselines:[{adapterProfileId:adapterId,scanId:baselineId}],requiredCases:[{adapterProfileId:adapterId,workflowId:"api-graphql-authorization",caseFingerprint:"c".repeat(64)}],gates:{failOnRegression:true as const,failOnNewFinding:true,failOnOpenDrift:true,requireExactCases:true as const,requireCleanupResolved:true as const},evidence:{retentionDays:90,autoExportOn:["REGRESSION","FAILED","CLEANUP_REQUIRED","APPROVAL_REQUIRED"] as const,preserveFailures:true as const,preserveCleanupEvidence:true as const}};}
