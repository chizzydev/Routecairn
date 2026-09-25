import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ArtifactRepository, ProjectRepository, SavedConfigurationRepository, ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { CloudSyncService } from "../../src/dashboard/operations/CloudSyncService.js";
import { OrganizationStateMergeService } from "../../src/dashboard/operations/OrganizationStateMergeService.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { cloudSyncPushSchema } from "../../src/dashboard/contracts/OperationalScaleSchemas.js";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

describe("organization tenancy and state merge", () => {
  it("automatically assigns legacy rows and rejects cross-organization parent relationships", () => {
    const database=fixture();const organizations=new OrganizationService(database);const defaultId=organizations.defaultOrganizationId();
    const secondId=organizations.create({name:"Second tenant",slug:`second-${randomUUID().slice(0,8)}`},"local-operator");
    const projects=new ProjectRepository(database),targets=new TargetRepository(database);
    const legacyId=randomUUID(),now=new Date().toISOString();
    database.db.prepare("INSERT INTO projects (id,name,tags_json,default_scope_json,created_at,updated_at) VALUES (?,?,?,?,?,?)").run(legacyId,"Legacy","[]","{}",now,now);
    expect((database.db.prepare("SELECT organization_id FROM projects WHERE id=?").get(legacyId) as {organization_id:string}).organization_id).toBe(defaultId);
    const secondProject=projects.create({organizationId:secondId,name:"Second",tags:[],defaultScope:{}});
    expect(projects.list(undefined,false,defaultId).map((item)=>item.id)).toContain(legacyId);
    expect(projects.list(undefined,false,defaultId).map((item)=>item.id)).not.toContain(secondProject);
    expect(()=>targets.create({organizationId:defaultId,projectId:secondProject,displayName:"Cross tenant",baseOrigin:"https://cross.example.test",tags:[],classification:"PRIVATE",authorizationType:"OWNED",authorizationSummary:"fixture",approvedScope:{}})).toThrow(/ORGANIZATION_MISMATCH/);
    const secondScan=randomUUID();new ScanRepository(database).create({organizationId:secondId,id:secondScan,source:"DASHBOARD",status:"COMPLETED",targetOrigin:"https://second.example.test",safeTargetLabel:"second.example.test",profile:"quick",evidenceLevel:"minimal",safeConfigurationSummary:{},projectId:secondProject});
    expect(new ScanComparisonService(database).candidates(undefined,defaultId).map((item)=>item.id)).not.toContain(secondScan);
    expect(new ScanComparisonService(database).candidates(undefined,secondId).map((item)=>item.id)).toContain(secondScan);
    database.close();
  });

  it("merges full organization state and re-encrypts credentials under the destination vault key", () => {
    const left=fixture(),right=fixture();
    const leftOrg=new OrganizationService(left).defaultOrganizationId(),rightOrg=new OrganizationService(right).defaultOrganizationId();
    const leftVault=new CredentialVault(left,{bytes:randomBytes(32),version:"left"}),rightVault=new CredentialVault(right,{bytes:randomBytes(32),version:"right"});
    const projects=new ProjectRepository(left),targets=new TargetRepository(left),scans=new ScanRepository(left);
    const configurationId=new SavedConfigurationRepository(left).create({organizationId:leftOrg,name:"Federated configuration",profile:"quick",modules:[],limits:{},scopeSettings:{},browserPolicySettings:{},evidenceLevel:"minimal",workflowRefs:[]});
    const projectId=projects.create({organizationId:leftOrg,name:"Federated project",tags:["state"],defaultScope:{program:"fixture"}});
    const targetId=targets.create({organizationId:leftOrg,projectId,displayName:"Federated target",baseOrigin:"https://state.example.test",tags:[],classification:"PRIVATE",authorizationType:"OWNED",authorizationSummary:"Owned fixture",approvedScope:{allowedDomains:["state.example.test"]}});
    const scanId=randomUUID();scans.create({organizationId:leftOrg,id:scanId,source:"DASHBOARD",status:"COMPLETED",targetOrigin:"https://state.example.test",safeTargetLabel:"state.example.test",profile:"quick",evidenceLevel:"minimal",safeConfigurationSummary:{},projectId,targetId});
    const newerScanId=randomUUID();scans.create({organizationId:leftOrg,id:newerScanId,source:"DASHBOARD",status:"COMPLETED",targetOrigin:"https://state.example.test",safeTargetLabel:"state.example.test",profile:"quick",evidenceLevel:"minimal",safeConfigurationSummary:{},projectId,targetId});
    const findingId=randomUUID(),now=new Date().toISOString();
    left.db.prepare(`INSERT INTO findings (id,organization_id,fingerprint,target_identity,module,finding_category,safe_endpoint_identity,safe_authorization_boundary_identity,canonical_title,current_scanner_severity,current_scanner_confidence,human_review_status,remediation_status,first_seen_at,last_seen_at,last_occurrence_scan_id,occurrence_count,project_id,target_id,remediation_state_v2,row_version,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,'UNREVIEWED','OPEN',?,?,?,1,?,?,'OPEN',1,?,?)`).run(findingId,leftOrg,`${leftOrg}:fixture-fingerprint`,"state.example.test","header-review","Headers","/","public","Fixture finding","Low","High",now,now,scanId,projectId,targetId,now,now);
    left.appendEvent(scanId,"SCAN_COMPLETED","Fixture scan completed.",{safe:true});
    const occurrenceId=randomUUID(),evidenceId=randomUUID();
    left.db.prepare(`INSERT INTO finding_occurrences (id,finding_id,scan_id,module,finding_category,severity,confidence,title,safe_endpoint,evidence_summary,finding_source_json,created_at,project_id,target_id,source_kind) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(occurrenceId,findingId,scanId,"header-review","Headers","Low","High","Fixture finding","/","Safe evidence","{}",now,projectId,targetId,"NATIVE");
    left.db.prepare(`INSERT INTO evidence_records (id,finding_occurrence_id,evidence_type,evidence_level,safe_summary,safe_structured_data_json,retention_classification,created_at) VALUES (?,?,?,?,?,?,?,?)`).run(evidenceId,occurrenceId,"HTTP_RESPONSE","minimal","Safe evidence","{}","STANDARD",now);
    const proofPackId=randomUUID();
    left.db.prepare(`INSERT INTO proof_packs (id,organization_id,safe_title,status,version,created_at,generated_at,source_scan_ids_json,scope_summary,included_finding_count,output_artifact_ids_json,immutable_snapshot_metadata_json) VALUES (?,?,'Federated proof','READY',1,?,?,?,?,1,'[]','{}')`).run(proofPackId,leftOrg,now,now,JSON.stringify([scanId]),"Safe fixture scope");
    left.db.prepare(`INSERT INTO proof_pack_findings (proof_pack_id,finding_id,selected_occurrence_id,sort_order,included_evidence_ids_json,snapshot_content_json,created_at) VALUES (?,?,?,?,?,?,?)`).run(proofPackId,findingId,occurrenceId,1,JSON.stringify([evidenceId]),"{}",now);
    const artifactDirectory=join(dirname(left.databasePath),"artifacts");mkdirSync(artifactDirectory,{recursive:true});
    const artifactPath=join(artifactDirectory,"federated-proof.txt"),artifactBytes=Buffer.from("Portable proof content");writeFileSync(artifactPath,artifactBytes);
    const artifactId=new ArtifactRepository(left).create({organizationId:leftOrg,proofPackId,type:"PROOF_PACK_TEXT",name:"federated-proof.txt",path:artifactPath,size:artifactBytes.length,contentType:"text/plain",hash:createHash("sha256").update(artifactBytes).digest("hex")});
    left.db.prepare("UPDATE proof_packs SET output_artifact_ids_json=? WHERE id=?").run(JSON.stringify([artifactId]),proofPackId);
    const comparisonId=new ScanComparisonService(left).compare(scanId,newerScanId).comparisonId;
    const otherOrg=new OrganizationService(left).create({name:"Foreign scan tenant",slug:`foreign-${randomUUID().slice(0,8)}`},"local-operator");
    const foreignScan=randomUUID();scans.create({organizationId:otherOrg,id:foreignScan,source:"DASHBOARD",status:"COMPLETED",targetOrigin:"https://foreign.example.test",safeTargetLabel:"foreign.example.test",profile:"quick",evidenceLevel:"minimal",safeConfigurationSummary:{}});
    expect(()=>left.db.prepare(`INSERT INTO finding_occurrences (id,finding_id,scan_id,module,finding_category,severity,confidence,title,safe_endpoint,evidence_summary,finding_source_json,created_at,source_kind) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(randomUUID(),findingId,foreignScan,"header-review","Headers","Low","High","Foreign", "/", "", "{}",now,"NATIVE")).toThrow(/ORGANIZATION_MISMATCH/);
    const credentialId=leftVault.create({organizationId:leftOrg,name:"Federated credential",safeAlias:"fixture-user",projectId,targetId,safeIdentitySummary:{principal:"fixture-user"},secret:{authorizationHeader:"Bearer private-federation-value"}});
    const env=`ROUTECAIRN_STATE_SYNC_${randomUUID().replaceAll("-","_")}`;process.env[env]="s".repeat(48);
    try{
      const leftSync=new CloudSyncService(left,leftVault),rightSync=new CloudSyncService(right,rightVault);
      const leftPeer=leftSync.createPeer({organizationId:leftOrg,remoteOrganizationId:rightOrg,name:"federation",endpoint:"https://right.example.test",sharedSecretEnv:env,enabled:true,syncMode:"FULL_STATE"},"operator");
      const rightPeer=rightSync.createPeer({organizationId:rightOrg,remoteOrganizationId:leftOrg,name:"federation",endpoint:"https://left.example.test",sharedSecretEnv:env,enabled:true,syncMode:"FULL_STATE"},"operator");
      const batch=leftSync.batch(leftPeer);expect(batch.state?.entities.length).toBeGreaterThanOrEqual(4);
      const body=cloudSyncPushSchema.parse({organizationId:batch.organizationId,cursor:batch.cursor,events:batch.events,...(batch.state?{state:batch.state}:{})});
      expect(rightSync.receive(rightPeer,body,batch.signature)).toEqual(expect.objectContaining({state:expect.objectContaining({applied:expect.any(Number)})}));
      expect(new ProjectRepository(right).get(projectId,false,rightOrg)?.name).toBe("Federated project");
      expect(new SavedConfigurationRepository(right).get(configurationId,false,rightOrg)?.name).toBe("Federated configuration");
      expect(new SavedConfigurationRepository(right).history(configurationId,rightOrg)).toHaveLength(1);
      expect(new TargetRepository(right).get(targetId,false,rightOrg)?.projectId).toBe(projectId);
      expect(new ScanRepository(right).get(scanId,rightOrg)?.status).toBe("COMPLETED");
      expect((right.db.prepare("SELECT organization_id FROM findings WHERE id=?").get(findingId) as {organization_id:string}).organization_id).toBe(rightOrg);
      expect((right.db.prepare("SELECT COUNT(*) AS count FROM scan_events WHERE scan_id=?").get(scanId) as {count:number}).count).toBe(1);
      expect((right.db.prepare("SELECT safe_summary FROM evidence_records WHERE id=?").get(evidenceId) as {safe_summary:string}).safe_summary).toBe("Safe evidence");
      expect(new ScanComparisonService(right).get(comparisonId).oldScanId).toBe(scanId);
      expect((right.db.prepare("SELECT organization_id FROM proof_packs WHERE id=?").get(proofPackId) as {organization_id:string}).organization_id).toBe(rightOrg);
      expect((right.db.prepare("SELECT COUNT(*) AS count FROM proof_pack_findings WHERE proof_pack_id=?").get(proofPackId) as {count:number}).count).toBe(1);
      const receivedArtifact=new ArtifactRepository(right).get(artifactId,rightOrg);
      expect(receivedArtifact).toBeDefined();expect(readFileSync(receivedArtifact!.path,"utf8")).toBe("Portable proof content");
      expect(rightVault.getSummary(credentialId,rightOrg)?.keyVersion).toBe("right");
      expect(rightVault.decryptForUse(credentialId).authorizationHeader).toBe("Bearer private-federation-value");
      // Scans have no updated_at/row_version; a later status change still
      // needs to propagate, including when the original created_at is old.
      left.db.prepare("UPDATE scans SET status='FAILED',error_summary=? WHERE id=?").run("Safe fixture failure",scanId);
      const changed=leftSync.batch(leftPeer);
      expect(changed.state?.stateDigest).not.toBe(batch.state?.stateDigest);
      rightSync.receive(rightPeer,{organizationId:changed.organizationId,cursor:changed.cursor,events:changed.events,state:changed.state},changed.signature);
      expect(new ScanRepository(right).get(scanId,rightOrg)?.status).toBe("FAILED");
      const echoed=rightSync.batch(rightPeer).state?.entities.find((entity)=>entity.entityType==="scan"&&entity.entityId===scanId);
      const changedScan=changed.state?.entities.find((entity)=>entity.entityType==="scan"&&entity.entityId===scanId);
      expect(echoed?.originInstallationId).toBe(changedScan?.originInstallationId);
      expect(echoed?.rowVersion).toBe(changedScan?.rowVersion);
      leftVault.delete(credentialId);left.db.prepare("UPDATE credential_profiles SET updated_at=? WHERE id=?").run(new Date(Date.now()+1000).toISOString(),credentialId);
      const deletion=leftSync.batch(leftPeer),deletionBody={organizationId:deletion.organizationId,cursor:deletion.cursor,events:deletion.events,...(deletion.state?{state:deletion.state}:{})};
      rightSync.receive(rightPeer,deletionBody,deletion.signature);expect(rightVault.getSummary(credentialId,rightOrg)).toBeUndefined();
      const outside=join(mkdtempSync(join(tmpdir(),"routecairn-outside-artifact-")),"outside.txt");directories.push(dirname(outside));writeFileSync(outside,"not portable");
      new ArtifactRepository(left).create({organizationId:leftOrg,scanId,type:"UNSAFE_FIXTURE",name:"outside.txt",path:outside,size:12,contentType:"text/plain",hash:"fixture"});
      expect(()=>leftSync.batch(leftPeer)).toThrow("CLOUD_SYNC_ARTIFACT_PATH_REJECTED");
    }finally{delete process.env[env];left.close();right.close();}
  });

  it("scopes dashboard resource APIs to the selected organization", async () => {
    const directory=mkdtempSync(join(tmpdir(),"routecairn-tenant-api-"));directories.push(directory);
    const server=await startDashboardServer({dataDir:directory,uiDistDir:join(directory,"ui")});
    try{
      const token=new URL(server.bootstrapUrl!).hash.replace("#bootstrap=","");
      const login=await fetch(`${server.url}/api/session/bootstrap`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({token})});
      const auth=await login.json() as {csrfToken:string};const cookie=login.headers.get("set-cookie")!.split(";")[0]!;
      const organizations=await fetch(`${server.url}/api/operations/organizations`,{headers:{cookie}}).then((response)=>response.json()) as {organizations:Array<{id:string}>};
      const second=await mutate<{organizationId:string}>(server.url,"/api/operations/organizations",cookie,auth.csrfToken,undefined,{name:"Isolated",slug:`isolated-${randomUUID().slice(0,8)}`});
      const firstId=organizations.organizations[0]!.id;
      await mutate(server.url,"/api/projects",cookie,auth.csrfToken,firstId,{name:"First project",tags:[],defaultScope:{}});
      await mutate(server.url,"/api/projects",cookie,auth.csrfToken,second.organizationId,{name:"Second project",tags:[],defaultScope:{}});
      const first=await listProjects(server.url,cookie,firstId),isolated=await listProjects(server.url,cookie,second.organizationId);
      expect(first).toEqual(["First project"]);expect(isolated).toEqual(["Second project"]);
      await mutate(server.url,"/api/configurations",cookie,auth.csrfToken,firstId,{name:"First configuration",profile:"quick"});
      await mutate(server.url,"/api/configurations",cookie,auth.csrfToken,second.organizationId,{name:"Second configuration",profile:"quick"});
      const firstConfigurations=await fetch(`${server.url}/api/configurations`,{headers:{cookie,"x-routecairn-organization-id":firstId}}).then((response)=>response.json()) as {configurations:Array<{name:string}>};
      expect(firstConfigurations.configurations.map((item)=>item.name)).toEqual(["First configuration"]);
      const direct=new DashboardDatabase(join(directory,"routecairn-dashboard.sqlite"));
      const isolatedScan=randomUUID();
      let isolatedArtifact="";
      try{new ScanRepository(direct).create({organizationId:second.organizationId,id:isolatedScan,source:"DASHBOARD",status:"COMPLETED",targetOrigin:"https://isolated.example.test",safeTargetLabel:"isolated.example.test",profile:"quick",evidenceLevel:"minimal",safeConfigurationSummary:{}});
        isolatedArtifact=new ArtifactRepository(direct).create({organizationId:second.organizationId,scanId:isolatedScan,type:"FIXTURE",name:"isolated.txt",path:join(directory,"artifacts","isolated.txt"),size:0,contentType:"text/plain",hash:"fixture"});
      }finally{direct.close();}
      const candidateResponse=await fetch(`${server.url}/api/comparisons/candidates`,{headers:{cookie,"x-routecairn-organization-id":firstId}});
      expect(candidateResponse.status).toBe(200);
      expect(((await candidateResponse.json()) as {scans:Array<{id:string}>}).scans.map((item)=>item.id)).not.toContain(isolatedScan);
      expect((await fetch(`${server.url}/api/artifacts/${isolatedArtifact}/download`,{headers:{cookie,"x-routecairn-organization-id":firstId}})).status).toBe(404);
      expect((await fetch(`${server.url}/api/artifacts/${isolatedArtifact}/preview`,{headers:{cookie,"x-routecairn-organization-id":firstId}})).status).toBe(404);
    }finally{await server.close();}
  });

  it("maps verified SSO memberships and queues unmapped users for explicit binding",()=>{
    const left=fixture(),right=fixture();
    const leftOrg=new OrganizationService(left).defaultOrganizationId(),rightOrg=new OrganizationService(right).defaultOrganizationId();
    const sourceUser=randomUUID(),destinationUser=randomUUID(),localOnlyUser=randomUUID(),destinationLocalUser=randomUUID(),now=new Date().toISOString();
    for(const [database,id,login] of [[left,sourceUser,"source"],[right,destinationUser,"destination"],[left,localOnlyUser,"local-source"],[right,destinationLocalUser,"local-destination"]] as const){
      database.db.prepare("INSERT INTO dashboard_users (id,login,normalized_login,password_hash,role,created_at,updated_at,password_changed_at) VALUES (?,?,?,?,'ANALYST',?,?,?)").run(id,login,login,"fixture-hash",now,now,now);
    }
    const leftProvider=randomUUID(),rightProvider=randomUUID(),issuer="https://identity.example.test";
    for(const [database,organizationId,providerId,userId] of [[left,leftOrg,leftProvider,sourceUser],[right,rightOrg,rightProvider,destinationUser]] as const){
      database.db.prepare(`INSERT INTO sso_providers (id,organization_id,name,issuer,authorization_endpoint,token_endpoint,jwks_uri,client_id,client_secret_env,scopes_json,allowed_domains_json,enabled,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,1,'fixture',?,?)`).run(providerId,organizationId,"Fixture IdP",issuer,`${issuer}/authorize`,`${issuer}/token`,`${issuer}/jwks`,"client","TEST_CLIENT_SECRET","[]","[]",now,now);
      database.db.prepare("INSERT INTO sso_identities (provider_id,subject,user_id,created_at) VALUES (?,?,?,?)").run(providerId,"shared-subject",userId,now);
    }
    left.db.prepare("INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?,?,'ANALYST','fixture',?,?)").run(leftOrg,sourceUser,now,now);
    left.db.prepare("INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?,?,'VIEWER','fixture',?,?)").run(leftOrg,localOnlyUser,now,now);
    const env=`ROUTECAIRN_MEMBER_SYNC_${randomUUID().replaceAll("-","_")}`;process.env[env]="m".repeat(48);
    try{
      const sender=new CloudSyncService(left),receiver=new CloudSyncService(right);
      const senderPeer=sender.createPeer({organizationId:leftOrg,remoteOrganizationId:rightOrg,name:"members",endpoint:"https://right.example.test",sharedSecretEnv:env,enabled:true},"fixture");
      const receiverPeer=receiver.createPeer({organizationId:rightOrg,remoteOrganizationId:leftOrg,name:"members",endpoint:"https://left.example.test",sharedSecretEnv:env,enabled:true},"fixture");
      const transfer=()=>{const batch=sender.batch(senderPeer);receiver.receive(receiverPeer,{organizationId:batch.organizationId,cursor:batch.cursor,events:batch.events,state:batch.state},batch.signature);};
      transfer();
      expect((right.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(rightOrg,destinationUser) as {role:string}).role).toBe("ANALYST");
      const pending=receiver.pendingMemberships(rightOrg) as Array<{sourceUserId:string;status:string}>;
      expect(pending).toEqual(expect.arrayContaining([expect.objectContaining({sourceUserId:localOnlyUser,status:"PENDING"})]));
      const leftInstallation=(left.db.prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'").get() as {value:string}).value;
      receiver.bindMembership(rightOrg,leftInstallation,localOnlyUser,destinationLocalUser);
      expect((right.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(rightOrg,destinationLocalUser) as {role:string}).role).toBe("VIEWER");
      left.db.prepare("DELETE FROM organization_memberships WHERE organization_id=? AND user_id=?").run(leftOrg,sourceUser);
      transfer();
      expect(right.db.prepare("SELECT 1 FROM organization_memberships WHERE organization_id=? AND user_id=?").get(rightOrg,destinationUser)).toBeUndefined();
    }finally{delete process.env[env];left.close();right.close();}
  });

  it("pages a large organization without dropping the tail of its state",()=>{
    const database=fixture(),organizationId=new OrganizationService(database).defaultOrganizationId(),insert=database.db.prepare("INSERT INTO projects (id,organization_id,name,tags_json,default_scope_json,created_at,updated_at) VALUES (?,?,?,'[]','{}',?,?)"),now=new Date().toISOString();
    database.transaction(()=>{for(let index=0;index<9_050;index++)insert.run(randomUUID(),organizationId,`Project ${index}`,now,now);});
    const merger=new OrganizationStateMergeService(database),snapshot=merger.snapshot(organizationId,"p".repeat(48)),first=merger.page(snapshot,null),second=merger.page(snapshot,first.nextCursor!);
    expect(first.entities).toHaveLength(9_000);expect(first.nextCursor).toBeTruthy();
    expect(second.entities).toHaveLength(50);expect(second.nextCursor).toBeUndefined();
    expect(first.fullStateDigest).toBe(snapshot.stateDigest);expect(second.fullStateDigest).toBe(snapshot.stateDigest);
    database.close();
  });
  it("restarts a paginated transfer when the source changes before the next page",()=>{
    const database=fixture(),organizationId=new OrganizationService(database).defaultOrganizationId(),projects=new ProjectRepository(database);
    const firstId=projects.create({organizationId,name:"First",tags:[],defaultScope:{}}),secondId=projects.create({organizationId,name:"Second",tags:[],defaultScope:{}});
    const env=`ROUTECAIRN_CURSOR_SYNC_${randomUUID().replaceAll("-","_")}`;process.env[env]="r".repeat(48);
    try{
      const service=new CloudSyncService(database),peer=service.createPeer({organizationId,name:"cursor",endpoint:"https://cursor.example.test",sharedSecretEnv:env,enabled:true},"fixture");
      const initial=service.batch(peer),first=initial.state!.entities.find((entity)=>entity.entityType==="project")!;
      database.db.prepare("UPDATE cloud_sync_peers SET state_cursor=?,state_cursor_digest=? WHERE id=?").run(`00:project:${first.entityId}`,initial.state!.fullStateDigest,peer);
      database.db.prepare("UPDATE projects SET name=?,updated_at=? WHERE id=?").run("Changed",new Date(Date.now()+1000).toISOString(),first.entityId);
      const restarted=service.batch(peer);
      expect(restarted.state?.entities.find((entity)=>entity.entityId===first.entityId)).toBeDefined();
      expect([firstId,secondId]).toContain(first.entityId);
    }finally{delete process.env[env];database.close();}
  });
  it("resumes multi-page artifact chunks and publishes only verified complete files",()=>{
    const left=fixture(),right=fixture(),leftOrg=new OrganizationService(left).defaultOrganizationId(),rightOrg=new OrganizationService(right).defaultOrganizationId();
    const artifactDirectory=join(dirname(left.databasePath),"artifacts");mkdirSync(artifactDirectory,{recursive:true});
    const sourcePath=join(artifactDirectory,"large-fixture.bin"),content=Buffer.alloc(9*1024*1024,0x5a);writeFileSync(sourcePath,content);
    const artifactId=new ArtifactRepository(left).create({organizationId:leftOrg,type:"FIXTURE",name:"large-fixture.bin",path:sourcePath,size:content.length,contentType:"application/octet-stream",hash:createHash("sha256").update(content).digest("hex")});
    const secret="c".repeat(48),sourceMerge=new OrganizationStateMergeService(left),destinationMerge=new OrganizationStateMergeService(right),snapshot=sourceMerge.snapshot(leftOrg,secret,rightOrg);
    let cursor:string|null=null,pages=0;
    do{
      const page=sourceMerge.page(snapshot,cursor);cloudSyncPushSchema.parse({organizationId:rightOrg,cursor:0,events:[],state:page});
      destinationMerge.merge(rightOrg,page,secret);pages+=1;cursor=page.nextCursor??null;
      const row=right.db.prepare("SELECT missing_file_flag FROM artifacts WHERE id=?").get(artifactId) as {missing_file_flag:number};
      if(cursor)expect(row.missing_file_flag).toBe(1);
    }while(cursor);
    expect(pages).toBeGreaterThan(1);
    const received=new ArtifactRepository(right).get(artifactId,rightOrg)!;
    expect(readFileSync(received.path)).toEqual(content);
    expect((right.db.prepare("SELECT missing_file_flag FROM artifacts WHERE id=?").get(artifactId) as {missing_file_flag:number}).missing_file_flag).toBe(0);
    left.close();right.close();
  },90_000);
});

function fixture():DashboardDatabase{const directory=mkdtempSync(join(tmpdir(),"routecairn-tenant-state-"));directories.push(directory);const database=new DashboardDatabase(join(directory,"dashboard.sqlite"));database.migrate();return database;}
async function mutate<T=unknown>(base:string,path:string,cookie:string,csrf:string,organizationId:string|undefined,body:unknown):Promise<T>{const response=await fetch(`${base}${path}`,{method:"POST",headers:{cookie,"x-csrf-token":csrf,"content-type":"application/json",origin:base,...(organizationId?{"x-routecairn-organization-id":organizationId}:{})},body:JSON.stringify(body)});if(!response.ok)throw new Error(`${response.status}:${await response.text()}`);return response.json() as Promise<T>;}
async function listProjects(base:string,cookie:string,organizationId:string):Promise<string[]>{const response=await fetch(`${base}/api/projects`,{headers:{cookie,"x-routecairn-organization-id":organizationId}});if(!response.ok)throw new Error(`${response.status}:${await response.text()}`);return((await response.json()) as {projects:Array<{name:string}>}).projects.map((item)=>item.name);}
