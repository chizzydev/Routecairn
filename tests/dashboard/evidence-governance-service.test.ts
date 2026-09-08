import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ArtifactRepository, ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { EvidenceGovernanceService, rotateEvidenceExportKey } from "../../src/dashboard/execution/EvidenceGovernanceService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

const directories:string[]=[];
afterEach(()=>{while(directories.length)rmSync(directories.pop()!,{recursive:true,force:true});});

describe("continuous-assurance evidence governance",()=>{
  it("creates, authenticates, rotates, and re-verifies an encrypted installation-bound export",()=>{
    const {database,paths,dir}=fixture(),current={bytes:randomBytes(32),version:"one"},next={bytes:randomBytes(32),version:"two"};directories.push(dir);
    const scanId=scan(database,"COMPLETED"),content=Buffer.from("redacted evidence\n"),artifactPath=join(paths.artifactsDir,"evidence.txt");mkdirSync(paths.artifactsDir,{recursive:true});writeFileSync(artifactPath,content);
    new ArtifactRepository(database).create({scanId,type:"REPORT",name:"evidence.txt",path:artifactPath,size:content.length,contentType:"text/plain",hash:sha(content)});
    const service=new EvidenceGovernanceService(database,paths,current),created=service.createExport([scanId],"owner") as any;
    expect(created).toMatchObject({status:"READY",scanCount:1,artifactCount:1,keyVersion:"one"});
    expect(service.verifyExport(created.id)).toMatchObject({verified:true,scanCount:1,artifactCount:1});
    expect(readFileSync(service.downloadableExport(created.id).path,"utf8")).not.toContain("redacted evidence");
    expect(rotateEvidenceExportKey(database,paths,current,next)).toBe(1);
    expect(new EvidenceGovernanceService(database,paths,next).verifyExport(created.id)).toMatchObject({verified:true,keyVersion:"two"});
    database.close();
  });

  it("rejects tampering and excludes failed evidence from retention purge",()=>{
    const {database,paths,dir}=fixture();directories.push(dir);const key={bytes:randomBytes(32),version:"one"};mkdirSync(paths.artifactsDir,{recursive:true});
    const completed=scan(database,"COMPLETED"),failed=scan(database,"FAILED"),repo=new ArtifactRepository(database);
    const pathsByScan=[completed,failed].map((id,index)=>{const path=join(paths.artifactsDir,`${index}.txt`),content=Buffer.from(`safe-${index}`);writeFileSync(path,content);const artifact=repo.create({scanId:id,type:"REPORT",name:`${index}.txt`,path,size:content.length,contentType:"text/plain",hash:sha(content)});database.db.prepare("UPDATE artifacts SET created_at='2020-01-01T00:00:00.000Z' WHERE id=?").run(artifact);return {path,artifact};});
    const service=new EvidenceGovernanceService(database,paths,key),created=service.createExport([completed],"owner") as any,download=service.downloadableExport(created.id),envelope=JSON.parse(readFileSync(download.path,"utf8"));const ciphertext=Buffer.from(envelope.ciphertext,"base64url");ciphertext[0]^=1;envelope.ciphertext=ciphertext.toString("base64url");writeFileSync(download.path,JSON.stringify(envelope));
    expect(()=>service.verifyExport(created.id)).toThrow(/SIGNATURE|authenticate/i);
    database.db.prepare("UPDATE evidence_exports SET created_at='2020-01-01T00:00:00.000Z' WHERE id=?").run(created.id);
    service.updatePolicy({retentionDays:1,preserveFailedScans:true,preserveUnresolvedCleanup:true,preserveUnreviewedFindings:true,maximumExportBytes:1048576,expectedVersion:1,confirmation:"I_CONFIRM_EVIDENCE_GOVERNANCE_POLICY"},"owner");
    const preview=service.purgePreview();expect(preview.protectedCounts.failed).toBe(1);expect(preview.candidates.map(x=>x.id).sort()).toEqual([pathsByScan[0]!.artifact,created.id].sort());
    const result=service.purge(preview.previewDigest,"owner") as any;expect(result).toMatchObject({purgedCount:2,failedCount:0});expect(service.purgePreview().candidates).toHaveLength(0);expect(service.listExports()).toHaveLength(0);
    database.close();
  });

  it("recovers interrupted purge claims according to the durable file state",()=>{
    const {database,paths,dir}=fixture();directories.push(dir);const key={bytes:randomBytes(32),version:"one"};mkdirSync(paths.artifactsDir,{recursive:true});
    const scanId=scan(database,"COMPLETED"),content=Buffer.from("recoverable"),artifactPath=join(paths.artifactsDir,"recoverable.txt");writeFileSync(artifactPath,content);
    const artifactId=new ArtifactRepository(database).create({scanId,type:"REPORT",name:"recoverable.txt",path:artifactPath,size:content.length,contentType:"text/plain",hash:sha(content)});
    const created=new EvidenceGovernanceService(database,paths,key).createExport([scanId],"owner") as any,exportPath=new EvidenceGovernanceService(database,paths,key).downloadableExport(created.id).path;
    database.db.prepare("UPDATE artifacts SET retention_state='PURGING' WHERE id=?").run(artifactId);rmSync(artifactPath);
    database.db.prepare("UPDATE evidence_exports SET status='PURGING' WHERE id=?").run(created.id);
    new EvidenceGovernanceService(database,paths,key);
    expect(database.db.prepare("SELECT retention_state state FROM artifacts WHERE id=?").get(artifactId)).toEqual({state:"PURGED"});
    expect(database.db.prepare("SELECT status FROM evidence_exports WHERE id=?").get(created.id)).toEqual({status:"READY"});
    database.db.prepare("UPDATE evidence_exports SET status='PURGING' WHERE id=?").run(created.id);rmSync(exportPath);
    new EvidenceGovernanceService(database,paths,key);
    expect(database.db.prepare("SELECT status,canonical_path path FROM evidence_exports WHERE id=?").get(created.id)).toEqual({status:"DELETED",path:null});
    database.close();
  });
});

function fixture(){const dir=mkdtempSync(join(tmpdir(),"routecairn-evidence-")),paths=resolveDashboardPaths(dir),database=new DashboardDatabase(paths.databasePath);database.migrate();return{database,paths,dir};}
function scan(database:DashboardDatabase,status:string){const id=randomUUID();new ScanRepository(database).create({id,source:"DASHBOARD",status:status as any,targetOrigin:"https://owned.example.test",safeTargetLabel:"owned",profile:"full",evidenceLevel:"strong",safeConfigurationSummary:{}});return id;}
function sha(value:Buffer){return createHash("sha256").update(value).digest("hex");}
