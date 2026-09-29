import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { controlPlaneConfigFromEnv } from "../../src/controlPlane/ControlPlaneConfig.js";
import { LocalEvidenceObjectStore } from "../../src/controlPlane/ObjectStorage.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { RemoteWorkerService } from "../../src/dashboard/operations/RemoteWorkerService.js";

const directories:string[]=[];
afterEach(async()=>{await Promise.all(directories.splice(0).map((path)=>rm(path,{recursive:true,force:true})));});

describe("horizontal control-plane infrastructure",()=>{
  it("keeps the local deployment default and requires PostgreSQL in distributed mode",()=>{
    expect(controlPlaneConfigFromEnv({ ROUTECAIRN_INSTANCE_ID:"test-instance" })).toMatchObject({mode:"local",objectStorage:{kind:"local"}});
    expect(()=>controlPlaneConfigFromEnv({ROUTECAIRN_CONTROL_PLANE_MODE:"distributed",ROUTECAIRN_INSTANCE_ID:"test-instance"})).toThrow(/PostgreSQL/);
    expect(()=>controlPlaneConfigFromEnv({ROUTECAIRN_INSTANCE_ID:"test-instance",ROUTECAIRN_WORKLOAD_IDENTITY_REQUIRED:"true"})).toThrow(/trusted issuer/);
  });

  it("validates evidence size and digest before accepting local objects",async()=>{
    const directory=join(tmpdir(),`routecairn-object-${randomUUID()}`);directories.push(directory);await mkdir(directory,{recursive:true});const path=join(directory,"evidence.json");const body=Buffer.from('{"safe":true}\n');await writeFile(path,body);
    const store=new LocalEvidenceObjectStore();const item={artifactId:randomUUID(),organizationId:randomUUID(),path,sha256:createHash("sha256").update(body).digest("hex"),size:body.length,contentType:"application/json"};
    await expect(store.put(item)).resolves.toEqual({key:path});
    await expect(store.put({...item,sha256:"0".repeat(64)})).rejects.toThrow("EVIDENCE_OBJECT_DIGEST_MISMATCH");
  });

  it("binds local queue claims to both capabilities and network zones",()=>{
    const directory=join(tmpdir(),`routecairn-zone-${randomUUID()}`);directories.push(directory);const database=new DashboardDatabase(join(directory,"dashboard.sqlite"));database.migrate();
    try{
      const organization=(database.db.prepare("SELECT value FROM dashboard_meta WHERE key='default_organization_id'").get() as{value:string}).value;const service=new RemoteWorkerService(database);
      const enrollment=service.createEnrollment({organizationId:organization,expiresInMinutes:10},"operator");const pair=generateKeyPairSync("ed25519");
      const workerId=service.enroll({token:enrollment.token,name:"private worker",publicKeyPem:pair.publicKey.export({format:"pem",type:"spki"}).toString(),capabilities:["scan"],labels:{networkZone:"private-east"}}).workerId;
      service.enqueue({organizationId:organization,kind:"SCAN",payload:{case:"zone"},requiredCapabilities:[],networkZone:"public-west",priority:1,maxAttempts:2},"operator");
      const row=database.db.prepare("SELECT * FROM remote_workers WHERE id=?").get(workerId) as Parameters<RemoteWorkerService["claim"]>[0];expect(service.claim(row)).toEqual({job:null});
      service.enqueue({organizationId:organization,kind:"SCAN",payload:{case:"matching"},requiredCapabilities:[],networkZone:"private-east",priority:2,maxAttempts:2},"operator");
      expect(service.claim(row)).toMatchObject({job:{kind:"SCAN",payload:{case:"matching"}}});
    }finally{database.close();}
  });
});
