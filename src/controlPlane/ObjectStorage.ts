import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, rm, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { createHash, randomBytes } from "node:crypto";
import { GetObjectCommand, HeadBucketCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import type { ControlPlaneConfig } from "./ControlPlaneConfig.js";
import type { PostgresControlPlane } from "./PostgresControlPlane.js";

export interface EvidenceObject {
  artifactId: string; organizationId: string; path: string; sha256: string; size: number; contentType: string;
}

export interface EvidenceObjectStore {
  readonly kind: "local" | "s3";
  put(item: EvidenceObject): Promise<{ key: string }>;
  materialize(item: EvidenceObject, cacheDirectory: string): Promise<string>;
  lookup(artifactId: string, organizationId: string): Promise<(EvidenceObject & { name: string }) | undefined>;
  ready(): Promise<boolean>;
  shutdown(): Promise<void>;
}

export class LocalEvidenceObjectStore implements EvidenceObjectStore {
  public readonly kind = "local" as const;
  public async put(item: EvidenceObject): Promise<{ key: string }> { await verifyFile(item.path, item.size, item.sha256); return { key: item.path }; }
  public async materialize(item: EvidenceObject): Promise<string> { await verifyFile(item.path, item.size, item.sha256); return item.path; }
  public async lookup(): Promise<undefined> { return undefined; }
  public async ready(): Promise<boolean> { return true; }
  public async shutdown(): Promise<void> { return Promise.resolve(); }
}

export class S3EvidenceObjectStore implements EvidenceObjectStore {
  public readonly kind = "s3" as const;
  private readonly client: S3Client;
  public constructor(private readonly config: Extract<ControlPlaneConfig["objectStorage"], { kind: "s3" }>, private readonly database: PostgresControlPlane) {
    this.client = new S3Client({ region: config.region, forcePathStyle: config.forcePathStyle, ...(config.endpoint ? { endpoint: config.endpoint } : {}), ...(config.accessKeyId && config.secretAccessKey ? { credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey } } : {}) });
  }
  public async put(item: EvidenceObject): Promise<{ key: string }> {
    await verifyFile(item.path, item.size, item.sha256);
    const key = objectKey(this.config.prefix, item);
    await this.database.pool.query(`INSERT INTO routecairn_control.object_records(object_key,organization_id,artifact_id,sha256,size,content_type,state)
      VALUES($1,$2,$3,$4,$5,$6,'UPLOADING') ON CONFLICT(artifact_id) DO UPDATE SET state='UPLOADING'`, [key, item.organizationId, item.artifactId, item.sha256, item.size, item.contentType]);
    try{
      await this.client.send(new PutObjectCommand({ Bucket: this.config.bucket, Key: key, Body: createReadStream(item.path), ContentLength: item.size,
        ContentType: item.contentType, Metadata: { sha256: item.sha256, artifactid: item.artifactId, organizationid: item.organizationId },
        ...(this.config.kmsKeyId ? { ServerSideEncryption: "aws:kms", SSEKMSKeyId: this.config.kmsKeyId, BucketKeyEnabled: true } : { ServerSideEncryption: "AES256" }) }));
      await this.database.pool.query("UPDATE routecairn_control.object_records SET state='STORED',stored_at=clock_timestamp() WHERE artifact_id=$1 AND sha256=$2", [item.artifactId, item.sha256]);
      return { key };
    }catch(error){await this.database.pool.query("UPDATE routecairn_control.object_records SET state='FAILED' WHERE artifact_id=$1",[item.artifactId]).catch(()=>undefined);throw error;}
  }
  public async materialize(item: EvidenceObject, cacheDirectory: string): Promise<string> {
    try { await verifyFile(item.path, item.size, item.sha256); return item.path; } catch { /* retrieve below */ }
    const key = objectKey(this.config.prefix, item);
    const row = await this.database.pool.query<{ state: string }>("SELECT state FROM routecairn_control.object_records WHERE artifact_id=$1 AND object_key=$2 AND sha256=$3", [item.artifactId, key, item.sha256]);
    if (row.rows[0]?.state !== "STORED") throw new Error("EVIDENCE_OBJECT_UNAVAILABLE");
    const destination = resolve(cacheDirectory, item.organizationId, item.artifactId, item.sha256);
    try{await verifyFile(destination,item.size,item.sha256);return destination;}catch{/* populate cache */}
    await mkdir(dirname(destination), { recursive: true });
    const temporary = `${destination}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      const response = await this.client.send(new GetObjectCommand({ Bucket: this.config.bucket, Key: key, ChecksumMode: "ENABLED" }));
      if (!response.Body) throw new Error("EVIDENCE_OBJECT_EMPTY");
      await pipeline(response.Body.transformToWebStream(), createWriteStream(temporary, { flags: "wx", mode: 0o600 }));
      await verifyFile(temporary, item.size, item.sha256);try{await rename(temporary,destination);}catch(error){try{await verifyFile(destination,item.size,item.sha256);return destination;}catch{throw error;}}return destination;
    } finally { await rm(temporary, { force: true }); }
  }
  public async lookup(artifactId: string, organizationId: string): Promise<(EvidenceObject & { name: string }) | undefined> {
    if (!/^[0-9a-f-]{36}$/i.test(artifactId) || !/^[0-9a-f-]{36}$/i.test(organizationId)) return undefined;
    const result=await this.database.pool.query<{sha256:string;size:string;content_type:string}>("SELECT sha256,size,content_type FROM routecairn_control.object_records WHERE artifact_id=$1 AND organization_id=$2 AND state='STORED'",[artifactId,organizationId]);
    const row=result.rows[0];if(!row)return undefined;return{artifactId,organizationId,path:"",sha256:row.sha256,size:Number(row.size),contentType:row.content_type,name:`evidence-${artifactId}`};
  }
  public async ready(): Promise<boolean> {
    try { await this.client.send(new HeadBucketCommand({ Bucket: this.config.bucket })); return true; }
    catch { return false; }
  }
  public async shutdown(): Promise<void> { this.client.destroy(); }
}

export function createEvidenceObjectStore(config: ControlPlaneConfig, database?: PostgresControlPlane): EvidenceObjectStore {
  if (config.objectStorage.kind === "local") return new LocalEvidenceObjectStore();
  if (!database) throw new Error("S3 evidence storage requires distributed PostgreSQL metadata.");
  return new S3EvidenceObjectStore(config.objectStorage, database);
}

async function verifyFile(path: string, expectedSize: number, expectedHash: string): Promise<void> {
  const info = await stat(path); if (!info.isFile() || info.size !== expectedSize) throw new Error("EVIDENCE_OBJECT_SIZE_MISMATCH");
  const hash=createHash("sha256");for await(const chunk of createReadStream(path))hash.update(chunk as Buffer);const actual=hash.digest("hex");
  if (actual !== expectedHash) throw new Error("EVIDENCE_OBJECT_DIGEST_MISMATCH");
}
function objectKey(prefix: string, item: EvidenceObject): string {
  if (!/^[0-9a-f-]{36}$/i.test(item.organizationId) || !/^[0-9a-f-]{36}$/i.test(item.artifactId) || !/^[0-9a-f]{64}$/i.test(item.sha256)) throw new Error("EVIDENCE_OBJECT_IDENTITY_INVALID");
  return `${prefix.replace(/^\/+|\/+$/g, "")}/${item.organizationId}/evidence/${item.artifactId}/${item.sha256}`;
}
