import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { CredentialVaultKey } from "../credentials/CredentialVault.js";
import { credentialVaultAlgorithm } from "../credentials/CredentialVault.js";
import { evidenceGovernancePolicySchema, type EvidenceGovernancePolicy } from "../contracts/ContinuousAssuranceSchemas.js";

const defaultPolicy: EvidenceGovernancePolicy = { retentionDays: 90, preserveFailedScans: true, preserveUnresolvedCleanup: true, preserveUnreviewedFindings: true, maximumExportBytes: 50 * 1024 * 1024 };

export class EvidenceGovernanceService {
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly key?: CredentialVaultKey) { this.recoverInterruptedPurges(); }

  public available(): boolean { return Boolean(this.key); }
  public policy(): EvidenceGovernancePolicy & { rowVersion: number; updatedAt?: string } {
    const row = this.database.db.prepare("SELECT * FROM evidence_governance_policy WHERE id=1").get() as GovernanceRow | undefined;
    return row ? { retentionDays: row.retention_days, preserveFailedScans: true, preserveUnresolvedCleanup: true, preserveUnreviewedFindings: true, maximumExportBytes: row.maximum_export_bytes, rowVersion: row.row_version, updatedAt: row.updated_at } : { ...defaultPolicy, rowVersion: 1 };
  }

  public updatePolicy(value: unknown, actor: string): ReturnType<EvidenceGovernanceService["policy"]> {
    const parsed = evidenceGovernancePolicySchema.parse(value);
    const current = this.database.db.prepare("SELECT row_version FROM evidence_governance_policy WHERE id=1").get() as { row_version: number } | undefined;
    if (current && current.row_version !== parsed.expectedVersion) throw new Error("EVIDENCE_GOVERNANCE_POLICY_CONFLICT");
    const now = nowIso();
    if (current) this.database.db.prepare("UPDATE evidence_governance_policy SET retention_days=?,preserve_failed_scans=?,preserve_unresolved_cleanup=?,preserve_unreviewed_findings=?,maximum_export_bytes=?,updated_by=?,updated_at=?,row_version=row_version+1 WHERE id=1")
      .run(parsed.retentionDays, flag(parsed.preserveFailedScans), flag(parsed.preserveUnresolvedCleanup), flag(parsed.preserveUnreviewedFindings), parsed.maximumExportBytes, actor, now);
    else this.database.db.prepare("INSERT INTO evidence_governance_policy (id,retention_days,preserve_failed_scans,preserve_unresolved_cleanup,preserve_unreviewed_findings,maximum_export_bytes,updated_by,updated_at) VALUES (1,?,?,?,?,?,?,?)")
      .run(parsed.retentionDays, flag(parsed.preserveFailedScans), flag(parsed.preserveUnresolvedCleanup), flag(parsed.preserveUnreviewedFindings), parsed.maximumExportBytes, actor, now);
    return this.policy();
  }

  public createExport(scanIds: readonly string[], actor: string): Record<string, unknown> {
    this.requireKey();
    const ids = [...new Set(scanIds)];
    if (ids.length < 1 || ids.length > 100) throw new Error("EVIDENCE_EXPORT_SCAN_COUNT_INVALID");
    const placeholders = ids.map(() => "?").join(",");
    const scans = this.database.db.prepare(`SELECT id,target_id,target_origin,profile,status,created_at,completed_at FROM scans WHERE id IN (${placeholders}) AND deleted_at IS NULL`).all(...ids) as ScanRow[];
    if (scans.length !== ids.length) throw new Error("EVIDENCE_EXPORT_SCAN_NOT_FOUND");
    const rows = this.database.db.prepare(`SELECT id,scan_id,artifact_type,safe_display_name,canonical_path,size,content_type,scoped_or_full_safe_hash,created_at FROM artifacts WHERE scan_id IN (${placeholders}) AND retention_state!='PURGED' ORDER BY scan_id,id`).all(...ids) as ArtifactRow[];
    const policy = this.policy();
    const files: Array<Record<string, unknown>> = [];
    let bytes = 0;
    for (const row of rows) {
      const path = this.safeArtifactPath(row.canonical_path);
      if (!existsSync(path) || !statSync(path).isFile()) throw new Error(`EVIDENCE_EXPORT_ARTIFACT_MISSING: ${row.id}`);
      const content = readFileSync(path);
      bytes += content.length;
      if (bytes > policy.maximumExportBytes) throw new Error("EVIDENCE_EXPORT_SIZE_LIMIT_EXCEEDED");
      const actualHash = sha256(content);
      if (row.scoped_or_full_safe_hash && /^[a-f0-9]{64}$/i.test(row.scoped_or_full_safe_hash) && row.scoped_or_full_safe_hash.toLowerCase() !== actualHash) throw new Error(`EVIDENCE_EXPORT_ARTIFACT_HASH_MISMATCH: ${row.id}`);
      files.push({ artifactId: row.id, scanId: row.scan_id, type: row.artifact_type, name: safeName(row.safe_display_name), contentType: row.content_type, size: content.length, sha256: actualHash, contentBase64: content.toString("base64") });
    }
    const id = randomUUID(); const createdAt = nowIso();
    const manifest = { schemaVersion: 1, exportId: id, installationId: this.installationId(), createdAt, scans: scans.map((scan) => ({ id: scan.id, targetId: scan.target_id, targetOrigin: scan.target_origin, profile: scan.profile, status: scan.status, createdAt: scan.created_at, completedAt: scan.completed_at })), files };
    const plaintext = Buffer.from(JSON.stringify(manifest));
    const manifestDigest = sha256(plaintext); const nonce = randomBytes(12); const aad = this.aad(id, this.key!.version);
    const cipher = createCipheriv(credentialVaultAlgorithm, this.key!.bytes, nonce); cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]); const authTag = cipher.getAuthTag();
    const signature = this.sign(id, this.key!.version, manifestDigest, nonce, authTag, ciphertext);
    const envelope = { schemaVersion: 1, exportId: id, algorithm: credentialVaultAlgorithm, keyVersion: this.key!.version, manifestDigest, nonce: nonce.toString("base64url"), authTag: authTag.toString("base64url"), ciphertext: ciphertext.toString("base64url"), signature };
    const output = resolve(this.paths.artifactsDir, "evidence-exports", `${id}.routecairn-evidence`); mkdirSync(dirname(output), { recursive: true });
    this.database.db.prepare("INSERT INTO evidence_exports (id,status,scan_count,algorithm,key_version,created_by,created_at) VALUES (?,'CREATING',?,?,?,?,?)").run(id, ids.length, credentialVaultAlgorithm, this.key!.version, actor, createdAt);
    try {
      writeFileSync(output, JSON.stringify(envelope), { encoding: "utf8", mode: 0o600, flag: "wx" });
      const size = statSync(output).size;
      this.database.transaction(() => {
        for (const scanId of ids) this.database.db.prepare("INSERT INTO evidence_export_scans (export_id,scan_id) VALUES (?,?)").run(id, scanId);
        this.database.db.prepare("UPDATE evidence_exports SET status='READY',artifact_count=?,plaintext_bytes=?,ciphertext_bytes=?,manifest_digest=?,signature=?,canonical_path=?,verified_at=? WHERE id=?")
          .run(files.length, plaintext.length, size, manifestDigest, signature, output, nowIso(), id);
      });
    } catch (error) {
      this.database.db.prepare("UPDATE evidence_exports SET status='FAILED',safe_error_summary=? WHERE id=?").run(safeError(error), id);
      throw error;
    }
    return this.exportSummary(id);
  }

  public verifyExport(id: string): Record<string, unknown> {
    this.requireKey(); const row = this.exportRow(id);
    if (row.status !== "READY" || !row.canonical_path) throw new Error("EVIDENCE_EXPORT_NOT_READY");
    const path = this.safeArtifactPath(row.canonical_path); const envelope = JSON.parse(readFileSync(path, "utf8")) as Envelope;
    if (envelope.exportId !== id || envelope.algorithm !== credentialVaultAlgorithm || envelope.keyVersion !== this.key!.version) throw new Error("EVIDENCE_EXPORT_BINDING_MISMATCH");
    const nonce = Buffer.from(envelope.nonce,"base64url"), tag = Buffer.from(envelope.authTag,"base64url"), ciphertext = Buffer.from(envelope.ciphertext,"base64url");
    const expected = this.sign(id,envelope.keyVersion,envelope.manifestDigest,nonce,tag,ciphertext);
    if (!constantEqual(expected,envelope.signature)) throw new Error("EVIDENCE_EXPORT_SIGNATURE_INVALID");
    const decipher = createDecipheriv(credentialVaultAlgorithm,this.key!.bytes,nonce); decipher.setAAD(this.aad(id,envelope.keyVersion)); decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext),decipher.final()]);
    if (sha256(plaintext) !== envelope.manifestDigest) throw new Error("EVIDENCE_EXPORT_MANIFEST_DIGEST_INVALID");
    const manifest = JSON.parse(plaintext.toString("utf8")) as { exportId: string; installationId: string; scans: unknown[]; files: Array<{ size: number; sha256: string; contentBase64: string }> };
    if (manifest.exportId !== id || manifest.installationId !== this.installationId()) throw new Error("EVIDENCE_EXPORT_INSTALLATION_MISMATCH");
    for (const file of manifest.files) { const content = Buffer.from(file.contentBase64,"base64"); if (content.length !== file.size || sha256(content) !== file.sha256) throw new Error("EVIDENCE_EXPORT_FILE_INTEGRITY_INVALID"); }
    this.database.db.prepare("UPDATE evidence_exports SET verified_at=? WHERE id=?").run(nowIso(),id);
    return { ...this.exportSummary(id), verified: true, scanCount: manifest.scans.length, artifactCount: manifest.files.length };
  }

  public listExports(): Record<string, unknown>[] { return (this.database.db.prepare("SELECT id FROM evidence_exports WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 100").all() as Array<{id:string}>).map((row) => this.exportSummary(row.id)); }

  public downloadableExport(id: string): { path: string; name: string; contentType: string } {
    const row = this.exportRow(id);
    if (row.status !== "READY" || !row.canonical_path) throw new Error("EVIDENCE_EXPORT_NOT_READY");
    const path = this.safeArtifactPath(row.canonical_path);
    if (!existsSync(path) || !statSync(path).isFile()) throw new Error("EVIDENCE_EXPORT_FILE_MISSING");
    return { path, name: `${id}.routecairn-evidence`, contentType: "application/vnd.routecairn.evidence+json" };
  }

  public purgePreview(): { previewDigest: string; cutoff: string; candidates: Array<{ kind:"ARTIFACT"|"EXPORT"; id: string; scanId?: string; name: string; size: number; createdAt: string }>; protectedCounts: Record<string, number> } {
    const policy = this.policy();
    const retentionBoundary = new Date();
    retentionBoundary.setUTCHours(0, 0, 0, 0);
    const cutoff = new Date(retentionBoundary.getTime() - policy.retentionDays * 86_400_000).toISOString();
    const rows = this.database.db.prepare("SELECT a.id,a.scan_id,a.safe_display_name,a.size,a.created_at,s.status scan_status FROM artifacts a LEFT JOIN scans s ON s.id=a.scan_id WHERE a.retention_state!='PURGED' AND a.created_at<? ORDER BY a.created_at,a.id LIMIT 5000").all(cutoff) as Array<{id:string;scan_id:string|null;safe_display_name:string;size:number;created_at:string;scan_status:string|null}>;
    const protectedCounts = { failed: 0, cleanup: 0, review: 0 }; const candidates: ReturnType<EvidenceGovernanceService["purgePreview"]>["candidates"] = [];
    for (const row of rows) {
      if (policy.preserveFailedScans && row.scan_status && ["FAILED","INTERRUPTED","CANCELLED"].includes(row.scan_status)) { protectedCounts.failed++; continue; }
      if (policy.preserveUnresolvedCleanup && row.scan_id && this.hasUnresolvedCleanup(row.scan_id)) { protectedCounts.cleanup++; continue; }
      if (policy.preserveUnreviewedFindings && row.scan_id && this.hasUnreviewedFinding(row.scan_id)) { protectedCounts.review++; continue; }
      candidates.push({ kind:"ARTIFACT", id: row.id, ...(row.scan_id ? { scanId: row.scan_id } : {}), name: safeName(row.safe_display_name), size: row.size, createdAt: row.created_at });
    }
    const exports=this.database.db.prepare("SELECT id,canonical_path,ciphertext_bytes,created_at FROM evidence_exports WHERE status='READY' AND deleted_at IS NULL AND created_at<? ORDER BY created_at,id LIMIT 1000").all(cutoff) as Array<{id:string;canonical_path:string|null;ciphertext_bytes:number;created_at:string}>;
    for(const item of exports){const linked=this.database.db.prepare("SELECT s.id,s.status FROM evidence_export_scans x JOIN scans s ON s.id=x.scan_id WHERE x.export_id=?").all(item.id) as Array<{id:string;status:string}>;if(policy.preserveFailedScans&&linked.some(s=>["FAILED","INTERRUPTED","CANCELLED"].includes(s.status))){protectedCounts.failed++;continue;}if(policy.preserveUnresolvedCleanup&&linked.some(s=>this.hasUnresolvedCleanup(s.id))){protectedCounts.cleanup++;continue;}if(policy.preserveUnreviewedFindings&&linked.some(s=>this.hasUnreviewedFinding(s.id))){protectedCounts.review++;continue;}candidates.push({kind:"EXPORT",id:item.id,name:`${item.id}.routecairn-evidence`,size:item.ciphertext_bytes,createdAt:item.created_at});}
    return { previewDigest: digest({ cutoff, policy: { ...policy, rowVersion: undefined, updatedAt: undefined }, candidates: candidates.map(({kind,id,size}) => ({kind,id,size})) }), cutoff, candidates, protectedCounts };
  }

  public purge(previewDigest: string, actor: string): Record<string, unknown> {
    const preview = this.purgePreview(); if (preview.previewDigest !== previewDigest) throw new Error("EVIDENCE_PURGE_PREVIEW_STALE");
    let purged = 0, reclaimed = 0; const failures: string[] = [];
    for (const candidate of preview.candidates) {
      let path: string | undefined;
      try {
        if(candidate.kind==="EXPORT"){
          const row=this.database.db.prepare("SELECT canonical_path FROM evidence_exports WHERE id=? AND status='READY' AND deleted_at IS NULL").get(candidate.id) as {canonical_path:string|null}|undefined;
          if(!row?.canonical_path)continue;
          path=this.safeArtifactPath(row.canonical_path);
          if(this.database.db.prepare("UPDATE evidence_exports SET status='PURGING' WHERE id=? AND status='READY' AND deleted_at IS NULL").run(candidate.id).changes!==1)continue;
          if(existsSync(path))rmSync(path,{force:false});
          this.database.db.prepare("UPDATE evidence_exports SET status='DELETED',deleted_at=?,canonical_path=NULL WHERE id=? AND status='PURGING'").run(nowIso(),candidate.id);
        }else{
          const row = this.database.db.prepare("SELECT canonical_path FROM artifacts WHERE id=? AND retention_state='RETAIN'").get(candidate.id) as { canonical_path: string } | undefined;
          if (!row) continue;
          path=this.safeArtifactPath(row.canonical_path);
          if(this.database.db.prepare("UPDATE artifacts SET retention_state='PURGING' WHERE id=? AND retention_state='RETAIN'").run(candidate.id).changes!==1)continue;
          if (existsSync(path)) rmSync(path,{force:false});
          this.database.db.prepare("UPDATE artifacts SET retention_state='PURGED',missing_file_flag=1 WHERE id=? AND retention_state='PURGING'").run(candidate.id);
        }
        purged++; reclaimed += candidate.size;
      } catch (error) {
        const fileWasRemoved=Boolean(path&&!existsSync(path));
        if(candidate.kind==="EXPORT")this.database.db.prepare("UPDATE evidence_exports SET status=?,deleted_at=?,canonical_path=? WHERE id=? AND status='PURGING'").run(fileWasRemoved?"DELETED":"READY",fileWasRemoved?nowIso():null,fileWasRemoved?null:path,candidate.id);
        else this.database.db.prepare("UPDATE artifacts SET retention_state=?,missing_file_flag=? WHERE id=? AND retention_state='PURGING'").run(fileWasRemoved?"PURGED":"RETAIN",fileWasRemoved?1:0,candidate.id);
        failures.push(`${candidate.id}: ${safeError(error)}`);
      }
    }
    const id=randomUUID(); this.database.db.prepare("INSERT INTO evidence_purge_actions (id,preview_digest,candidate_count,purged_count,failed_count,reclaimed_bytes,safe_failures_json,executed_by,created_at) VALUES (?,?,?,?,?,?,?,?,?)").run(id,previewDigest,preview.candidates.length,purged,failures.length,reclaimed,JSON.stringify(failures),actor,nowIso());
    return { id, previewDigest, candidateCount: preview.candidates.length, purgedCount: purged, failedCount: failures.length, reclaimedBytes: reclaimed, failures };
  }

  private hasUnresolvedCleanup(scanId:string):boolean { return Boolean(this.database.db.prepare("SELECT 1 FROM assisted_case_results WHERE scan_id=? AND cleanup_unresolved=1 LIMIT 1").get(scanId) || this.database.db.prepare("SELECT 1 FROM controlled_mutation_approvals WHERE execution_scan_id=? AND status IN ('EXECUTING','CLEANUP_REQUIRED','CLEANUP_FAILED') LIMIT 1").get(scanId)); }
  private recoverInterruptedPurges():void {
    const exports=this.database.db.prepare("SELECT id,canonical_path FROM evidence_exports WHERE status='PURGING'").all() as Array<{id:string;canonical_path:string|null}>;
    for(const row of exports){let present=true;try{present=Boolean(row.canonical_path&&existsSync(this.safeArtifactPath(row.canonical_path)));}catch{present=true;}this.database.db.prepare("UPDATE evidence_exports SET status=?,deleted_at=?,canonical_path=? WHERE id=? AND status='PURGING'").run(present?"READY":"DELETED",present?null:nowIso(),present?row.canonical_path:null,row.id);}
    const artifacts=this.database.db.prepare("SELECT id,canonical_path FROM artifacts WHERE retention_state='PURGING'").all() as Array<{id:string;canonical_path:string}>;
    for(const row of artifacts){let present=true;try{present=existsSync(this.safeArtifactPath(row.canonical_path));}catch{present=true;}this.database.db.prepare("UPDATE artifacts SET retention_state=?,missing_file_flag=? WHERE id=? AND retention_state='PURGING'").run(present?"RETAIN":"PURGED",present?0:1,row.id);}
  }
  private hasUnreviewedFinding(scanId:string):boolean { return Boolean(this.database.db.prepare("SELECT 1 FROM finding_occurrences o JOIN findings f ON f.id=o.finding_id WHERE o.scan_id=? AND f.human_review_status='UNREVIEWED' LIMIT 1").get(scanId)); }
  private safeArtifactPath(value:string):string { const candidate=canonicalPath(value); const roots=[this.paths.reportsDir,this.paths.proofPacksDir,this.paths.artifactsDir].map(canonicalPath); if(!roots.some((root)=>candidate===root||candidate.startsWith(`${root}\\`)||candidate.startsWith(`${root}/`))) throw new Error("EVIDENCE_PATH_OUTSIDE_DASHBOARD_ROOTS"); return candidate; }
  private installationId():string { return (this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'").get() as {value:string}).value; }
  private aad(id:string,keyVersion:string):Buffer { return Buffer.from(JSON.stringify({purpose:"routecairn-evidence-export",installationId:this.installationId(),exportId:id,keyVersion})); }
  private sign(id:string,keyVersion:string,manifestDigest:string,nonce:Buffer,tag:Buffer,ciphertext:Buffer):string { return createHmac("sha256",evidenceSigningKey(this.key!)).update("routecairn-evidence-signature-v1\0").update(id).update("\0").update(keyVersion).update("\0").update(manifestDigest).update(nonce).update(tag).update(ciphertext).digest("hex"); }
  private exportRow(id:string):ExportRow { const row=this.database.db.prepare("SELECT * FROM evidence_exports WHERE id=? AND deleted_at IS NULL").get(id) as ExportRow|undefined; if(!row)throw new Error("EVIDENCE_EXPORT_NOT_FOUND"); return row; }
  private exportSummary(id:string):Record<string,unknown>{const row=this.exportRow(id);return{id:row.id,status:row.status,scanCount:row.scan_count,artifactCount:row.artifact_count,plaintextBytes:row.plaintext_bytes,ciphertextBytes:row.ciphertext_bytes,manifestDigest:row.manifest_digest,signature:row.signature,keyVersion:row.key_version,artifactAvailable:Boolean(row.canonical_path&&existsSync(row.canonical_path)),createdAt:row.created_at,verifiedAt:row.verified_at,safeErrorSummary:row.safe_error_summary};}
  private requireKey():void{if(!this.key)throw new Error("EVIDENCE_GOVERNANCE_MASTER_KEY_REQUIRED");}
}

/** Offline rotation for encrypted evidence bundles. Call while the dashboard is stopped. */
export function rotateEvidenceExportKey(database: DashboardDatabase, paths: DashboardPaths, currentKey: CredentialVaultKey, nextKey: CredentialVaultKey): number {
  const installationId=(database.db.prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'").get() as {value:string}).value;
  const rows=database.db.prepare("SELECT id,canonical_path FROM evidence_exports WHERE status='READY' AND deleted_at IS NULL ORDER BY id").all() as Array<{id:string;canonical_path:string}>;
  const prepared:Array<{id:string;path:string;serialized:string;signature:string}>=[];
  for(const row of rows){
    const root=existsSync(paths.artifactsDir)?realpathSync(paths.artifactsDir):resolve(paths.artifactsDir),path=existsSync(resolve(row.canonical_path))?realpathSync(resolve(row.canonical_path)):resolve(row.canonical_path);
    if(!(path===root||path.startsWith(`${root}\\`)||path.startsWith(`${root}/`)))throw new Error(`Evidence export ${row.id} is outside the dashboard artifact root.`);
    const envelope=JSON.parse(readFileSync(path,"utf8")) as Envelope;if(envelope.exportId!==row.id||envelope.algorithm!==credentialVaultAlgorithm||envelope.keyVersion!==currentKey.version)throw new Error(`Evidence export ${row.id} is not bound to the current key version.`);
    const aad=(version:string)=>Buffer.from(JSON.stringify({purpose:"routecairn-evidence-export",installationId,exportId:row.id,keyVersion:version}));
    const sign=(key:CredentialVaultKey,version:string,n:Buffer,t:Buffer,c:Buffer)=>createHmac("sha256",evidenceSigningKey(key)).update("routecairn-evidence-signature-v1\0").update(row.id).update("\0").update(version).update("\0").update(envelope.manifestDigest).update(n).update(t).update(c).digest("hex");
    const nonce=Buffer.from(envelope.nonce,"base64url"),tag=Buffer.from(envelope.authTag,"base64url"),ciphertext=Buffer.from(envelope.ciphertext,"base64url");if(!constantEqual(sign(currentKey,currentKey.version,nonce,tag,ciphertext),envelope.signature))throw new Error(`Evidence export ${row.id} signature is invalid.`);
    const decipher=createDecipheriv(credentialVaultAlgorithm,currentKey.bytes,nonce);decipher.setAAD(aad(currentKey.version));decipher.setAuthTag(tag);const plaintext=Buffer.concat([decipher.update(ciphertext),decipher.final()]);if(sha256(plaintext)!==envelope.manifestDigest)throw new Error(`Evidence export ${row.id} manifest digest is invalid.`);
    const nextNonce=randomBytes(12),cipher=createCipheriv(credentialVaultAlgorithm,nextKey.bytes,nextNonce);cipher.setAAD(aad(nextKey.version));const nextCiphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]),nextTag=cipher.getAuthTag(),signature=sign(nextKey,nextKey.version,nextNonce,nextTag,nextCiphertext);prepared.push({id:row.id,path,signature,serialized:JSON.stringify({...envelope,keyVersion:nextKey.version,nonce:nextNonce.toString("base64url"),authTag:nextTag.toString("base64url"),ciphertext:nextCiphertext.toString("base64url"),signature})});
  }
  const replaced:Array<{path:string;backup:string}>=[];try{for(const item of prepared){const temp=`${item.path}.rotation-${randomUUID()}.tmp`,backup=`${item.path}.rotation-backup`;if(existsSync(backup))throw new Error(`Stale evidence rotation backup exists for ${item.id}.`);writeFileSync(temp,item.serialized,{encoding:"utf8",mode:0o600,flag:"wx"});renameSync(item.path,backup);try{renameSync(temp,item.path);}catch(error){renameSync(backup,item.path);rmSync(temp,{force:true});throw error;}replaced.push({path:item.path,backup});}database.transaction(()=>{for(const item of prepared)database.db.prepare("UPDATE evidence_exports SET key_version=?,signature=?,verified_at=NULL WHERE id=?").run(nextKey.version,item.signature,item.id);});for(const item of replaced)rmSync(item.backup,{force:true});}catch(error){for(const item of [...replaced].reverse())if(existsSync(item.backup)){rmSync(item.path,{force:true});renameSync(item.backup,item.path);}throw error;}return rows.length;
}

function evidenceSigningKey(key:CredentialVaultKey):Buffer{return createHmac("sha256",key.bytes).update("routecairn-evidence-signing-key-v1").digest();} function flag(value:boolean):number{return value?1:0;} function sha256(value:Buffer|string):string{return createHash("sha256").update(value).digest("hex");} function digest(value:unknown):string{return sha256(JSON.stringify(sort(value)));} function sort(value:unknown):unknown{if(Array.isArray(value))return value.map(sort);if(!value||typeof value!=="object")return value;return Object.fromEntries(Object.entries(value as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,sort(v)]));} function safeName(value:string):string{return value.replace(/[\r\n\0"\\/]/g,"-").slice(0,200);} function safeError(error:unknown):string{return clamp(error instanceof Error?error.message:"Evidence operation failed.",800);} function constantEqual(a:string,b:string):boolean{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);}
function canonicalPath(value:string):string{const suffix:string[]=[];let cursor=resolve(value);while(!existsSync(cursor)){const parent=dirname(cursor);if(parent===cursor)return resolve(value);suffix.unshift(basename(cursor));cursor=parent;}return resolve(realpathSync(cursor),...suffix);}
interface GovernanceRow{retention_days:number;preserve_failed_scans:number;preserve_unresolved_cleanup:number;preserve_unreviewed_findings:number;maximum_export_bytes:number;updated_at:string;row_version:number}
interface ScanRow{id:string;target_id:string|null;target_origin:string;profile:string;status:string;created_at:string;completed_at:string|null}
interface ArtifactRow{id:string;scan_id:string;artifact_type:string;safe_display_name:string;canonical_path:string;size:number;content_type:string;scoped_or_full_safe_hash:string;created_at:string}
interface ExportRow{id:string;status:string;scan_count:number;artifact_count:number;plaintext_bytes:number;ciphertext_bytes:number;manifest_digest:string|null;signature:string|null;key_version:string;canonical_path:string|null;safe_error_summary:string|null;created_at:string;verified_at:string|null}
interface Envelope{schemaVersion:number;exportId:string;algorithm:string;keyVersion:string;manifestDigest:string;nonce:string;authTag:string;ciphertext:string;signature:string}
