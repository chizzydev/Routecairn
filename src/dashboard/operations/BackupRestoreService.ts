import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { CredentialVaultKey } from "../credentials/CredentialVault.js";
import SqliteDatabase from "better-sqlite3";

export class BackupRestoreService {
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly key: CredentialVaultKey | undefined) {}

  public async create(encrypted: boolean, actor: string): Promise<string> {
    if (encrypted && !this.key) throw new Error("BACKUP_MASTER_KEY_REQUIRED");
    const id = randomUUID(); const createdAt = nowIso(); mkdirSync(this.paths.backupsDir, { recursive: true });
    this.database.db.prepare("INSERT INTO operational_backups (id,status,encrypted,key_version,created_by,created_at) VALUES (?, 'CREATING', ?, ?, ?, ?)").run(id, encrypted ? 1 : 0, encrypted ? this.key!.version : null, actor, createdAt);
    const snapshot = resolve(this.paths.backupsDir, `${id}.sqlite.tmp`); const bundlePath = resolve(this.paths.backupsDir, `${id}.rcbackup`);
    try {
      await this.database.db.backup(snapshot);
      const data = readFileSync(snapshot); if (!data.subarray(0, 16).equals(Buffer.from("SQLite format 3\0"))) throw new Error("BACKUP_SQLITE_HEADER_INVALID");
      const payload = encrypted ? encrypt(data, this.key!, id) : { algorithm: "none", keyVersion: null, nonce: null, authTag: null, ciphertext: data.toString("base64") };
      const manifest = { format: "routecairn-backup-v1", id, createdAt, schemaVersion: this.meta("schema_version"), installationId: this.meta("installation_id"), encrypted, payload };
      const serialized = JSON.stringify(manifest); const digest = createHash("sha256").update(serialized).digest("hex");
      writeFileSync(bundlePath, `${JSON.stringify({ ...manifest, digest })}\n`, { encoding: "utf8", mode: 0o600 });
      this.database.db.prepare("UPDATE operational_backups SET status='READY',path=?,manifest_digest=?,byte_size=? WHERE id=?").run(bundlePath, digest, statSync(bundlePath).size, id);
      return id;
    } catch (error) {
      this.database.db.prepare("UPDATE operational_backups SET status='FAILED',safe_error=? WHERE id=?").run(safeError(error), id); throw error;
    } finally { rmSync(snapshot, { force: true }); }
  }

  public verify(id: string): { id: string; valid: true; schemaVersion: string; encrypted: boolean } {
    const row = this.row(id); const bundle = parseBundle(row.path!); const digest = digestBundle(bundle);
    if (digest !== bundle.digest || digest !== row.manifest_digest!) throw new Error("BACKUP_DIGEST_REJECTED");
    const data = decryptPayload(bundle, this.key, id); if (!data.subarray(0, 16).equals(Buffer.from("SQLite format 3\0"))) throw new Error("BACKUP_SQLITE_HEADER_INVALID");
    this.database.db.prepare("UPDATE operational_backups SET status='VERIFIED',verified_at=?,safe_error=NULL WHERE id=?").run(nowIso(), id);
    return { id, valid: true, schemaVersion: bundle.schemaVersion, encrypted: bundle.encrypted };
  }

  public stageRestore(id: string): void {
    const verification = this.verify(id); const row = this.row(id);
    writeFileSync(this.paths.restoreMarkerPath, `${JSON.stringify({ format: "routecairn-restore-marker-v1", backupId: id, path: row.path!, digest: row.manifest_digest!, schemaVersion: verification.schemaVersion, stagedAt: nowIso() })}\n`, { encoding: "utf8", mode: 0o600 });
    this.database.db.prepare("UPDATE operational_backups SET status='RESTORE_STAGED',restore_staged_at=? WHERE id=?").run(nowIso(), id);
  }

  public list(): unknown[] { return this.database.db.prepare("SELECT id,status,manifest_digest AS manifestDigest,byte_size AS byteSize,encrypted,key_version AS keyVersion,safe_error AS safeError,created_by AS createdBy,created_at AS createdAt,verified_at AS verifiedAt,restore_staged_at AS restoreStagedAt FROM operational_backups ORDER BY created_at DESC LIMIT 100").all(); }
  private row(id: string): BackupRow { const row = this.database.db.prepare("SELECT * FROM operational_backups WHERE id=? AND status!='DELETED'").get(id) as BackupRow | undefined; if (!row?.path || !row.manifest_digest) throw new Error("BACKUP_NOT_FOUND"); return row; }
  private meta(key: string): string { const row = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as { value: string } | undefined; if (!row) throw new Error(`DASHBOARD_META_MISSING:${key}`); return row.value; }

  public static applyStagedRestore(paths: DashboardPaths, key: CredentialVaultKey | undefined): boolean {
    if (!existsSync(paths.restoreMarkerPath)) return false;
    const marker = JSON.parse(readFileSync(paths.restoreMarkerPath, "utf8")) as { format: string; backupId: string; path: string; digest: string };
    if (marker.format !== "routecairn-restore-marker-v1") throw new Error("RESTORE_MARKER_INVALID");
    const allowedRoot = resolve(paths.backupsDir); const bundlePath = resolve(marker.path); if (bundlePath !== allowedRoot && !bundlePath.startsWith(`${allowedRoot}\\`) && !bundlePath.startsWith(`${allowedRoot}/`)) throw new Error("RESTORE_PATH_REJECTED");
    const bundle = parseBundle(bundlePath); if (digestBundle(bundle) !== marker.digest || bundle.digest !== marker.digest || bundle.id !== marker.backupId) throw new Error("RESTORE_DIGEST_REJECTED");
    const data = decryptPayload(bundle, key, bundle.id); if (!data.subarray(0, 16).equals(Buffer.from("SQLite format 3\0"))) throw new Error("RESTORE_SQLITE_HEADER_INVALID");
    mkdirSync(dirname(paths.databasePath), { recursive: true }); const stamp = Date.now(); const candidate = `${paths.databasePath}.restore-${stamp}`; const previous = `${paths.databasePath}.pre-restore-${stamp}`; writeFileSync(candidate, data, { mode: 0o600 });
    let check: SqliteDatabase.Database | undefined;
    try {
      check = new SqliteDatabase(candidate, { fileMustExist: true });
      const rows = check.pragma("quick_check") as Array<Record<string, unknown>>;
      if (!rows.length || !rows.every((row) => Object.values(row).includes("ok"))) throw new Error("RESTORE_SQLITE_INTEGRITY_REJECTED");
      check.prepare("UPDATE operational_backups SET status='VERIFIED',path=?,manifest_digest=?,safe_error=NULL,verified_at=? WHERE id=?").run(bundlePath,marker.digest,nowIso(),bundle.id);
    } catch(error) { check?.close();check=undefined;rmSync(candidate,{force:true});throw error; } finally { check?.close(); }
    rmSync(`${paths.databasePath}-wal`, { force: true }); rmSync(`${paths.databasePath}-shm`, { force: true });
    const hadCurrent = existsSync(paths.databasePath);
    try {
      if (hadCurrent) renameSync(paths.databasePath, previous);
      renameSync(candidate, paths.databasePath);
    } catch (error) {
      if (hadCurrent && !existsSync(paths.databasePath) && existsSync(previous)) renameSync(previous, paths.databasePath);
      rmSync(candidate, { force: true }); throw error;
    }
    rmSync(paths.restoreMarkerPath, { force: true }); return true;
  }
}

interface BackupRow { id: string; path: string | null; manifest_digest: string | null }
interface Bundle { format: string; id: string; createdAt: string; schemaVersion: string; installationId: string; encrypted: boolean; payload: { algorithm: string; keyVersion: string | null; nonce: string | null; authTag: string | null; ciphertext: string }; digest: string }
function encrypt(data: Buffer, key: CredentialVaultKey, id: string) { const nonce = randomBytes(12); const cipher = createCipheriv("aes-256-gcm", key.bytes, nonce); cipher.setAAD(Buffer.from(`routecairn-backup-v1\0${id}\0${key.version}`)); const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]); return { algorithm: "aes-256-gcm", keyVersion: key.version, nonce: nonce.toString("base64"), authTag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") }; }
function decryptPayload(bundle: Bundle, key: CredentialVaultKey | undefined, id: string): Buffer { if (!bundle.encrypted) return Buffer.from(bundle.payload.ciphertext, "base64"); if (!key || key.version !== bundle.payload.keyVersion) throw new Error("BACKUP_KEY_UNAVAILABLE"); const decipher = createDecipheriv("aes-256-gcm", key.bytes, Buffer.from(bundle.payload.nonce!, "base64")); decipher.setAAD(Buffer.from(`routecairn-backup-v1\0${id}\0${key.version}`)); decipher.setAuthTag(Buffer.from(bundle.payload.authTag!, "base64")); return Buffer.concat([decipher.update(Buffer.from(bundle.payload.ciphertext, "base64")), decipher.final()]); }
function parseBundle(path: string): Bundle { const value = JSON.parse(readFileSync(path, "utf8")) as Bundle; if (value.format !== "routecairn-backup-v1" || !value.id || !value.digest) throw new Error("BACKUP_FORMAT_INVALID"); return value; }
function digestBundle(bundle: Bundle): string { const { digest: _digest, ...unsigned } = bundle; return createHash("sha256").update(JSON.stringify(unsigned)).digest("hex"); }
function safeError(error: unknown): string { return (error instanceof Error ? error.message : "BACKUP_FAILED").slice(0, 500); }
