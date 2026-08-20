import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";

export const credentialVaultAlgorithm = "aes-256-gcm";

export interface CredentialVaultKey {
  bytes: Buffer;
  version: string;
}

export interface CredentialVaultStatus {
  enabled: boolean;
  algorithm: typeof credentialVaultAlgorithm;
  keyVersion?: string;
  reason?: string;
}

export interface CredentialProfileSecret {
  authorizationHeader?: string | undefined;
  cookies?: Record<string, string> | undefined;
  headers?: Record<string, string> | undefined;
  csrfToken?: string | undefined;
  tenantHeader?: string | undefined;
  sessionHeader?: string | undefined;
  identityVerification?: {
    endpoint: string;
    principalFieldPath?: string | undefined;
    tenantFieldPath?: string | undefined;
    roleFieldPath?: string | undefined;
    accountStateFieldPath?: string | undefined;
  } | undefined;
}

export interface CredentialProfileInput {
  name: string;
  description?: string | undefined;
  safeAlias: string;
  projectId?: string | undefined;
  targetId?: string | undefined;
  expiresAt?: string | undefined;
  safeIdentitySummary: Record<string, unknown>;
  secret: CredentialProfileSecret;
  createdByUserId?: string | undefined;
}

export interface CredentialProfileSummary {
  id: string;
  name: string;
  description?: string;
  safeAlias: string;
  enabled: boolean;
  projectId?: string;
  targetId?: string;
  credentialTypeSummary: string;
  safeIdentitySummary: Record<string, unknown>;
  expiresAt?: string;
  lastUsedAt?: string;
  keyVersion: string;
  createdAt: string;
  updatedAt: string;
}

export class CredentialVault {
  public constructor(private readonly database: DashboardDatabase, private readonly key: CredentialVaultKey | undefined) {}

  public status(): CredentialVaultStatus {
    if (!this.key) return { enabled: false, algorithm: credentialVaultAlgorithm, reason: "ROUTECAIRN_MASTER_KEY is not configured." };
    return { enabled: true, algorithm: credentialVaultAlgorithm, keyVersion: this.key.version };
  }

  public create(input: CredentialProfileInput): string {
    this.requireEnabled();
    validateSecret(input.secret);
    const id = randomUUID();
    const now = nowIso();
    const encrypted = this.encrypt(id, input.secret);
    this.database.db
      .prepare(
        `INSERT INTO credential_profiles (id, name, description, safe_alias, enabled, project_id, target_id, credential_type_summary, safe_identity_summary_json, expires_at, created_by_user_id, created_at, updated_at, algorithm, key_version, nonce, ciphertext, auth_tag)
         VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        clamp(input.name, 160),
        input.description ? clamp(input.description, 2000) : null,
        clamp(input.safeAlias, 160),
        input.projectId ?? null,
        input.targetId ?? null,
        credentialTypeSummary(input.secret),
        JSON.stringify(input.safeIdentitySummary),
        input.expiresAt ?? null,
        input.createdByUserId ?? null,
        now,
        now,
        credentialVaultAlgorithm,
        this.key!.version,
        encrypted.nonce,
        encrypted.ciphertext,
        encrypted.authTag
      );
    return id;
  }

  public update(id: string, input: CredentialProfileInput): void {
    this.requireEnabled();
    validateSecret(input.secret);
    const encrypted = this.encrypt(id, input.secret);
    this.database.db
      .prepare(
        `UPDATE credential_profiles
         SET name = ?, description = ?, safe_alias = ?, project_id = ?, target_id = ?, credential_type_summary = ?, safe_identity_summary_json = ?, expires_at = ?, updated_at = ?, algorithm = ?, key_version = ?, nonce = ?, ciphertext = ?, auth_tag = ?
         WHERE id = ? AND deleted_at IS NULL`
      )
      .run(
        clamp(input.name, 160),
        input.description ? clamp(input.description, 2000) : null,
        clamp(input.safeAlias, 160),
        input.projectId ?? null,
        input.targetId ?? null,
        credentialTypeSummary(input.secret),
        JSON.stringify(input.safeIdentitySummary),
        input.expiresAt ?? null,
        nowIso(),
        credentialVaultAlgorithm,
        this.key!.version,
        encrypted.nonce,
        encrypted.ciphertext,
        encrypted.authTag,
        id
      );
  }

  public updateMetadata(id: string, input: Omit<CredentialProfileInput, "secret" | "createdByUserId">): void {
    const result = this.database.db.prepare(`UPDATE credential_profiles SET name = ?, description = ?, safe_alias = ?, project_id = ?, target_id = ?, safe_identity_summary_json = ?, expires_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`)
      .run(clamp(input.name, 160), input.description ? clamp(input.description, 2000) : null, clamp(input.safeAlias, 160), input.projectId ?? null, input.targetId ?? null, JSON.stringify(input.safeIdentitySummary), input.expiresAt ?? null, nowIso(), id);
    if (result.changes !== 1) throw new Error("Credential profile not found.");
  }

  public replaceSecret(id: string, secret: CredentialProfileSecret): void {
    this.requireEnabled(); validateSecret(secret);
    const encrypted = this.encrypt(id, secret);
    const result = this.database.db.prepare(`UPDATE credential_profiles SET credential_type_summary = ?, algorithm = ?, key_version = ?, nonce = ?, ciphertext = ?, auth_tag = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`)
      .run(credentialTypeSummary(secret), credentialVaultAlgorithm, this.key!.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, nowIso(), id);
    if (result.changes !== 1) throw new Error("Credential profile not found.");
  }

  public dependencies(id: string): { targetDefaults: number; configurationReferences: number; activeScans: number; canDelete: boolean } {
    const targetDefaults = (this.database.db.prepare("SELECT COUNT(*) AS count FROM targets WHERE default_credential_profile_id = ? AND archived_at IS NULL").get(id) as { count: number }).count;
    const configurationReferences = (this.database.db.prepare("SELECT COUNT(*) AS count FROM saved_scan_configuration_versions WHERE snapshot_json LIKE ?").get(`%${id}%`) as { count: number }).count;
    const activeScans = (this.database.db.prepare("SELECT COUNT(*) AS count FROM scans JOIN scan_plan_snapshots ON scan_plan_snapshots.scan_id = scans.id WHERE scans.status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED') AND scan_plan_snapshots.authentication_summary_json LIKE ?").get(`%${id}%`) as { count: number }).count;
    return { targetDefaults, configurationReferences, activeScans, canDelete: targetDefaults + configurationReferences + activeScans === 0 };
  }

  public list(): CredentialProfileSummary[] {
    const rows = this.database.db.prepare("SELECT * FROM credential_profiles WHERE deleted_at IS NULL ORDER BY updated_at DESC LIMIT 200").all() as CredentialProfileRow[];
    return rows.map(summaryFromRow);
  }

  public getSummary(id: string): CredentialProfileSummary | undefined {
    const row = this.database.db.prepare("SELECT * FROM credential_profiles WHERE id = ? AND deleted_at IS NULL").get(id) as CredentialProfileRow | undefined;
    return row ? summaryFromRow(row) : undefined;
  }

  public decryptForUse(id: string): CredentialProfileSecret {
    this.requireEnabled();
    const row = this.database.db.prepare("SELECT * FROM credential_profiles WHERE id = ? AND enabled = 1 AND deleted_at IS NULL").get(id) as CredentialProfileRow | undefined;
    if (!row) throw new Error("Credential profile unavailable.");
    if (row.algorithm !== credentialVaultAlgorithm) throw new Error("Unsupported credential profile algorithm.");
    const decipher = createDecipheriv(credentialVaultAlgorithm, this.key!.bytes, Buffer.from(row.nonce, "base64url"));
    decipher.setAAD(this.associatedData(row.id, row.key_version));
    decipher.setAuthTag(Buffer.from(row.auth_tag, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(row.ciphertext, "base64url")), decipher.final()]).toString("utf8");
    this.database.db.prepare("UPDATE credential_profiles SET last_used_at = ? WHERE id = ?").run(nowIso(), id);
    return JSON.parse(plaintext) as CredentialProfileSecret;
  }

  public setEnabled(id: string, enabled: boolean): void {
    this.database.db.prepare("UPDATE credential_profiles SET enabled = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL").run(enabled ? 1 : 0, nowIso(), id);
  }

  public delete(id: string): void {
    const dependencies = this.dependencies(id);
    if (!dependencies.canDelete) throw new Error(`CREDENTIAL_IN_USE: Remove ${dependencies.targetDefaults + dependencies.configurationReferences + dependencies.activeScans} dependency reference(s) before deletion.`);
    this.database.db.prepare("UPDATE credential_profiles SET deleted_at = ?, enabled = 0, updated_at = ? WHERE id = ?").run(nowIso(), nowIso(), id);
  }

  public rotateKey(nextKey: CredentialVaultKey): number {
    this.requireEnabled();
    const rows = this.database.db.prepare("SELECT id FROM credential_profiles WHERE deleted_at IS NULL").all() as Array<{ id: string }>;
    let rotated = 0;
    this.database.transaction(() => {
      for (const row of rows) {
        const secret = this.decryptForUse(row.id);
        const encrypted = encryptWithKey(this.database, nextKey, row.id, secret);
        this.database.db
          .prepare("UPDATE credential_profiles SET algorithm = ?, key_version = ?, nonce = ?, ciphertext = ?, auth_tag = ?, updated_at = ? WHERE id = ?")
          .run(credentialVaultAlgorithm, nextKey.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, nowIso(), row.id);
        rotated += 1;
      }
    });
    return rotated;
  }

  private encrypt(id: string, secret: CredentialProfileSecret): { nonce: string; ciphertext: string; authTag: string } {
    return encryptWithKey(this.database, this.key!, id, secret);
  }

  private associatedData(id: string, keyVersion: string): Buffer {
    return associatedData(this.database, id, keyVersion);
  }

  private requireEnabled(): void {
    if (!this.key) throw new Error("Credential vault is not enabled.");
  }
}

export function parseVaultKey(value: string | undefined, version = "1"): CredentialVaultKey | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  const bytes = /^[a-f0-9]{64}$/i.test(trimmed) ? Buffer.from(trimmed, "hex") : Buffer.from(trimmed, "base64url");
  if (bytes.length !== 32) throw new Error("ROUTECAIRN_MASTER_KEY must decode to exactly 32 bytes.");
  if (!/^[A-Za-z0-9_.-]{1,40}$/.test(version)) throw new Error("ROUTECAIRN_MASTER_KEY_VERSION is invalid.");
  return { bytes, version };
}

function encryptWithKey(database: DashboardDatabase, key: CredentialVaultKey, id: string, secret: CredentialProfileSecret): { nonce: string; ciphertext: string; authTag: string } {
  const nonce = randomBytes(12);
  const cipher = createCipheriv(credentialVaultAlgorithm, key.bytes, nonce);
  cipher.setAAD(associatedData(database, id, key.version));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(secret), "utf8"), cipher.final()]);
  return { nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), authTag: cipher.getAuthTag().toString("base64url") };
}

function associatedData(database: DashboardDatabase, id: string, keyVersion: string): Buffer {
  const installation = database.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'installation_id'").get() as { value: string } | undefined;
  return Buffer.from(JSON.stringify({ purpose: "routecairn-credential-profile", id, installationId: installation?.value ?? "unknown", keyVersion }), "utf8");
}

function validateSecret(secret: CredentialProfileSecret): void {
  const json = JSON.stringify(secret);
  if (Buffer.byteLength(json, "utf8") > 32 * 1024) throw new Error("Credential profile secret is too large.");
  for (const name of Object.keys(secret.headers ?? {})) validateHeaderName(name);
  for (const name of Object.keys(secret.cookies ?? {})) validateCookieName(name);
  if (secret.authorizationHeader && /[\r\n]/.test(secret.authorizationHeader)) throw new Error("Authorization header contains invalid characters.");
}

function validateHeaderName(name: string): void {
  if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,80}$/.test(name)) throw new Error(`Invalid header name: ${name}`);
  if (["host", "content-length", "connection", "transfer-encoding"].includes(name.toLowerCase())) throw new Error(`Forbidden header name: ${name}`);
}

function validateCookieName(name: string): void {
  if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,80}$/.test(name)) throw new Error(`Invalid cookie name: ${name}`);
}

function credentialTypeSummary(secret: CredentialProfileSecret): string {
  const parts = [];
  if (secret.authorizationHeader) parts.push("authorization-header");
  if (secret.cookies && Object.keys(secret.cookies).length > 0) parts.push(`${Object.keys(secret.cookies).length}-cookie(s)`);
  if (secret.headers && Object.keys(secret.headers).length > 0) parts.push(`${Object.keys(secret.headers).length}-custom-header(s)`);
  if (secret.identityVerification) parts.push("identity-verification");
  return parts.length > 0 ? parts.join(", ") : "metadata-only";
}

function summaryFromRow(row: CredentialProfileRow): CredentialProfileSummary {
  const identity = JSON.parse(row.safe_identity_summary_json) as Record<string, unknown>;
  return {
    id: row.id,
    name: row.name,
    ...(row.description ? { description: row.description } : {}),
    safeAlias: row.safe_alias,
    enabled: row.enabled === 1,
    ...(row.project_id ? { projectId: row.project_id } : {}),
    ...(row.target_id ? { targetId: row.target_id } : {}),
    credentialTypeSummary: row.credential_type_summary,
    safeIdentitySummary: identity,
    ...(row.expires_at ? { expiresAt: row.expires_at } : {}),
    ...(row.last_used_at ? { lastUsedAt: row.last_used_at } : {}),
    keyVersion: row.key_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

interface CredentialProfileRow {
  id: string;
  name: string;
  description: string | null;
  safe_alias: string;
  enabled: number;
  project_id: string | null;
  target_id: string | null;
  credential_type_summary: string;
  safe_identity_summary_json: string;
  expires_at: string | null;
  last_used_at: string | null;
  key_version: string;
  algorithm: string;
  nonce: string;
  ciphertext: string;
  auth_tag: string;
  created_at: string;
  updated_at: string;
}
