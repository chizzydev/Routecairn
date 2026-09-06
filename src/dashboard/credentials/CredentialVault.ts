import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import { browserBootstrapSchema } from "../../core/auth/AuthProfile.js";

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
  browserBootstrap?: import("../../core/auth/AuthProfile.js").AuthProfile["browserBootstrap"] | undefined;
  lifecycleSecrets?: Record<string, string> | undefined;
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

export type CredentialHealthClassification =
  | "HEALTHY"
  | "NEAR_EXPIRY"
  | "EXPIRED"
  | "DISABLED"
  | "INVALID"
  | "IDENTITY_MISMATCH"
  | "UNVERIFIED";

export interface CredentialHealthEvent {
  id: string;
  credentialProfileId: string;
  classification: CredentialHealthClassification;
  source: string;
  reasonCode: string;
  safeSummary: string;
  principalFingerprint?: string;
  createdAt: string;
}

export interface CredentialDependencyImpact {
  targetDefaults: number;
  configurationReferences: number;
  activeScans: number;
  canDelete: boolean;
  impactDigest: string;
  targetIds: string[];
  configurationIds: string[];
  activeScanIds: string[];
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
  secretVersion: number;
  secretReplacedAt?: string;
  health: {
    classification: CredentialHealthClassification;
    reasonCode: string;
    checkedAt?: string;
    principalFingerprint?: string;
    expiresInMs?: number;
  };
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
    this.recordHealth(id, "UNVERIFIED", "CREATE", "CREDENTIAL_NOT_YET_TESTED", "Credential created; identity and validity have not yet been verified.");
    return id;
  }

  public update(id: string, input: CredentialProfileInput): void {
    this.requireEnabled();
    validateSecret(input.secret);
    const encrypted = this.encrypt(id, input.secret);
    this.database.db
      .prepare(
        `UPDATE credential_profiles
         SET name = ?, description = ?, safe_alias = ?, project_id = ?, target_id = ?, credential_type_summary = ?, safe_identity_summary_json = ?, expires_at = ?, updated_at = ?, algorithm = ?, key_version = ?, nonce = ?, ciphertext = ?, auth_tag = ?, secret_version = secret_version + 1, secret_replaced_at = ?, last_health_status = 'UNVERIFIED', last_health_checked_at = NULL, last_health_reason_code = 'SECRET_REPLACED_RETEST_REQUIRED', last_principal_fingerprint = NULL
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
        nowIso(),
        id
      );
    this.recordHealth(id, "UNVERIFIED", "PROFILE_UPDATE", "SECRET_REPLACED_RETEST_REQUIRED", "Credential secret and metadata were updated; a fresh health test is required.");
  }

  public updateMetadata(id: string, input: Omit<CredentialProfileInput, "secret" | "createdByUserId">): void {
    const result = this.database.db.prepare(`UPDATE credential_profiles SET name = ?, description = ?, safe_alias = ?, project_id = ?, target_id = ?, safe_identity_summary_json = ?, expires_at = ?, last_health_status = 'UNVERIFIED', last_health_checked_at = NULL, last_health_reason_code = 'METADATA_CHANGED_RETEST_REQUIRED', last_principal_fingerprint = NULL, updated_at = ? WHERE id = ? AND deleted_at IS NULL`)
      .run(clamp(input.name, 160), input.description ? clamp(input.description, 2000) : null, clamp(input.safeAlias, 160), input.projectId ?? null, input.targetId ?? null, JSON.stringify(input.safeIdentitySummary), input.expiresAt ?? null, nowIso(), id);
    if (result.changes !== 1) throw new Error("Credential profile not found.");
    this.recordHealth(id, "UNVERIFIED", "METADATA_UPDATE", "METADATA_CHANGED_RETEST_REQUIRED", "Credential metadata changed; identity and validity must be verified again.");
  }

  public replaceSecret(id: string, secret: CredentialProfileSecret): void {
    this.requireEnabled(); validateSecret(secret);
    const encrypted = this.encrypt(id, secret);
    const replacedAt = nowIso();
    const result = this.database.db.prepare(`UPDATE credential_profiles SET credential_type_summary = ?, algorithm = ?, key_version = ?, nonce = ?, ciphertext = ?, auth_tag = ?, secret_version = secret_version + 1, secret_replaced_at = ?, last_health_status = 'UNVERIFIED', last_health_checked_at = NULL, last_health_reason_code = 'SECRET_REPLACED_RETEST_REQUIRED', last_principal_fingerprint = NULL, updated_at = ? WHERE id = ? AND deleted_at IS NULL`)
      .run(credentialTypeSummary(secret), credentialVaultAlgorithm, this.key!.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, replacedAt, replacedAt, id);
    if (result.changes !== 1) throw new Error("Credential profile not found.");
    this.recordHealth(id, "UNVERIFIED", "SECRET_REPLACEMENT", "SECRET_REPLACED_RETEST_REQUIRED", "Secret material was replaced; a fresh health test is required.");
  }

  public renew(id: string, input: { secret: CredentialProfileSecret; expiresAt: string; safeIdentitySummary?: Record<string, unknown> | undefined; impactDigest?: string | undefined; preserveUnspecified?: boolean | undefined }): CredentialProfileSummary {
    this.requireEnabled();
    const secret = input.preserveUnspecified === false ? input.secret : mergeCredentialSecrets(this.decrypt(id, false, false), input.secret);
    validateSecret(secret);
    const expiry = Date.parse(input.expiresAt);
    if (!Number.isFinite(expiry) || expiry <= Date.now()) throw new Error("CREDENTIAL_EXPIRY_INVALID: Renewal expiry must be in the future.");
    if (input.impactDigest) this.assertImpactDigest(id, input.impactDigest);
    const encrypted = this.encrypt(id, secret);
    const now = nowIso();
    const result = this.database.db.prepare(`UPDATE credential_profiles
      SET credential_type_summary = ?, safe_identity_summary_json = COALESCE(?, safe_identity_summary_json), expires_at = ?, algorithm = ?, key_version = ?, nonce = ?, ciphertext = ?, auth_tag = ?, secret_version = secret_version + 1, secret_replaced_at = ?, last_health_status = 'UNVERIFIED', last_health_checked_at = NULL, last_health_reason_code = 'RENEWED_RETEST_REQUIRED', last_principal_fingerprint = NULL, updated_at = ?
      WHERE id = ? AND deleted_at IS NULL`)
      .run(credentialTypeSummary(secret), input.safeIdentitySummary ? JSON.stringify(input.safeIdentitySummary) : null, input.expiresAt, credentialVaultAlgorithm, this.key!.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, now, now, id);
    if (result.changes !== 1) throw new Error("Credential profile not found.");
    this.recordHealth(id, "UNVERIFIED", "RENEWAL", "RENEWED_RETEST_REQUIRED", "Credential renewed; run identity verification before scan use.");
    return this.getSummary(id)!;
  }

  public dependencies(id: string): CredentialDependencyImpact {
    const targetIds = (this.database.db.prepare("SELECT id FROM targets WHERE default_credential_profile_id = ? AND archived_at IS NULL ORDER BY id").all(id) as Array<{ id: string }>).map((row) => row.id);
    const configurationIds = (this.database.db.prepare("SELECT DISTINCT configuration_id AS id FROM saved_scan_configuration_versions WHERE snapshot_json LIKE ? ORDER BY configuration_id").all(`%${id}%`) as Array<{ id: string }>).map((row) => row.id);
    const activeScanIds = (this.database.db.prepare("SELECT scans.id AS id FROM scans JOIN scan_plan_snapshots ON scan_plan_snapshots.scan_id = scans.id WHERE scans.status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED') AND scan_plan_snapshots.authentication_summary_json LIKE ? ORDER BY scans.id").all(`%${id}%`) as Array<{ id: string }>).map((row) => row.id);
    const impact = { targetDefaults: targetIds.length, configurationReferences: configurationIds.length, activeScans: activeScanIds.length, targetIds, configurationIds, activeScanIds };
    return { ...impact, canDelete: targetIds.length + configurationIds.length + activeScanIds.length === 0, impactDigest: impactDigest(id, impact) };
  }

  public assertImpactDigest(id: string, expected: string): CredentialDependencyImpact {
    const actual = this.dependencies(id);
    if (actual.impactDigest !== expected) throw new Error("CREDENTIAL_DEPENDENCY_IMPACT_CHANGED: Refresh dependency impact and review it again.");
    return actual;
  }

  public list(): CredentialProfileSummary[] {
    this.refreshDerivedHealth();
    const rows = this.database.db.prepare("SELECT * FROM credential_profiles WHERE deleted_at IS NULL ORDER BY updated_at DESC LIMIT 200").all() as CredentialProfileRow[];
    return rows.map(summaryFromRow);
  }

  public getSummary(id: string): CredentialProfileSummary | undefined {
    this.refreshDerivedHealth(id);
    const row = this.database.db.prepare("SELECT * FROM credential_profiles WHERE id = ? AND deleted_at IS NULL").get(id) as CredentialProfileRow | undefined;
    return row ? summaryFromRow(row) : undefined;
  }

  public decryptForUse(id: string): CredentialProfileSecret {
    const summary = this.getSummary(id);
    if (!summary) throw new Error("Credential profile unavailable.");
    if (["DISABLED", "EXPIRED", "INVALID", "IDENTITY_MISMATCH"].includes(summary.health.classification)) {
      throw new Error(`Credential profile unavailable. CREDENTIAL_${summary.health.classification}: profile cannot be used.`);
    }
    return this.decrypt(id, true, true);
  }

  public decryptForHealthCheck(id: string): CredentialProfileSecret {
    const summary = this.getSummary(id);
    if (!summary || !summary.enabled) throw new Error("Credential profile unavailable.");
    if (summary.expiresAt && Date.parse(summary.expiresAt) <= Date.now()) throw new Error("CREDENTIAL_EXPIRED: Credential profile cannot be tested after expiry; renew it first.");
    try {
      return this.decrypt(id, true, true);
    } catch (error) {
      this.recordHealth(id, "INVALID", "VAULT_VALIDATION", "VAULT_DECRYPTION_FAILED", "Credential ciphertext could not be authenticated or decoded with the active vault key.");
      throw error;
    }
  }

  private decrypt(id: string, recordUse: boolean, requireEnabled: boolean): CredentialProfileSecret {
    this.requireEnabled();
    const row = this.database.db.prepare(`SELECT * FROM credential_profiles WHERE id = ? ${requireEnabled ? "AND enabled = 1" : ""} AND deleted_at IS NULL`).get(id) as CredentialProfileRow | undefined;
    if (!row) throw new Error("Credential profile unavailable.");
    if (row.algorithm !== credentialVaultAlgorithm) throw new Error("Unsupported credential profile algorithm.");
    const decipher = createDecipheriv(credentialVaultAlgorithm, this.key!.bytes, Buffer.from(row.nonce, "base64url"));
    decipher.setAAD(this.associatedData(row.id, row.key_version));
    decipher.setAuthTag(Buffer.from(row.auth_tag, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(row.ciphertext, "base64url")), decipher.final()]).toString("utf8");
    if (recordUse) this.database.db.prepare("UPDATE credential_profiles SET last_used_at = ? WHERE id = ?").run(nowIso(), id);
    return JSON.parse(plaintext) as CredentialProfileSecret;
  }

  public setEnabled(id: string, enabled: boolean, expectedImpactDigest?: string): void {
    if (expectedImpactDigest) this.assertImpactDigest(id, expectedImpactDigest);
    const now = nowIso();
    const result = this.database.db.prepare("UPDATE credential_profiles SET enabled = ?, last_health_status = ?, last_health_reason_code = ?, last_health_checked_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL")
      .run(enabled ? 1 : 0, enabled ? "UNVERIFIED" : "DISABLED", enabled ? "REENABLED_RETEST_REQUIRED" : "OPERATOR_DISABLED", now, now, id);
    if (result.changes !== 1) throw new Error("Credential profile not found.");
    this.recordHealth(id, enabled ? "UNVERIFIED" : "DISABLED", enabled ? "ENABLE" : "DISABLE", enabled ? "REENABLED_RETEST_REQUIRED" : "OPERATOR_DISABLED", enabled ? "Credential re-enabled; a fresh health test is required." : "Credential disabled by an operator.");
  }

  public delete(id: string): void {
    const dependencies = this.dependencies(id);
    if (!dependencies.canDelete) throw new Error(`CREDENTIAL_IN_USE: Remove ${dependencies.targetDefaults + dependencies.configurationReferences + dependencies.activeScans} dependency reference(s) before deletion.`);
    this.database.db.prepare("UPDATE credential_profiles SET deleted_at = ?, enabled = 0, updated_at = ? WHERE id = ?").run(nowIso(), nowIso(), id);
  }

  public recordHealth(id: string, classification: CredentialHealthClassification, source: string, reasonCode: string, safeSummary: string, principalFingerprint?: string): void {
    const timestamp = nowIso();
    const safeSource = clamp(source.replace(/[^A-Za-z0-9_.-]/g, "_"), 80);
    const safeReason = clamp(reasonCode.replace(/[^A-Za-z0-9_.-]/g, "_"), 120);
    const safeText = clamp(safeSummary.replace(/[\r\n\0]/g, " "), 500);
    this.database.transaction(() => {
      const result = this.database.db.prepare(`UPDATE credential_profiles SET last_health_status = ?, last_health_checked_at = ?, last_health_reason_code = ?, last_principal_fingerprint = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`)
        .run(classification, timestamp, safeReason, principalFingerprint ?? null, timestamp, id);
      if (result.changes !== 1) throw new Error("Credential profile not found.");
      this.database.db.prepare(`INSERT INTO credential_health_events (id, credential_profile_id, classification, source, reason_code, safe_summary, principal_fingerprint, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(randomUUID(), id, classification, safeSource, safeReason, safeText, principalFingerprint ?? null, timestamp);
    });
  }

  public healthTimeline(id: string, limit = 50): CredentialHealthEvent[] {
    this.refreshDerivedHealth(id);
    // Multiple lifecycle transitions can legitimately occur within the same
    // millisecond. rowid preserves the append order when ISO timestamps tie.
    const rows = this.database.db.prepare("SELECT * FROM credential_health_events WHERE credential_profile_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?").all(id, Math.max(1, Math.min(200, limit))) as CredentialHealthEventRow[];
    return rows.map((row) => ({
      id: row.id,
      credentialProfileId: row.credential_profile_id,
      classification: row.classification,
      source: row.source,
      reasonCode: row.reason_code,
      safeSummary: row.safe_summary,
      ...(row.principal_fingerprint ? { principalFingerprint: row.principal_fingerprint } : {}),
      createdAt: row.created_at
    }));
  }

  public rotateKey(nextKey: CredentialVaultKey): number {
    this.requireEnabled();
    const rows = this.database.db.prepare("SELECT id FROM credential_profiles WHERE deleted_at IS NULL").all() as Array<{ id: string }>;
    let rotated = 0;
    this.database.transaction(() => {
      for (const row of rows) {
        const secret = this.decrypt(row.id, false, false);
        const encrypted = encryptWithKey(this.database, nextKey, row.id, secret);
        this.database.db
          .prepare("UPDATE credential_profiles SET algorithm = ?, key_version = ?, nonce = ?, ciphertext = ?, auth_tag = ?, updated_at = ? WHERE id = ?")
          .run(credentialVaultAlgorithm, nextKey.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, nowIso(), row.id);
        rotated += 1;
      }
    });
    return rotated;
  }

  private refreshDerivedHealth(id?: string): void {
    const rows = this.database.db.prepare(`SELECT * FROM credential_profiles WHERE deleted_at IS NULL AND enabled = 1 ${id ? "AND id = ?" : ""}`).all(...(id ? [id] : [])) as CredentialProfileRow[];
    const now = Date.now();
    for (const row of rows) {
      if (!row.expires_at) continue;
      const remaining = Date.parse(row.expires_at) - now;
      if (remaining <= 0 && row.last_health_status !== "EXPIRED") {
        this.recordHealth(row.id, "EXPIRED", "CLOCK", "EXPIRY_REACHED", "Credential expiry was reached; scan use is blocked.", row.last_principal_fingerprint ?? undefined);
      } else if (remaining > 0 && remaining <= 7 * 24 * 60 * 60 * 1000 && row.last_health_status === "HEALTHY") {
        this.recordHealth(row.id, "NEAR_EXPIRY", "CLOCK", "EXPIRY_WITHIN_SEVEN_DAYS", "Credential entered the seven-day renewal window.", row.last_principal_fingerprint ?? undefined);
      }
    }
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
  if (secret.browserBootstrap) {
    const parsed = browserBootstrapSchema.safeParse(secret.browserBootstrap);
    if (!parsed.success) throw new Error(`Invalid browser bootstrap configuration: ${parsed.error.message}`);
  }
  for (const [name, value] of Object.entries(secret.lifecycleSecrets ?? {})) {
    if (!/^[A-Za-z0-9._-]{1,100}$/.test(name) || value.length < 1 || value.length > 8192) throw new Error(`Invalid lifecycle secret reference: ${name}`);
  }
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
  if (secret.browserBootstrap) parts.push("browser-bootstrap");
  if (secret.lifecycleSecrets && Object.keys(secret.lifecycleSecrets).length > 0) parts.push(`${Object.keys(secret.lifecycleSecrets).length}-lifecycle-secret(s)`);
  return parts.length > 0 ? parts.join(", ") : "metadata-only";
}

function summaryFromRow(row: CredentialProfileRow): CredentialProfileSummary {
  const identity = JSON.parse(row.safe_identity_summary_json) as Record<string, unknown>;
  const health = effectiveCredentialHealth(row);
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
    secretVersion: row.secret_version,
    ...(row.secret_replaced_at ? { secretReplacedAt: row.secret_replaced_at } : {}),
    health,
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
  secret_version: number;
  secret_replaced_at: string | null;
  last_health_status: CredentialHealthClassification;
  last_health_checked_at: string | null;
  last_health_reason_code: string | null;
  last_principal_fingerprint: string | null;
  key_version: string;
  algorithm: string;
  nonce: string;
  ciphertext: string;
  auth_tag: string;
  created_at: string;
  updated_at: string;
}

interface CredentialHealthEventRow {
  id: string;
  credential_profile_id: string;
  classification: CredentialHealthClassification;
  source: string;
  reason_code: string;
  safe_summary: string;
  principal_fingerprint: string | null;
  created_at: string;
}

function effectiveCredentialHealth(row: CredentialProfileRow, now = Date.now()): CredentialProfileSummary["health"] {
  const expiry = row.expires_at ? Date.parse(row.expires_at) : undefined;
  const expiresInMs = expiry !== undefined && Number.isFinite(expiry) ? expiry - now : undefined;
  let classification: CredentialHealthClassification = row.last_health_status ?? "UNVERIFIED";
  let reasonCode = row.last_health_reason_code ?? "CREDENTIAL_NOT_YET_TESTED";
  if (row.enabled !== 1) {
    classification = "DISABLED";
    reasonCode = "OPERATOR_DISABLED";
  } else if (expiresInMs !== undefined && expiresInMs <= 0) {
    classification = "EXPIRED";
    reasonCode = "EXPIRY_REACHED";
  } else if (expiresInMs !== undefined && expiresInMs <= 7 * 24 * 60 * 60 * 1000 && classification === "HEALTHY") {
    classification = "NEAR_EXPIRY";
    reasonCode = "EXPIRY_WITHIN_SEVEN_DAYS";
  }
  return {
    classification,
    reasonCode,
    ...(row.last_health_checked_at ? { checkedAt: row.last_health_checked_at } : {}),
    ...(row.last_principal_fingerprint ? { principalFingerprint: row.last_principal_fingerprint } : {}),
    ...(expiresInMs !== undefined ? { expiresInMs } : {})
  };
}

function impactDigest(id: string, impact: { targetIds: string[]; configurationIds: string[]; activeScanIds: string[] }): string {
  return createHash("sha256").update("routecairn-credential-impact-v1\n").update(JSON.stringify({ id, ...impact })).digest("hex");
}

function mergeCredentialSecrets(current: CredentialProfileSecret, replacement: CredentialProfileSecret): CredentialProfileSecret {
  return {
    ...current,
    ...replacement,
    ...(replacement.cookies ? { cookies: { ...(current.cookies ?? {}), ...replacement.cookies } } : {}),
    ...(replacement.headers ? { headers: { ...(current.headers ?? {}), ...replacement.headers } } : {}),
    ...(replacement.lifecycleSecrets ? { lifecycleSecrets: { ...(current.lifecycleSecrets ?? {}), ...replacement.lifecycleSecrets } } : {})
  };
}
