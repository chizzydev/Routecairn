import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { Database } from "better-sqlite3";
import type { CredentialVaultKey } from "../credentials/CredentialVault.js";
import { credentialVaultAlgorithm } from "../credentials/CredentialVault.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { authorizationWorkflowConfigurationsSchema, type AuthorizationWorkflowConfiguration } from "../contracts/ScanStudioSchemas.js";

const maximumTemplateBytes = 256 * 1024;

export class RetestTemplateVault {
  public constructor(private readonly db: Database, private readonly key?: CredentialVaultKey) {}

  public available(): boolean {
    return Boolean(this.key);
  }

  public save(scanId: string, workflows: readonly AuthorizationWorkflowConfiguration[]): void {
    if (!this.key || workflows.length === 0) return;
    const validated = authorizationWorkflowConfigurationsSchema.parse(workflows);
    const plaintext = Buffer.from(JSON.stringify(validated), "utf8");
    if (plaintext.length > maximumTemplateBytes) throw new Error("Retest workflow template exceeds 256 KiB.");
    const nonce = randomBytes(12);
    const cipher = createCipheriv(credentialVaultAlgorithm, this.key.bytes, nonce);
    cipher.setAAD(this.associatedData(scanId, this.key.version));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    this.db.prepare(
      `INSERT INTO scan_retest_templates
       (scan_id, algorithm, key_version, nonce, ciphertext, auth_tag, workflow_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(scan_id) DO UPDATE SET algorithm = excluded.algorithm,
         key_version = excluded.key_version, nonce = excluded.nonce,
         ciphertext = excluded.ciphertext, auth_tag = excluded.auth_tag,
         workflow_count = excluded.workflow_count, created_at = excluded.created_at`
    ).run(scanId, credentialVaultAlgorithm, this.key.version, nonce.toString("base64url"),
      ciphertext.toString("base64url"), cipher.getAuthTag().toString("base64url"), validated.length, nowIso());
  }

  public load(scanId: string): AuthorizationWorkflowConfiguration[] | undefined {
    if (!this.key) return undefined;
    const row = this.db.prepare("SELECT * FROM scan_retest_templates WHERE scan_id = ?").get(scanId) as TemplateRow | undefined;
    if (!row) return undefined;
    if (row.algorithm !== credentialVaultAlgorithm) throw new Error("Unsupported retest template algorithm.");
    if (row.key_version !== this.key.version) throw new Error("Retest template key version is unavailable.");
    const decipher = createDecipheriv(credentialVaultAlgorithm, this.key.bytes, Buffer.from(row.nonce, "base64url"));
    decipher.setAAD(this.associatedData(scanId, row.key_version));
    decipher.setAuthTag(Buffer.from(row.auth_tag, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(row.ciphertext, "base64url")), decipher.final()]);
    if (plaintext.length > maximumTemplateBytes) throw new Error("Retest workflow template exceeds 256 KiB.");
    return authorizationWorkflowConfigurationsSchema.parse(JSON.parse(plaintext.toString("utf8")));
  }

  public rotateKey(nextKey: CredentialVaultKey): number {
    if (!this.key) throw new Error("Retest template vault is not enabled.");
    const scanIds = this.db.prepare("SELECT scan_id FROM scan_retest_templates ORDER BY scan_id").all() as Array<{ scan_id: string }>;
    const nextVault = new RetestTemplateVault(this.db, nextKey);
    for (const row of scanIds) {
      const workflows = this.load(row.scan_id);
      if (workflows) nextVault.save(row.scan_id, workflows);
    }
    return scanIds.length;
  }

  private associatedData(scanId: string, keyVersion: string): Buffer {
    const installation = this.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'installation_id'").get() as { value: string } | undefined;
    return Buffer.from(JSON.stringify({ purpose: "routecairn-retest-template", scanId, installationId: installation?.value ?? "unknown", keyVersion }), "utf8");
  }
}

interface TemplateRow {
  algorithm: string;
  key_version: string;
  nonce: string;
  ciphertext: string;
  auth_tag: string;
}
