import { randomUUID } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { SandboxedModuleHost } from "../../core/plugins/SandboxedModuleHost.js";
import type { ThirdPartyModuleBrokerBinding, ThirdPartyModuleManifest } from "../contracts/OperationalScaleSchemas.js";
import { readModuleJson, verifyModuleEnvelope, type ModulePayload } from "../../core/plugins/ModuleDistribution.js";

export class ThirdPartyModuleService {
  private readonly host = new SandboxedModuleHost();
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly trustPath = process.env.ROUTECAIRN_MODULE_TRUST_PATH, private readonly requireSigned = process.env.ROUTECAIRN_REQUIRE_SIGNED_MODULES === "true") {}

  public register(organizationId: string, packageDirectory: string, actor: string, bundlePath?: string): string {
    const root = this.allowedPath(packageDirectory);
    if (this.requireSigned && !bundlePath) throw new Error("MODULE_SIGNATURE_REQUIRED");
    const manifest = JSON.parse(readFileSync(resolve(root, "routecairn.module.json"), "utf8")) as unknown; const validated = this.host.validatePackage(root, manifest); const id = randomUUID(); const now = nowIso();
    const envelope = bundlePath ? readModuleJson(this.allowedPath(bundlePath)) : undefined;
    if (envelope) { const payload = this.verify(envelope); if (payload.packageDigest !== validated.digest || payload.moduleId !== validated.manifest.moduleId || payload.version !== validated.manifest.version) throw new Error("MODULE_REGISTER_DIGEST_MISMATCH"); }
    this.database.db.transaction(() => {
      this.database.db.prepare(`INSERT INTO third_party_modules (id,organization_id,module_id,version,manifest_json,package_path,package_digest,status,created_by,created_at,updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'REGISTERED', ?, ?, ?)`).run(id, organizationId, validated.manifest.moduleId, validated.manifest.version, JSON.stringify(validated.manifest), root, validated.digest, actor, now, now);
      if (envelope) this.database.db.prepare("INSERT INTO third_party_module_signatures (module_id,envelope_json) VALUES (?,?)").run(id, JSON.stringify(envelope));
    })(); return id;
  }
  public approve(id: string, actor: string): void { this.checkTrust(id); const result=this.database.db.prepare("UPDATE third_party_modules SET status='APPROVED',approved_by=?,updated_at=? WHERE id=? AND status IN ('REGISTERED','DISABLED')").run(actor, nowIso(), id);if(result.changes!==1)throw new Error("SDK_MODULE_NOT_APPROVABLE"); }
  public async execute(id: string, input: Record<string, unknown>, broker?: ThirdPartyModuleBrokerBinding): Promise<unknown> { const row = this.database.db.prepare("SELECT * FROM third_party_modules WHERE id=? AND status='APPROVED'").get(id) as ModuleRow | undefined; if (!row) throw new Error("SDK_MODULE_NOT_APPROVED"); const manifest = JSON.parse(row.manifest_json) as ThirdPartyModuleManifest; try { this.checkTrust(id, row.package_digest); return await this.host.execute(row.package_path, manifest, input, broker, row.package_digest); } catch (error) { if (error instanceof Error && (["SDK_PACKAGE_DIGEST_CHANGED", "SDK_PACKAGE_CHANGED_DURING_SNAPSHOT"].includes(error.message) || error.message.startsWith("MODULE_"))) this.database.db.prepare("UPDATE third_party_modules SET status='QUARANTINED',updated_at=? WHERE id=?").run(nowIso(), id); throw error; } }
  public list(organizationId: string): unknown[] { const rows = this.database.db.prepare("SELECT id,module_id AS moduleId,version,status,package_digest AS packageDigest,manifest_json AS manifestJson,approved_by AS approvedBy,created_by AS createdBy,created_at AS createdAt,updated_at AS updatedAt FROM third_party_modules WHERE organization_id=? ORDER BY module_id,version").all(organizationId) as Array<Record<string, unknown> & { manifestJson: string }>; return rows.map(({ manifestJson, ...row }) => { const manifest = JSON.parse(manifestJson) as ThirdPartyModuleManifest; return { ...row, description: manifest.description, capabilities: manifest.capabilities, permissions: manifest.permissions, inputSchema: manifest.inputSchema, signature: this.signatureSummary(String(row.id)) }; }); }
  public organizationForModule(id: string): string { const row=this.database.db.prepare("SELECT organization_id FROM third_party_modules WHERE id=?").get(id) as {organization_id:string}|undefined;if(!row)throw new Error("SDK_MODULE_NOT_FOUND");return row.organization_id; }
  public disable(id: string): void { const changed = this.database.db.prepare("UPDATE third_party_modules SET status='DISABLED',updated_at=? WHERE id=? AND status IN ('REGISTERED','APPROVED','DISABLED')").run(nowIso(), id); if (changed.changes !== 1) throw new Error("SDK_MODULE_NOT_DISABLEABLE"); }
  private signatureSummary(id: string): unknown { const row = this.database.db.prepare("SELECT envelope_json FROM third_party_module_signatures WHERE module_id=?").get(id) as { envelope_json: string } | undefined; if (!row) return { signed: false }; const envelope = JSON.parse(row.envelope_json); const payload = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8")); return { signed: true, publisher: payload.publisher, keyId: envelope.signatures[0].keyid, expiresAt: payload.expiresAt, checkedBeforeApprovalAndExecution: true }; }
  private allowedPath(path: string): string { const root = realpathSync(resolve(path)), allowed = realpathSync(resolve(this.paths.thirdPartyModulesDir)); if (root === allowed || (!root.startsWith(`${allowed}\\`) && !root.startsWith(`${allowed}/`))) throw new Error("SDK_PACKAGE_OUTSIDE_MODULE_ROOT"); return root; }
  private verify(envelope: unknown): ModulePayload { if (!this.trustPath) throw new Error("MODULE_TRUST_CONFIGURATION_REQUIRED"); try { return verifyModuleEnvelope(envelope, readModuleJson(this.trustPath, 1024 * 1024)); } catch (error) { if (error instanceof Error && /^MODULE_[A-Z_]+$/.test(error.message)) throw error; throw new Error("MODULE_TRUST_INVALID"); } }
  private checkTrust(id: string, digest?: string): void {
    const signed = this.database.db.prepare("SELECT envelope_json FROM third_party_module_signatures WHERE module_id=?").get(id) as { envelope_json: string } | undefined;
    if (!signed) { if (this.requireSigned) throw new Error("MODULE_SIGNATURE_REQUIRED"); return; }
    const payload = this.verify(JSON.parse(signed.envelope_json)); if (digest && payload.packageDigest !== digest) throw new Error("MODULE_REGISTER_DIGEST_MISMATCH");
  }
}
interface ModuleRow { package_path: string; package_digest: string; manifest_json: string }
