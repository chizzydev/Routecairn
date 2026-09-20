import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { SandboxedModuleHost } from "../../core/plugins/SandboxedModuleHost.js";

export class ThirdPartyModuleService {
  private readonly host = new SandboxedModuleHost();
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths) {}

  public register(organizationId: string, packageDirectory: string, actor: string): string {
    const root = resolve(packageDirectory); const allowed = resolve(this.paths.thirdPartyModulesDir); if (root !== allowed && !root.startsWith(`${allowed}\\`) && !root.startsWith(`${allowed}/`)) throw new Error("SDK_PACKAGE_OUTSIDE_MODULE_ROOT");
    const manifest = JSON.parse(readFileSync(resolve(root, "routecairn.module.json"), "utf8")) as unknown; const validated = this.host.validatePackage(root, manifest); const id = randomUUID(); const now = nowIso();
    this.database.db.prepare(`INSERT INTO third_party_modules (id,organization_id,module_id,version,manifest_json,package_path,package_digest,status,created_by,created_at,updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'REGISTERED', ?, ?, ?)`).run(id, organizationId, validated.manifest.moduleId, validated.manifest.version, JSON.stringify(validated.manifest), root, validated.digest, actor, now, now); return id;
  }
  public approve(id: string, actor: string): void { const result=this.database.db.prepare("UPDATE third_party_modules SET status='APPROVED',approved_by=?,updated_at=? WHERE id=? AND status IN ('REGISTERED','DISABLED')").run(actor, nowIso(), id);if(result.changes!==1)throw new Error("SDK_MODULE_NOT_APPROVABLE"); }
  public async execute(id: string, input: Record<string, unknown>): Promise<unknown> { const row = this.database.db.prepare("SELECT * FROM third_party_modules WHERE id=? AND status='APPROVED'").get(id) as ModuleRow | undefined; if (!row) throw new Error("SDK_MODULE_NOT_APPROVED"); const validated = this.host.validatePackage(row.package_path, JSON.parse(row.manifest_json)); if (validated.digest !== row.package_digest) { this.database.db.prepare("UPDATE third_party_modules SET status='QUARANTINED',updated_at=? WHERE id=?").run(nowIso(), id); throw new Error("SDK_PACKAGE_DIGEST_CHANGED"); } return this.host.execute(row.package_path, JSON.parse(row.manifest_json), input); }
  public list(organizationId: string): unknown[] { return this.database.db.prepare("SELECT id,module_id AS moduleId,version,status,package_digest AS packageDigest,approved_by AS approvedBy,created_by AS createdBy,created_at AS createdAt,updated_at AS updatedAt FROM third_party_modules WHERE organization_id=? ORDER BY module_id,version").all(organizationId); }
  public organizationForModule(id: string): string { const row=this.database.db.prepare("SELECT organization_id FROM third_party_modules WHERE id=?").get(id) as {organization_id:string}|undefined;if(!row)throw new Error("SDK_MODULE_NOT_FOUND");return row.organization_id; }
}
interface ModuleRow { package_path: string; package_digest: string; manifest_json: string }
