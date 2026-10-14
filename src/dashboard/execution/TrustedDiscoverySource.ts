import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, join, sep } from "node:path";
import { readBoundedFileSync } from "../../core/files/BoundedFile.js";
import { scopeSchema, type RouteCairnScope } from "../../config/ConfigSchema.js";
import { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
export type DiscoveryDenialCode =
  | "DENIED_SOURCE_STALE"
  | "DENIED_SCOPE"
  | "DENIED_EFFECT_UNKNOWN"
  | "DENIED_OPERATOR_BINDING"
  | "DENIED_DUPLICATE"
  | "DENIED_CAPACITY"
  | "DENIED_CANCELLED";
export class TrustedDiscoveryDenial extends Error {
  public constructor(public readonly code: DiscoveryDenialCode) {
    super(code);
  }
}
export function discoveryDeny(code: DiscoveryDenialCode): never {
  throw new TrustedDiscoveryDenial(code);
}
export interface TrustedDiscoveryActor {
  organizationId: string;
  userId: string;
}
type Row = Record<string, string | number | null>;
export interface TrustedDiscoverySnapshot {
  scanId: string;
  targetId: string;
  origin: string;
  scope: RouteCairnScope;
  report: RouteCairnReport;
  digest: string;
  generation: string;
  targetGeneration: string;
}
const maximumReportBytes = 2 * 1024 * 1024;
export function discoveryDigest(bytes: string | Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}
/** Server-owned root and actual SQLite instance; never a caller supplied report/repository. */
export class TrustedDiscoverySource {
  private readonly root: string;
  public constructor(
    private readonly database: DashboardDatabase,
    root: string
  ) {
    if (!(database instanceof DashboardDatabase)) discoveryDeny("DENIED_SOURCE_STALE");
    this.root = resolve(root);
    if (
      !isAbsolute(root) ||
      /^\\\\/.test(root) ||
      lstatSync(this.root).isSymbolicLink() ||
      realpathSync(this.root).toLowerCase() !== this.root.toLowerCase()
    )
      discoveryDeny("DENIED_SOURCE_STALE");
  }
  public capture(scanId: string, actor: TrustedDiscoveryActor, parse = true): TrustedDiscoverySnapshot {
    try {
      if (
        ![scanId, actor.organizationId, actor.userId].every(
          (v) => typeof v === "string" && v.length > 0 && v.length <= 128
        )
      )
        discoveryDeny("DENIED_OPERATOR_BINDING");
      const rows = this.database.transaction(() => {
        const get = (sql: string, ...args: string[]) => this.database.db.prepare(sql).get(...args) as Row | undefined;
        const org = get("SELECT * FROM organizations WHERE id=?", actor.organizationId);
        const user = get(
          "SELECT id,role,enabled,updated_at,password_changed_at,locked_until FROM dashboard_users WHERE id=?",
          actor.userId
        );
        const member = get(
          "SELECT * FROM organization_memberships WHERE organization_id=? AND user_id=?",
          actor.organizationId,
          actor.userId
        );
        if (
          !org ||
          org.status !== "ACTIVE" ||
          !user ||
          user.enabled !== 1 ||
          user.role !== "OWNER" ||
          !member ||
          member.role !== "OWNER" ||
          (user.locked_until && Date.parse(String(user.locked_until)) > Date.now())
        )
          discoveryDeny("DENIED_OPERATOR_BINDING");
        const scan = get("SELECT * FROM scans WHERE id=?", scanId);
        if (
          !scan ||
          scan.status !== "COMPLETED" ||
          scan.source !== "DASHBOARD" ||
          scan.deleted_at ||
          scan.archived_at ||
          !scan.target_id ||
          !scan.json_report_artifact_id ||
          scan.organization_id !== actor.organizationId
        )
          discoveryDeny("DENIED_SOURCE_STALE");
        const target = get("SELECT * FROM targets WHERE id=?", String(scan.target_id));
        if (
          !target ||
          target.archived_at ||
          target.organization_id !== actor.organizationId ||
          target.project_id !== scan.project_id ||
          target.base_origin !== scan.target_origin
        )
          discoveryDeny("DENIED_SOURCE_STALE");
        if (
          target.classification !== "LOCAL" ||
          !["OWNED", "CONTROLLED_LAB"].includes(String(target.authorization_type)) ||
          !target.authorization_summary ||
          target.production_mutation_enabled !== 0 ||
          target.default_credential_profile_id ||
          target.default_auth_template_json !== "{}"
        )
          discoveryDeny("DENIED_SCOPE");
        const origin = new URL(String(target.base_origin));
        if (
          origin.origin !== target.base_origin ||
          origin.protocol !== "http:" ||
          !["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname) ||
          origin.username ||
          origin.password
        )
          discoveryDeny("DENIED_SCOPE");
        const project = scan.project_id ? get("SELECT * FROM projects WHERE id=?", String(scan.project_id)) : null;
        if (scan.project_id && (!project || project.archived_at || project.organization_id !== actor.organizationId))
          discoveryDeny("DENIED_SOURCE_STALE");
        const artifact = get("SELECT * FROM artifacts WHERE id=?", String(scan.json_report_artifact_id));
        if (
          !artifact ||
          artifact.scan_id !== scan.id ||
          artifact.organization_id !== actor.organizationId ||
          artifact.artifact_type !== "JSON_REPORT" ||
          artifact.content_type !== "application/json" ||
          artifact.retention_state !== "RETAIN" ||
          artifact.missing_file_flag !== 0
        )
          discoveryDeny("DENIED_SOURCE_STALE");
        return { org, user, member, scan, target, project, artifact };
      });
      const bytes = this.readCanonical(String(rows.artifact.canonical_path));
      if (String(rows.target.approved_scope_json).length > 65536) discoveryDeny("DENIED_SCOPE");
      const scope = scopeSchema.parse(JSON.parse(String(rows.target.approved_scope_json)));
      const report = parse ? (JSON.parse(bytes.toString("utf8")) as RouteCairnReport) : undefined;
      if (
        parse &&
        (!report ||
          typeof report.target !== "string" ||
          new URL(report.target).origin !== rows.scan.target_origin ||
          report.execution?.status !== "COMPLETED" ||
          report.execution.partial !== false ||
          ("scanId" in report && (report as unknown as { scanId: string }).scanId !== scanId))
      )
        discoveryDeny("DENIED_SOURCE_STALE");
      // All authoritative rows are fingerprinted; scans/artifacts need no guessed row_version column.
      return {
        scanId,
        targetId: String(rows.target.id),
        origin: String(rows.target.base_origin),
        scope,
        report: report!,
        digest: discoveryDigest(bytes),
        generation: discoveryDigest(JSON.stringify(rows)),
        targetGeneration: discoveryDigest(JSON.stringify(rows.target))
      };
    } catch (error) {
      if (error instanceof TrustedDiscoveryDenial) throw error;
      discoveryDeny("DENIED_SOURCE_STALE");
    }
  }
  public assertCurrent(snapshot: TrustedDiscoverySnapshot, actor: TrustedDiscoveryActor): void {
    const current = this.capture(snapshot.scanId, actor, false);
    if (
      current.digest !== snapshot.digest ||
      current.generation !== snapshot.generation ||
      current.origin !== snapshot.origin ||
      current.targetId !== snapshot.targetId
    )
      discoveryDeny("DENIED_SOURCE_STALE");
  }
  private readCanonical(path: string): Buffer {
    if (!isAbsolute(path) || resolve(path) !== path || /^\\\\/.test(path) || path.slice(3).includes(":"))
      discoveryDeny("DENIED_SOURCE_STALE");
    const rel = relative(this.root, path);
    if (!rel || rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel)) discoveryDeny("DENIED_SOURCE_STALE");
    const validate = () => {
      let at = this.root;
      if (lstatSync(at).isSymbolicLink() || realpathSync(at).toLowerCase() !== at.toLowerCase())
        discoveryDeny("DENIED_SOURCE_STALE");
      for (const part of rel.split(sep)) {
        at = join(at, part);
        if (lstatSync(at).isSymbolicLink() || realpathSync(at).toLowerCase() !== at.toLowerCase())
          discoveryDeny("DENIED_SOURCE_STALE");
      }
    };
    validate();
    const bytes = readBoundedFileSync(path, maximumReportBytes);
    validate();
    return bytes;
  }
}
