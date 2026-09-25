import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";

export type OrganizationRole = "OWNER" | "ADMIN" | "ANALYST" | "VIEWER";
export type OrganizationPermission = "org.read" | "org.manage" | "resources.use" | "members.manage" | "sso.manage" | "notifications.manage" | "workers.manage" | "backups.manage" | "integrations.manage" | "modules.manage";

const permissions: Record<OrganizationRole, ReadonlySet<OrganizationPermission>> = {
  OWNER: new Set(["org.read", "org.manage", "resources.use", "members.manage", "sso.manage", "notifications.manage", "workers.manage", "backups.manage", "integrations.manage", "modules.manage"]),
  ADMIN: new Set(["org.read", "resources.use", "members.manage", "sso.manage", "notifications.manage", "workers.manage", "integrations.manage", "modules.manage"]),
  ANALYST: new Set(["org.read", "resources.use", "integrations.manage"]),
  VIEWER: new Set(["org.read"])
};

export class OrganizationService {
  public constructor(private readonly database: DashboardDatabase) {}

  public defaultOrganizationId(): string {
    const row = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'default_organization_id'").get() as { value: string } | undefined;
    if (!row) throw new Error("DEFAULT_ORGANIZATION_MISSING");
    return row.value;
  }

  public create(input: { name: string; slug: string }, actor: string): string {
    const id = randomUUID(); const now = nowIso();
    this.database.transaction(() => {
      this.database.db.prepare("INSERT INTO organizations (id,slug,name,status,created_by,created_at,updated_at) VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)").run(id, input.slug, input.name, actor, now, now);
      if (actor !== "local-operator") {
        const user = this.database.db.prepare("SELECT id FROM dashboard_users WHERE id = ? AND enabled=1").get(actor);
        if (!user) throw new Error("ORGANIZATION_OWNER_USER_NOT_FOUND");
        this.database.db.prepare("INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?, ?, 'OWNER', ?, ?, ?)").run(id, actor, actor, now, now);
      }
    });
    return id;
  }

  public list(userId: string, localOwner = false): unknown[] {
    const rows = localOwner
      ? this.database.db.prepare("SELECT o.*, 'OWNER' AS membership_role FROM organizations o ORDER BY o.name").all()
      : this.database.db.prepare("SELECT o.*, m.role AS membership_role FROM organizations o JOIN organization_memberships m ON m.organization_id=o.id WHERE m.user_id=? ORDER BY o.name").all(userId);
    return (rows as OrgRow[]).map(summary);
  }

  public detail(organizationId: string, userId: string, localOwner = false): { organization: unknown; members: unknown[] } {
    const role = this.require(organizationId, userId, "org.read", localOwner);
    const organization = this.database.db.prepare("SELECT *, ? AS membership_role FROM organizations WHERE id=?").get(role, organizationId) as OrgRow | undefined;
    if (!organization) throw new Error("ORGANIZATION_NOT_FOUND");
    const members = this.database.db.prepare(`SELECT m.user_id AS userId,u.login,m.role,m.created_at AS createdAt,m.updated_at AS updatedAt
      FROM organization_memberships m JOIN dashboard_users u ON u.id=m.user_id WHERE m.organization_id=? ORDER BY u.login`).all(organizationId);
    return { organization: { ...summary(organization), resources: this.resourceCounts(organizationId) }, members };
  }

  public setMember(organizationId: string, input: { userId: string; role: OrganizationRole }, actor: string, localOwner = false): void {
    this.require(organizationId, actor, "members.manage", localOwner);
    const user = this.database.db.prepare("SELECT id FROM dashboard_users WHERE id=? AND enabled=1").get(input.userId);
    if (!user) throw new Error("ORGANIZATION_MEMBER_USER_NOT_FOUND");
    const now = nowIso();
    this.database.transaction(() => {
      const current = this.database.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(organizationId, input.userId) as { role: OrganizationRole } | undefined;
      if (current?.role === "OWNER" && input.role !== "OWNER") this.assertAnotherOwner(organizationId);
      this.database.db.prepare(`INSERT INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(organization_id,user_id) DO UPDATE SET role=excluded.role,updated_at=excluded.updated_at`).run(organizationId, input.userId, input.role, actor, now, now);
    });
  }

  public removeMember(organizationId: string, userId: string, actor: string, localOwner = false): void {
    this.require(organizationId, actor, "members.manage", localOwner);
    const membership = this.database.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(organizationId, userId) as { role: OrganizationRole } | undefined;
    if (!membership) return;
    if (membership.role === "OWNER") {
      this.assertAnotherOwner(organizationId);
    }
    this.database.db.prepare("DELETE FROM organization_memberships WHERE organization_id=? AND user_id=?").run(organizationId, userId);
  }

  public require(organizationId: string, userId: string, permission: OrganizationPermission, localOwner = false): OrganizationRole {
    const organization = this.database.db.prepare("SELECT status FROM organizations WHERE id=?").get(organizationId) as { status: string } | undefined;
    if (!organization) throw new OrganizationPermissionError(permission);
    if (organization.status !== "ACTIVE" && permission !== "org.read") throw new OrganizationPermissionError(permission);
    if (localOwner) return "OWNER";
    const membership = this.database.db.prepare("SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=?").get(organizationId, userId) as { role: OrganizationRole } | undefined;
    if (!membership || !permissions[membership.role].has(permission)) throw new OrganizationPermissionError(permission);
    return membership.role;
  }

  public resourceCounts(organizationId: string): Record<string, number> {
    const count = (table: string): number => (this.database.db.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE organization_id=?`).get(organizationId) as { count: number }).count;
    return { projects: count("projects"), targets: count("targets"), scans: count("scans"), findings: count("findings"), credentials: count("credential_profiles"), configurations: count("saved_scan_configurations") };
  }

  public resourceOrganization(kind: "project" | "target" | "scan" | "finding" | "credential" | "configuration", id: string): string | undefined {
    const table = { project: "projects", target: "targets", scan: "scans", finding: "findings", credential: "credential_profiles", configuration: "saved_scan_configurations" }[kind];
    return (this.database.db.prepare(`SELECT organization_id FROM ${table} WHERE id=?`).get(id) as { organization_id: string } | undefined)?.organization_id;
  }

  public requireResource(kind: "project" | "target" | "scan" | "finding" | "credential" | "configuration", id: string, userId: string, permission: OrganizationPermission, localOwner = false): string {
    const organizationId = this.resourceOrganization(kind, id);
    if (!organizationId) throw new OrganizationPermissionError(permission);
    this.require(organizationId, userId, permission, localOwner);
    return organizationId;
  }

  private assertAnotherOwner(organizationId: string): void {
    const owners = this.database.db.prepare("SELECT COUNT(*) AS count FROM organization_memberships WHERE organization_id=? AND role='OWNER'").get(organizationId) as { count: number };
    if (owners.count <= 1) throw new Error("ORGANIZATION_FINAL_OWNER_REQUIRED");
  }
}

export class OrganizationPermissionError extends Error {
  public constructor(permission: string) { super(`Organization permission required: ${permission}`); this.name = "OrganizationPermissionError"; }
}

interface OrgRow { id: string; slug: string; name: string; status: string; membership_role: OrganizationRole; created_at: string; updated_at: string; row_version: number }
function summary(row: OrgRow) { return { id: row.id, slug: row.slug, name: row.name, status: row.status, role: row.membership_role, createdAt: row.created_at, updatedAt: row.updated_at, rowVersion: row.row_version }; }
