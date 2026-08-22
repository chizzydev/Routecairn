export type DashboardRole = "OWNER" | "ANALYST" | "VIEWER";

export type DashboardPermission =
  | "scans.read"
  | "scans.create"
  | "scans.cancel"
  | "findings.read"
  | "findings.review"
  | "findings.bulkReview"
  | "findings.assign"
  | "findings.remediate"
  | "findings.overrideSeverity"
  | "findings.markDuplicate"
  | "findings.linkRetest"
  | "findings.ownerOverride"
  | "comparisons.read"
  | "comparisons.create"
  | "comparisons.recompute"
  | "comparisons.delete"
  | "comparisons.export"
  | "notes.create"
  | "savedViews.manage"
  | "proofPacks.create"
  | "proofPacks.read"
  | "projects.manage"
  | "targets.manage"
  | "configurations.manage"
  | "imports.create"
  | "credentials.readSummary"
  | "credentials.create"
  | "credentials.update"
  | "credentials.delete"
  | "credentials.use"
  | "credentials.manage"
  | "credentials.test"
  | "credentials.rotateKey"
  | "users.manage"
  | "settings.manage"
  | "audit.read"
  | "artifacts.download"
  | "controlledMutation.approve"
  | "controlledMutation.recover";

const permissionsByRole: Record<DashboardRole, ReadonlySet<DashboardPermission>> = {
  OWNER: new Set([
    "scans.read",
    "scans.create",
    "scans.cancel",
    "findings.read",
    "findings.review",
    "findings.bulkReview",
    "findings.assign",
    "findings.remediate",
    "findings.overrideSeverity",
    "findings.markDuplicate",
    "findings.linkRetest",
    "findings.ownerOverride",
    "comparisons.read", "comparisons.create", "comparisons.recompute", "comparisons.delete", "comparisons.export",
    "notes.create",
    "savedViews.manage",
    "proofPacks.create",
    "proofPacks.read",
    "projects.manage",
    "targets.manage",
    "configurations.manage",
    "imports.create",
    "credentials.readSummary",
    "credentials.create",
    "credentials.update",
    "credentials.delete",
    "credentials.use",
    "credentials.manage",
    "credentials.test",
    "credentials.rotateKey",
    "users.manage",
    "settings.manage",
    "audit.read",
    "artifacts.download",
    "controlledMutation.approve",
    "controlledMutation.recover"
  ]),
  ANALYST: new Set([
    "scans.read",
    "scans.create",
    "scans.cancel",
    "findings.read",
    "findings.review",
    "findings.bulkReview",
    "findings.assign",
    "findings.remediate",
    "findings.overrideSeverity",
    "findings.markDuplicate",
    "findings.linkRetest",
    "comparisons.read", "comparisons.create", "comparisons.recompute", "comparisons.export",
    "notes.create",
    "savedViews.manage",
    "proofPacks.create",
    "proofPacks.read",
    "projects.manage",
    "targets.manage",
    "configurations.manage",
    "imports.create",
    "credentials.readSummary",
    "credentials.use",
    "credentials.test",
    "artifacts.download"
  ]),
  VIEWER: new Set(["scans.read", "findings.read", "comparisons.read", "proofPacks.read", "artifacts.download"])
};

export interface DashboardPrincipal {
  mode: "local" | "server";
  userId: string;
  login: string;
  role: DashboardRole;
  csrfToken: string;
}

export function hasPermission(role: DashboardRole, permission: DashboardPermission): boolean {
  return permissionsByRole[role].has(permission);
}

export function permissionsForRole(role: DashboardRole): DashboardPermission[] {
  return [...permissionsByRole[role]].sort();
}
