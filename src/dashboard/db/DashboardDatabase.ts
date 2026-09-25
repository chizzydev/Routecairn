import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { dashboardMigrations, dashboardSchemaVersion } from "./Migrations.js";

export type SqlValue = string | number | bigint | Buffer | null;

export class DashboardDatabase {
  public readonly db: Database.Database;

  public constructor(public readonly databasePath: string) {
    mkdirSync(dirname(databasePath), { recursive: true });
    this.db = new Database(databasePath);
    this.db.pragma("foreign_keys = ON");
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("busy_timeout = 5000");
  }

  public migrate(): void {
    this.db.exec("CREATE TABLE IF NOT EXISTS dashboard_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
    for (const migration of dashboardMigrations) {
      const existing = this.db.prepare("SELECT version FROM dashboard_migrations WHERE version = ?").get(migration.version);
      if (existing) continue;
      if (migration.requiresForeignKeysDisabled) {
        this.applyForeignKeyRebuildMigration(migration);
      } else {
        const apply = this.db.transaction(() => {
          this.db.exec(migration.sql);
          this.db.prepare("INSERT INTO dashboard_migrations (version, applied_at) VALUES (?, ?)").run(migration.version, nowIso());
        });
        apply();
      }
    }

    const metaUpsert = this.db.prepare(
      "INSERT INTO dashboard_meta (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
    );
    const installation = this.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'installation_id'").get() as { value: string } | undefined;
    if (!installation) {
      metaUpsert.run("installation_id", randomUUID(), nowIso());
    }
    const defaultOrganization = this.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'default_organization_id'").get() as { value: string } | undefined;
    const defaultOrganizationId = defaultOrganization?.value ?? randomUUID();
    if (!defaultOrganization) metaUpsert.run("default_organization_id", defaultOrganizationId, nowIso());
    const timestamp = nowIso();
    this.db.prepare("INSERT OR IGNORE INTO organizations (id, slug, name, status, created_by, created_at, updated_at) VALUES (?, 'default', 'Default organization', 'ACTIVE', 'SYSTEM', ?, ?)").run(defaultOrganizationId, timestamp, timestamp);
    this.db.prepare(`INSERT OR IGNORE INTO organization_memberships (organization_id,user_id,role,created_by,created_at,updated_at)
      SELECT ?, id, CASE role WHEN 'OWNER' THEN 'OWNER' WHEN 'ANALYST' THEN 'ANALYST' ELSE 'VIEWER' END, 'SYSTEM', ?, ? FROM dashboard_users`).run(defaultOrganizationId, timestamp, timestamp);
    this.assignLegacyResources(defaultOrganizationId);
    metaUpsert.run("schema_version", String(dashboardSchemaVersion), nowIso());
    metaUpsert.run("last_migration_at", nowIso(), nowIso());
  }

  private assignLegacyResources(defaultOrganizationId: string): void {
    this.transaction(() => {
      this.db.prepare("UPDATE projects SET organization_id=? WHERE organization_id IS NULL").run(defaultOrganizationId);
      this.db.prepare("UPDATE targets SET organization_id=COALESCE((SELECT organization_id FROM projects WHERE projects.id=targets.project_id),?) WHERE organization_id IS NULL").run(defaultOrganizationId);
      this.db.prepare("UPDATE scans SET organization_id=COALESCE((SELECT organization_id FROM targets WHERE targets.id=scans.target_id),(SELECT organization_id FROM projects WHERE projects.id=scans.project_id),?) WHERE organization_id IS NULL").run(defaultOrganizationId);
      this.db.prepare("UPDATE findings SET organization_id=COALESCE((SELECT organization_id FROM scans WHERE scans.id=findings.last_occurrence_scan_id),(SELECT organization_id FROM targets WHERE targets.id=findings.target_id),(SELECT organization_id FROM projects WHERE projects.id=findings.project_id),?) WHERE organization_id IS NULL").run(defaultOrganizationId);
      this.db.prepare("UPDATE findings SET fingerprint=organization_id||':'||fingerprint WHERE fingerprint NOT LIKE organization_id||':%'").run();
      this.db.prepare("UPDATE credential_profiles SET organization_id=COALESCE((SELECT organization_id FROM targets WHERE targets.id=credential_profiles.target_id),(SELECT organization_id FROM projects WHERE projects.id=credential_profiles.project_id),?) WHERE organization_id IS NULL").run(defaultOrganizationId);
    });
  }

  private applyForeignKeyRebuildMigration(migration: { version: number; sql: string }): void {
    this.db.pragma("foreign_keys = OFF");
    this.db.pragma("legacy_alter_table = ON");
    try {
      const apply = this.db.transaction(() => {
        this.db.exec(migration.sql);
        this.db.prepare("INSERT INTO dashboard_migrations (version, applied_at) VALUES (?, ?)").run(migration.version, nowIso());
      });
      apply();
    } finally {
      this.db.pragma("legacy_alter_table = OFF");
      this.db.pragma("foreign_keys = ON");
    }

    const violations = this.db.pragma("foreign_key_check") as unknown[];
    if (violations.length > 0) {
      throw new Error(`Dashboard migration ${migration.version} left ${violations.length} foreign-key violation(s).`);
    }
  }

  public recoverInterruptedScans(): void {
    const interruptedAt = nowIso();
    const tx = this.db.transaction(() => {
      const rows = this.db
        .prepare("SELECT id FROM scans WHERE status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED')")
        .all() as Array<{ id: string }>;
      for (const row of rows) {
        this.db
          .prepare("UPDATE scans SET status = 'INTERRUPTED', completed_at = ?, error_summary = ? WHERE id = ?")
          .run(interruptedAt, "Dashboard process stopped before this in-memory queued or running scan reached a terminal state.", row.id);
        this.appendEvent(row.id, "SCAN_INTERRUPTED", "Dashboard startup marked an unfinished scan as interrupted.", {});
      }
    });
    tx();
  }

  public appendEvent(scanId: string, eventType: string, message: string, metadata: Record<string, unknown>, moduleId?: string): void {
    const row = this.db.prepare("SELECT COALESCE(MAX(seq), 0) + 1 AS nextSeq FROM scan_events WHERE scan_id = ?").get(scanId) as { nextSeq: number };
    this.db
      .prepare(
        "INSERT INTO scan_events (id, seq, scan_id, event_type, module_id, safe_message, safe_metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(randomUUID(), row.nextSeq, scanId, eventType, moduleId ?? null, clamp(message, 500), clamp(JSON.stringify(metadata), 4000), nowIso());
  }

  public transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  public close(): void {
    this.db.close();
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function clamp(value: string, maxLength: number): string {
  return value.length <= maxLength ? value : `${value.slice(0, Math.max(0, maxLength - 15))}<truncated>`;
}
