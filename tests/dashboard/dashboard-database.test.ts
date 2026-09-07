import { mkdtempSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";

describe("dashboard database", () => {
  it("migrates idempotently and enables foreign keys", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-dashboard-db-"));
    try {
      const database = new DashboardDatabase(resolve(dir, "dashboard.sqlite"));
      database.migrate();
      database.migrate();
      const foreignKeys = database.db.pragma("foreign_keys", { simple: true });
      const journalMode = database.db.pragma("journal_mode", { simple: true });
      expect(foreignKeys).toBe(1);
      expect(String(journalMode).toLowerCase()).toBe("wal");
      database.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("accepts production targets after rebuilding the legacy classification constraint", () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-dashboard-production-target-"));
    const database = new DashboardDatabase(join(directory, "dashboard.sqlite"));
    try {
      database.migrate();
      const projectId = randomUUID();
      const targetId = randomUUID();
      const now = new Date().toISOString();
      database.db.prepare(
        "INSERT INTO projects (id, name, tags_json, default_scope_json, created_at, updated_at) VALUES (?, ?, '[]', '{}', ?, ?)"
      ).run(projectId, "Production acceptance", now, now);
      database.db.prepare(
        `INSERT INTO targets (
          id, project_id, display_name, base_origin, tags_json, classification,
          authorization_type, authorization_summary, approved_scope_json,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, '[]', 'PRODUCTION', 'OWNED', ?, '{}', ?, ?)`
      ).run(targetId, projectId, "Owned production", "https://example.test", "Explicitly authorized owned target", now, now);

      const stored = database.db.prepare("SELECT classification FROM targets WHERE id = ?").get(targetId) as { classification: string };
      expect(stored.classification).toBe("PRODUCTION");
      expect(database.db.pragma("foreign_key_check")).toEqual([]);
    } finally {
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("recovers interrupted queued and running scans on startup", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-dashboard-recovery-"));
    try {
      const database = new DashboardDatabase(resolve(dir, "dashboard.sqlite"));
      database.migrate();
      const scans = new ScanRepository(database);
      scans.create({
        id: "11111111-1111-4111-8111-111111111111",
        source: "DASHBOARD",
        status: "RUNNING",
        targetOrigin: "https://example.test",
        safeTargetLabel: "https://example.test",
        profile: "quick",
        evidenceLevel: "minimal",
        safeConfigurationSummary: {}
      });
      scans.create({
        id: "22222222-2222-4222-8222-222222222222",
        source: "DASHBOARD",
        status: "QUEUED",
        targetOrigin: "https://queued.example.test",
        safeTargetLabel: "https://queued.example.test",
        profile: "quick",
        evidenceLevel: "minimal",
        safeConfigurationSummary: {}
      });
      database.recoverInterruptedScans();
      expect(scans.get("11111111-1111-4111-8111-111111111111")?.status).toBe("INTERRUPTED");
      expect(scans.get("22222222-2222-4222-8222-222222222222")?.status).toBe("INTERRUPTED");
      expect(database.db.prepare("SELECT event_type FROM scan_events WHERE scan_id = ?").all("11111111-1111-4111-8111-111111111111")).toHaveLength(1);
      database.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
