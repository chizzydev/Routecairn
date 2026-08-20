import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { RetestTemplateVault } from "../../src/dashboard/retests/RetestTemplateVault.js";

describe("encrypted retest workflow templates", () => {
  it("restores schema-validated workflow values without exposing plaintext in the database", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-retest-template-"));
    const database = new DashboardDatabase(resolve(dir, "dashboard.sqlite"));
    try {
      database.migrate();
      const scanId = "11111111-1111-4111-8111-111111111111";
      database.db.prepare("INSERT INTO scans (id, source, status, target_origin, safe_target_label, profile, evidence_level, created_at, safe_configuration_summary) VALUES (?, 'DASHBOARD', 'COMPLETED', 'https://app.example.com', 'app', 'authenticated', 'strong', datetime('now'), '{}')").run(scanId);
      const key = { bytes: Buffer.alloc(32, 7), version: "test-1" };
      const vault = new RetestTemplateVault(database.db, key);
      const config = JSON.parse(readFileSync(resolve("examples", "authorization-matrix.example.json"), "utf8"));
      vault.save(scanId, [{ workflowId: "authorization-matrix", enabled: true, editorMode: "guided", disabledCaseIds: [], config }]);
      const row = database.db.prepare("SELECT ciphertext, nonce, auth_tag, workflow_count FROM scan_retest_templates WHERE scan_id = ?").get(scanId) as Record<string, unknown>;
      expect(JSON.stringify(row)).not.toContain("fictional-doc-owned-by-a");
      expect(row.workflow_count).toBe(1);
      const restored = vault.load(scanId)?.[0];
      expect(restored).toMatchObject({ workflowId: "authorization-matrix" });
      expect(restored && "config" in restored && restored.config.matrices[0]?.cases[0]).toMatchObject({ objectId: "fictional-doc-owned-by-a" });
      expect(() => new RetestTemplateVault(database.db, { bytes: Buffer.alloc(32, 9), version: "test-1" }).load(scanId)).toThrow();
      expect(new RetestTemplateVault(database.db).load(scanId)).toBeUndefined();
      const nextKey = { bytes: Buffer.alloc(32, 8), version: "test-2" };
      expect(vault.rotateKey(nextKey)).toBe(1);
      expect(new RetestTemplateVault(database.db, nextKey).load(scanId)?.[0]).toMatchObject({ workflowId: "authorization-matrix" });
      expect(() => vault.load(scanId)).toThrow(/key version/i);
    } finally {
      database.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
