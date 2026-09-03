import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { ExecutablePlanStore } from "../../src/dashboard/execution/ExecutablePlanStore.js";
import { assertExecutablePlanSourcesUnchanged, captureExecutablePlanSources, createExecutablePlanPayload, executablePlanContentDigest } from "../../src/dashboard/execution/ExecutablePlanSnapshot.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

describe("immutable executable plan snapshots", () => {
  it("encrypts, authenticates, and target-binds the complete executable plan", () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-executable-plan-"));
    const paths = resolveDashboardPaths(directory);
    const database = new DashboardDatabase(paths.databasePath);
    try {
      database.migrate();
      const scanId = randomUUID();
      const target = "https://example.test/";
      const scope = { ...exampleScope, program: "immutable-plan-sensitive-sentinel", allowedDomains: ["example.test"] };
      const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", config: defaultConfig, scope, overrides: { includeModules: ["baseline"] } });
      new ScanRepository(database).create({ id: scanId, source: "DASHBOARD", status: "QUEUED", targetOrigin: new URL(target).origin, safeTargetLabel: target, profile: "quick", evidenceLevel: "pending", safeConfigurationSummary: {} });
      const payload = createExecutablePlanPayload(target, { plan, config: defaultConfig, scope }, { safeSummary: { mode: "public" } });
      const store = new ExecutablePlanStore(database, paths.executablePlanKeyPath);
      const saved = store.save(scanId, new URL(target).origin, payload);
      const row = database.db.prepare("SELECT ciphertext, nonce, auth_tag, plan_binding FROM scan_executable_plans WHERE scan_id = ?").get(scanId) as Record<string, string>;
      expect(JSON.stringify(row)).not.toContain("immutable-plan-sensitive-sentinel");
      expect(saved.binding).toMatch(/^[a-f0-9]{64}$/);
      expect(store.load(scanId, new URL(target).origin)).toEqual(saved);
      expect(() => store.load(scanId, "https://other.test")).toThrow("EXECUTABLE_PLAN_TARGET_BINDING_INVALID");

      const changed = { ...payload, plan: { ...payload.plan, failurePolicy: payload.plan.failurePolicy === "fail-fast" ? "continue-on-module-error" as const : "fail-fast" as const } };
      expect(executablePlanContentDigest(changed)).not.toBe(saved.contentDigest);

      database.db.prepare("UPDATE scan_executable_plans SET ciphertext = ? WHERE scan_id = ?").run(`${row.ciphertext.startsWith("A") ? "B" : "A"}${row.ciphertext.slice(1)}`, scanId);
      expect(() => store.load(scanId, new URL(target).origin)).toThrow("EXECUTABLE_PLAN_SNAPSHOT_AUTHENTICATION_FAILED");
    } finally {
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("detects a changed or deleted source manifest without exposing its path", async () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-executable-source-"));
    try {
      const scopeFile = join(directory, "scope.json");
      writeFileSync(scopeFile, JSON.stringify({ ...exampleScope, allowedDomains: ["example.test"] }));
      const bindings = await captureExecutablePlanSources({ target: "https://example.test", profile: "quick", scopeFile });
      await expect(assertExecutablePlanSourcesUnchanged(bindings)).resolves.toBeUndefined();
      writeFileSync(scopeFile, JSON.stringify({ ...exampleScope, allowedDomains: ["changed.test"] }));
      await expect(assertExecutablePlanSourcesUnchanged(bindings)).rejects.toThrow("EXECUTABLE_PLAN_SOURCE_CHANGED:scopeFile");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
