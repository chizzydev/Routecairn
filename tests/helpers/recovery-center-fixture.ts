import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TargetRepository, ScanRepository, PlanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { RecoveryCenterService } from "../../src/dashboard/recovery/RecoveryCenterService.js";
import type { RecoveryScope } from "../../src/dashboard/contracts/RecoveryCenterContracts.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
import { exampleScope } from "../../src/config/defaults.js";
export function recoveryCenterFixture() {
  const root = createOwnedTestDirectory("recovery-center-"),
    database = new DashboardDatabase(resolveDashboardPaths(root).databasePath);
  database.migrate();
  const organizations = new OrganizationService(database),
    org = organizations.defaultOrganizationId(),
    other = organizations.create(
      { name: "Other synthetic organization", slug: "other-" + randomUUID() },
      "local-operator"
    );
  const target = new TargetRepository(database).create({
    displayName: "Synthetic recovery target",
    baseOrigin: "http://127.0.0.1:47999",
    tags: [],
    classification: "LOCAL",
    authorizationType: "OWNED",
    authorizationSummary: "Synthetic rows only; no target traffic",
    approvedScope: exampleScope,
    productionEnabled: false
  });
  const ids = [randomUUID(), randomUUID()];
  for (const id of ids) {
    new ScanRepository(database).create({
      id,
      source: "DASHBOARD",
      status: "COMPLETED",
      targetOrigin: "http://127.0.0.1:47999",
      safeTargetLabel: "SEEDED_NOT_EXECUTED",
      profile: "full",
      evidenceLevel: "normal",
      safeConfigurationSummary: {},
      targetId: target
    });
    new PlanRepository(database).create(id, {
      plannerVersion: "1",
      profile: "full",
      modules: [{ id: "baseline" }],
      limits: { maxRequests: 1 },
      evidencePolicy: { level: "normal" },
      browserPolicySummary: {},
      scopeSummary: { allowedDomains: ["127.0.0.1"], disallowedPaths: [], includeSubdomains: false },
      authenticationSummary: { mode: "public" },
      controlledWorkflowSummary: {},
      redactedPlan: {}
    });
  }
  const now = new Date().toISOString(),
    resourceId = randomUUID(),
    comparisonId = randomUUID();
  database.db
    .prepare(
      "INSERT INTO worker_resources(resource_id,worker_id,job_id,generation,resource_receipt_json,state,evidence_json,created_at,updated_at) VALUES(?,?,?,?,?,'UNKNOWN_RETAINED',?,?,?)"
    )
    .run(
      resourceId,
      randomUUID(),
      ids[1],
      randomUUID(),
      JSON.stringify({ secret: "RAW_WORKER_SECRET" }),
      JSON.stringify({
        custody: { rootClosed: true, rootOnlyFallback: true, job: { failure: "RAW_ERROR_SECRET" } },
        secret: "RAW_EVIDENCE_SECRET"
      }),
      now,
      now
    );
  database.db
    .prepare(
      "INSERT INTO scan_comparisons(id,older_scan_id,newer_scan_id,state,compatibility_state,source_quality_older,source_quality_newer,created_at,engine_version,coverage_algorithm_version,summary_json,coverage_summary_json,warning_json) VALUES(?,?,?,'FAILED','FAILED','NATIVE_FULL','NATIVE_FULL',?,'3.0.0','3.0.0','{}','{}','[]')"
    )
    .run(comparisonId, ids[0], ids[1], now);
  const policy = randomUUID(),
    version = randomUUID();
  database.db
    .prepare(
      "INSERT INTO continuous_assurance_policies(id,name,description,target_id,status,trigger_token_hash,trigger_token_rotated_at,created_by,created_at,updated_at) VALUES(?, 'Synthetic policy','fixture',?,'ACTIVE',?,?,'fixture',?,?)"
    )
    .run(policy, target, "a".repeat(64), now, now, now);
  database.db
    .prepare(
      "INSERT INTO continuous_assurance_policy_versions(id,policy_id,revision,status,policy_digest,target_row_version,policy_json,adapter_bindings_json,created_by,created_at) VALUES(?,?,1,'REVIEWED',?,1,'{}','[]','fixture',?)"
    )
    .run(version, policy, "a".repeat(64), now);
  const run = randomUUID();
  database.db
    .prepare(
      "INSERT INTO continuous_assurance_runs(id,policy_id,version_id,policy_digest,trigger_type,status,gate_status,requested_by,installation_id,safe_summary_json,created_at) VALUES(?,?,?,?,'DEPLOYMENT','BLOCKED','INCONCLUSIVE','fixture','fixture',?,?)"
    )
    .run(
      run,
      policy,
      version,
      "a".repeat(64),
      JSON.stringify({ launchOutcome: "UNKNOWN", secret: "RAW_ASSURANCE_SECRET" }),
      now
    );
  database.db
    .prepare(
      "INSERT INTO continuous_assurance_deployments(policy_id,deployment_id,build_fingerprint,run_id,received_at) VALUES(?, 'RAW_DEPLOYMENT_SECRET', ?, NULL, ?)"
    )
    .run(policy, "b".repeat(64), now);
  const scope: RecoveryScope = {
    organizationId: org,
    actor: "local-operator",
    canReview: true,
    canManageWorkers: true,
    canRecover: true,
    canRecompute: true
  };
  const emptyWorkflow = {
    inventory: async () => ({ cases: [], jobs: [], globalMutationActive: false, cleanupRequired: 0, modes: {} })
  };
  const service = new RecoveryCenterService(database, emptyWorkflow as never);
  const capture = (name: string) =>
    writeFileSync(
      join(root, name + ".json"),
      JSON.stringify(
        {
          provenance: "SEEDED_NOT_EXECUTED_NO_NETWORK",
          integrity: database.db.pragma("integrity_check"),
          foreignKeys: database.db.pragma("foreign_key_check"),
          resources: database.db.prepare("SELECT * FROM worker_resources").all(),
          assurance: database.db.prepare("SELECT * FROM continuous_assurance_runs").all(),
          deployments: database.db.prepare("SELECT * FROM continuous_assurance_deployments").all(),
          comparisons: database.db.prepare("SELECT * FROM scan_comparisons").all(),
          reviews: database.db.prepare("SELECT * FROM operator_uncertainty_reviews").all(),
          attempts: database.db.prepare("SELECT * FROM operator_comparison_attempts").all()
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  return {
    root,
    database,
    scope,
    other,
    resourceId,
    comparisonId,
    ids,
    policy,
    service,
    emptyWorkflow,
    capture,
    close() {
      capture("NATIVE_SQLITE_RECEIPT");
      database.close();
      retainOwnedTestDirectory(root);
    }
  };
}
