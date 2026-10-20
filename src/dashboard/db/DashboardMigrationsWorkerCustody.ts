export const DashboardMigrationsWorkerCustody = [{ version: 46, sql: `
CREATE TABLE worker_resources (
  resource_id TEXT PRIMARY KEY,
  worker_id TEXT NOT NULL UNIQUE,
  job_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  resource_receipt_json TEXT NOT NULL,
  process_identity_json TEXT,
  state TEXT NOT NULL CHECK(state IN ('CREATED','RUNNING','DRAINING','RETAINED','UNKNOWN_RETAINED')),
  evidence_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX worker_resources_job ON worker_resources(job_id);
` }] as const;
