export const DashboardMigrationsWorkflows: readonly {
  version: number;
  sql: string;
  requiresForeignKeysDisabled?: boolean;
}[] = [
{
    version: 16,
    sql: `
ALTER TABLE targets ADD COLUMN production_mutation_enabled INTEGER NOT NULL DEFAULT 0;
`
  },
{
    version: 17,
    sql: `
CREATE TABLE IF NOT EXISTS assisted_case_results (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  workflow_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  assessment_outcome TEXT NOT NULL CHECK (assessment_outcome IN ('PROVEN','INCONCLUSIVE','NOT_ASSESSED','BLOCKED')),
  conclusion TEXT NOT NULL CHECK (conclusion IN ('FINDING','NO_FINDING','UNRESOLVED','NOT_RUN')),
  cleanup_unresolved INTEGER NOT NULL,
  comparison_fingerprint TEXT,
  safe_result_json TEXT NOT NULL,
  PRIMARY KEY(scan_id, workflow_id, case_id)
);
CREATE TABLE IF NOT EXISTS assisted_review_runs (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  review_id TEXT NOT NULL,
  safe_report_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assisted_review_publications (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES assisted_review_runs(scan_id) ON DELETE CASCADE,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
  content_sha256 TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assisted_cases_comparison ON assisted_case_results(workflow_id, case_id, comparison_fingerprint);
`
  },
{
    version: 18,
    sql: `
ALTER TABLE controlled_mutation_approvals ADD COLUMN execution_scan_id TEXT REFERENCES scans(id) ON DELETE RESTRICT;
CREATE UNIQUE INDEX idx_mutation_approval_execution ON controlled_mutation_approvals(execution_scan_id) WHERE execution_scan_id IS NOT NULL;
`
  },
{
    version: 19,
    sql: `
CREATE TABLE workflow_recovery_jobs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  checkpoint_digest TEXT NOT NULL,
  target_id TEXT NOT NULL REFERENCES targets(id),
  status TEXT NOT NULL CHECK(status IN ('RUNNING','ROLLBACK_VERIFIED','CLEANUP_FAILED','INTERRUPTED')),
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  safe_summary TEXT NOT NULL
);
CREATE UNIQUE INDEX workflow_recovery_one_active ON workflow_recovery_jobs(case_id) WHERE status = 'RUNNING';
`
  },
{
    version: 20,
    sql: `
CREATE TABLE scan_executable_plans (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  schema_version INTEGER NOT NULL CHECK(schema_version = 1),
  target_origin TEXT NOT NULL,
  content_digest TEXT NOT NULL CHECK(length(content_digest) = 64),
  plan_binding TEXT NOT NULL CHECK(length(plan_binding) = 64),
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  created_at TEXT NOT NULL,
  worker_verified_at TEXT,
  worker_verified_binding TEXT
);
CREATE INDEX idx_scan_executable_plan_binding ON scan_executable_plans(plan_binding);
`
  },
{
    version: 21,
    sql: `
ALTER TABLE scan_workers ADD COLUMN heartbeat_sequence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_workers ADD COLUMN memory_rss_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_workers ADD COLUMN heap_used_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_workers ADD COLUMN cpu_user_micros INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_workers ADD COLUMN cpu_system_micros INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_workers ADD COLUMN output_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_workers ADD COLUMN temp_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_workers ADD COLUMN current_module TEXT;
ALTER TABLE scan_workers ADD COLUMN cleanup_state TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(cleanup_state IN ('CLEAR','PENDING','RUNNING','REQUIRED','UNKNOWN'));
ALTER TABLE scan_workers ADD COLUMN child_processes_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE scan_workers ADD COLUMN governance_policy_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE scan_workers ADD COLUMN failure_category TEXT;
ALTER TABLE scan_workers ADD COLUMN termination_reason TEXT;
ALTER TABLE scan_workers ADD COLUMN exit_code INTEGER;
ALTER TABLE scan_workers ADD COLUMN exit_signal TEXT;
ALTER TABLE scan_workers ADD COLUMN graceful_stop_requested_at TEXT;
ALTER TABLE scan_workers ADD COLUMN forced_termination_at TEXT;
ALTER TABLE scan_workers ADD COLUMN quarantined_at TEXT;
ALTER TABLE scan_workers ADD COLUMN quarantine_reason TEXT;
ALTER TABLE scan_workers ADD COLUMN updated_at TEXT;

CREATE TABLE worker_governance_state (
  id TEXT PRIMARY KEY CHECK(id = 'singleton'),
  dispatch_state TEXT NOT NULL CHECK(dispatch_state IN ('NORMAL','QUARANTINED')),
  crash_count INTEGER NOT NULL,
  crash_window_started_at TEXT,
  quarantine_reason TEXT,
  quarantined_at TEXT,
  updated_at TEXT NOT NULL
);
INSERT INTO worker_governance_state (id, dispatch_state, crash_count, updated_at)
VALUES ('singleton', 'NORMAL', 0, datetime('now'));
CREATE INDEX idx_workers_diagnostics ON scan_workers(state, started_at DESC);
`
  },
{
    version: 22,
    sql: `
ALTER TABLE credential_profiles ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE credential_profiles ADD COLUMN secret_replaced_at TEXT;
ALTER TABLE credential_profiles ADD COLUMN last_health_status TEXT NOT NULL DEFAULT 'UNVERIFIED'
  CHECK(last_health_status IN ('HEALTHY','NEAR_EXPIRY','EXPIRED','DISABLED','INVALID','IDENTITY_MISMATCH','UNVERIFIED'));
ALTER TABLE credential_profiles ADD COLUMN last_health_checked_at TEXT;
ALTER TABLE credential_profiles ADD COLUMN last_health_reason_code TEXT;
ALTER TABLE credential_profiles ADD COLUMN last_principal_fingerprint TEXT;

CREATE TABLE credential_health_events (
  id TEXT PRIMARY KEY,
  credential_profile_id TEXT NOT NULL REFERENCES credential_profiles(id) ON DELETE CASCADE,
  classification TEXT NOT NULL
    CHECK(classification IN ('HEALTHY','NEAR_EXPIRY','EXPIRED','DISABLED','INVALID','IDENTITY_MISMATCH','UNVERIFIED')),
  source TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  safe_summary TEXT NOT NULL,
  principal_fingerprint TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_credential_health_profile_time
  ON credential_health_events(credential_profile_id, created_at DESC);
`
  },
{
    version: 23,
    requiresForeignKeysDisabled: true,
    sql: `
ALTER TABLE targets RENAME TO targets_v22;

CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  display_name TEXT NOT NULL,
  base_origin TEXT NOT NULL,
  description TEXT,
  tags_json TEXT NOT NULL,
  classification TEXT NOT NULL CHECK (classification IN ('PUBLIC','PRIVATE','LOCAL','PRODUCTION','UNKNOWN')),
  authorization_type TEXT NOT NULL CHECK (authorization_type IN ('OWNED','CLIENT_AUTHORIZED','BUG_BOUNTY','CONTROLLED_LAB','OTHER_AUTHORIZED')),
  authorization_summary TEXT NOT NULL,
  approved_scope_json TEXT NOT NULL,
  default_profile TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT,
  row_version INTEGER NOT NULL DEFAULT 1,
  default_configuration_id TEXT,
  default_credential_profile_id TEXT,
  default_evidence_level TEXT,
  default_auth_template_json TEXT NOT NULL DEFAULT '{}',
  production_mutation_enabled INTEGER NOT NULL DEFAULT 0,
  UNIQUE(project_id, base_origin, display_name)
);

INSERT INTO targets (
  id, project_id, display_name, base_origin, description, tags_json,
  classification, authorization_type, authorization_summary,
  approved_scope_json, default_profile, created_by, created_at, updated_at,
  archived_at, row_version, default_configuration_id,
  default_credential_profile_id, default_evidence_level,
  default_auth_template_json, production_mutation_enabled
)
SELECT
  id, project_id, display_name, base_origin, description, tags_json,
  classification, authorization_type, authorization_summary,
  approved_scope_json, default_profile, created_by, created_at, updated_at,
  archived_at, row_version, default_configuration_id,
  default_credential_profile_id, default_evidence_level,
  default_auth_template_json, production_mutation_enabled
FROM targets_v22;

DROP TABLE targets_v22;

CREATE INDEX idx_targets_project ON targets(project_id);
CREATE INDEX idx_targets_origin ON targets(base_origin);
`
  },
{
    version: 24,
    sql: `
CREATE TABLE live_acceptance_plans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
  environment TEXT NOT NULL CHECK(environment IN ('STAGING','PRODUCTION')),
  status TEXT NOT NULL CHECK(status IN ('DRAFT','REVIEWED','ARCHIVED')),
  plan_digest TEXT NOT NULL CHECK(length(plan_digest) = 64),
  target_row_version INTEGER NOT NULL,
  scope_digest TEXT NOT NULL CHECK(length(scope_digest) = 64),
  authorization_mode TEXT NOT NULL,
  authorization_expires_at TEXT NOT NULL,
  lane_count INTEGER NOT NULL,
  algorithm TEXT NOT NULL,
  key_version TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  reviewed_by TEXT,
  reviewed_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_live_acceptance_plans_target ON live_acceptance_plans(target_id, updated_at DESC);

CREATE TABLE live_acceptance_runs (
  id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES live_acceptance_plans(id) ON DELETE RESTRICT,
  plan_digest TEXT NOT NULL CHECK(length(plan_digest) = 64),
  status TEXT NOT NULL CHECK(status IN ('RUNNING','COMPLETED','COMPLETED_WITH_GAPS','CANCELLED','FAILED')),
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  safe_error_summary TEXT
);
CREATE INDEX idx_live_acceptance_runs_plan ON live_acceptance_runs(plan_id, created_at DESC);

CREATE TABLE live_acceptance_run_lanes (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES live_acceptance_runs(id) ON DELETE CASCADE,
  lane_id TEXT NOT NULL,
  label TEXT NOT NULL,
  kind TEXT NOT NULL,
  required INTEGER NOT NULL,
  disposition TEXT NOT NULL,
  scan_id TEXT REFERENCES scans(id) ON DELETE RESTRICT,
  configured_outcome TEXT,
  safe_reason TEXT,
  ordinal INTEGER NOT NULL,
  UNIQUE(run_id, lane_id)
);
CREATE INDEX idx_live_acceptance_lanes_scan ON live_acceptance_run_lanes(scan_id);
`
  },
{
    version: 25,
    sql: `
CREATE TABLE adaptive_target_policies (
  target_id TEXT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
  required_lanes_json TEXT NOT NULL,
  require_na_evidence INTEGER NOT NULL CHECK(require_na_evidence IN (0,1)),
  detect_removed_surfaces INTEGER NOT NULL CHECK(detect_removed_surfaces IN (0,1)),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE adaptive_security_snapshots (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  source_scan_id TEXT NOT NULL UNIQUE REFERENCES scans(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK(status IN ('CANDIDATE','BASELINE','SUPERSEDED')),
  model_digest TEXT NOT NULL CHECK(length(model_digest) = 64),
  target_row_version INTEGER NOT NULL,
  build_fingerprint TEXT NOT NULL CHECK(length(build_fingerprint) = 64),
  inventory_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  accepted_by TEXT,
  accepted_at TEXT
);
CREATE INDEX idx_adaptive_snapshots_target ON adaptive_security_snapshots(target_id, created_at DESC);
CREATE UNIQUE INDEX idx_adaptive_one_baseline ON adaptive_security_snapshots(target_id) WHERE status='BASELINE';

CREATE TABLE adaptive_security_drifts (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  snapshot_id TEXT NOT NULL REFERENCES adaptive_security_snapshots(id) ON DELETE CASCADE,
  baseline_snapshot_id TEXT REFERENCES adaptive_security_snapshots(id) ON DELETE SET NULL,
  drift_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH')),
  semantic_key TEXT NOT NULL,
  semantic_fingerprint TEXT NOT NULL CHECK(length(semantic_fingerprint) = 64),
  safe_summary TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
  created_at TEXT NOT NULL
);
CREATE INDEX idx_adaptive_drifts_target ON adaptive_security_drifts(target_id, created_at DESC);

CREATE TABLE adaptive_security_recommendations (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  snapshot_id TEXT NOT NULL REFERENCES adaptive_security_snapshots(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  engine_id TEXT NOT NULL,
  lane_kind TEXT NOT NULL,
  source_fingerprint TEXT NOT NULL CHECK(length(source_fingerprint) = 64),
  status TEXT NOT NULL CHECK(status IN ('PROPOSED','APPROVED','DISMISSED','EXECUTION_LINKED','VERIFIED','INCONCLUSIVE')),
  mutation_hypothesis INTEGER NOT NULL CHECK(mutation_hypothesis IN (0,1)),
  operator_approval_required INTEGER NOT NULL CHECK(operator_approval_required IN (0,1)),
  safe_draft_json TEXT NOT NULL,
  required_bindings_json TEXT NOT NULL,
  operator_rationale TEXT,
  reviewed_by TEXT,
  reviewed_at TEXT,
  linked_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  linked_case_fingerprint TEXT CHECK(linked_case_fingerprint IS NULL OR length(linked_case_fingerprint) = 64),
  execution_outcome TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(snapshot_id, category, source_fingerprint)
);
CREATE INDEX idx_adaptive_recommendations_target ON adaptive_security_recommendations(target_id, created_at DESC);
CREATE INDEX idx_adaptive_recommendations_scan ON adaptive_security_recommendations(linked_scan_id);
`
  },
{
    version: 26,
    sql: `
ALTER TABLE live_acceptance_run_lanes
  ADD COLUMN evidence_scan_id TEXT REFERENCES scans(id) ON DELETE RESTRICT;

UPDATE live_acceptance_run_lanes
SET evidence_scan_id=scan_id, scan_id=NULL
WHERE disposition='NOT_APPLICABLE'
  AND configured_outcome='NOT_APPLICABLE'
  AND scan_id IS NOT NULL;

CREATE INDEX idx_live_acceptance_lanes_evidence_scan
  ON live_acceptance_run_lanes(evidence_scan_id);
`
  },
{
    version: 27,
    sql: `
CREATE TABLE provider_adapters (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
  provider TEXT NOT NULL,
  engine_id TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  active_version_id TEXT,
  pending_version_id TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  deleted_at TEXT
);
CREATE INDEX idx_provider_adapters_target ON provider_adapters(target_id,updated_at DESC);

CREATE TABLE provider_adapter_versions (
  id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL REFERENCES provider_adapters(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('DRAFT','REVIEWED','SUPERSEDED')),
  adapter_digest TEXT NOT NULL CHECK(length(adapter_digest)=64),
  target_row_version INTEGER NOT NULL,
  credential_binding_json TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  key_version TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  reviewed_by TEXT,
  reviewed_at TEXT,
  UNIQUE(profile_id,revision)
);
CREATE INDEX idx_provider_adapter_versions_profile ON provider_adapter_versions(profile_id,revision DESC);

CREATE TABLE provider_adapter_recommendation_bindings (
  recommendation_id TEXT PRIMARY KEY REFERENCES adaptive_security_recommendations(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES provider_adapters(id) ON DELETE CASCADE,
  version_id TEXT NOT NULL REFERENCES provider_adapter_versions(id) ON DELETE RESTRICT,
  source_fingerprint TEXT NOT NULL CHECK(length(source_fingerprint)=64),
  bound_by TEXT NOT NULL,
  bound_at TEXT NOT NULL
);
CREATE INDEX idx_provider_adapter_recommendation_profile ON provider_adapter_recommendation_bindings(profile_id);

CREATE TABLE scan_provider_adapter_bindings (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES provider_adapters(id) ON DELETE RESTRICT,
  version_id TEXT NOT NULL REFERENCES provider_adapter_versions(id) ON DELETE RESTRICT,
  adapter_digest TEXT NOT NULL CHECK(length(adapter_digest)=64),
  created_at TEXT NOT NULL
);
CREATE INDEX idx_scan_provider_adapter_profile ON scan_provider_adapter_bindings(profile_id,created_at DESC);
`
  },
{
    version: 28,
    sql: `
CREATE TABLE continuous_assurance_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK(status IN ('DRAFT','ACTIVE','DISABLED','ARCHIVED')),
  active_version_id TEXT,
  pending_version_id TEXT,
  trigger_token_hash TEXT NOT NULL CHECK(length(trigger_token_hash)=64),
  trigger_token_rotated_at TEXT NOT NULL,
  next_due_at TEXT,
  last_run_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  deleted_at TEXT
);
CREATE INDEX idx_continuous_assurance_due ON continuous_assurance_policies(status,next_due_at);
CREATE INDEX idx_continuous_assurance_target ON continuous_assurance_policies(target_id,updated_at DESC);

CREATE TABLE continuous_assurance_policy_versions (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL REFERENCES continuous_assurance_policies(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('DRAFT','REVIEWED','SUPERSEDED')),
  policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
  target_row_version INTEGER NOT NULL,
  policy_json TEXT NOT NULL,
  adapter_bindings_json TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  reviewed_by TEXT,
  reviewed_at TEXT,
  UNIQUE(policy_id,revision)
);
CREATE INDEX idx_continuous_assurance_versions ON continuous_assurance_policy_versions(policy_id,revision DESC);

CREATE TABLE continuous_assurance_runs (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL REFERENCES continuous_assurance_policies(id) ON DELETE RESTRICT,
  version_id TEXT NOT NULL REFERENCES continuous_assurance_policy_versions(id) ON DELETE RESTRICT,
  policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
  trigger_type TEXT NOT NULL CHECK(trigger_type IN ('MANUAL','SCHEDULE','DEPLOYMENT')),
  trigger_reference TEXT,
  build_fingerprint TEXT,
  status TEXT NOT NULL CHECK(status IN ('LAUNCHING','RUNNING','COMPLETED','FAILED','BLOCKED','CANCELLED')),
  gate_status TEXT NOT NULL CHECK(gate_status IN ('PENDING','PASSED','REGRESSION','INCONCLUSIVE','BLOCKED')),
  requested_by TEXT NOT NULL,
  installation_id TEXT NOT NULL,
  safe_summary_json TEXT NOT NULL DEFAULT '{}',
  comparison_ids_json TEXT NOT NULL DEFAULT '[]',
  notification_required INTEGER NOT NULL DEFAULT 0 CHECK(notification_required IN (0,1)),
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);
CREATE INDEX idx_continuous_assurance_runs_policy ON continuous_assurance_runs(policy_id,created_at DESC);

CREATE TABLE continuous_assurance_run_scans (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES continuous_assurance_runs(id) ON DELETE CASCADE,
  adapter_profile_id TEXT NOT NULL REFERENCES provider_adapters(id) ON DELETE RESTRICT,
  adapter_version_id TEXT NOT NULL REFERENCES provider_adapter_versions(id) ON DELETE RESTRICT,
  adapter_digest TEXT NOT NULL CHECK(length(adapter_digest)=64),
  scan_id TEXT REFERENCES scans(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK(status IN ('PENDING','QUEUED','COMPLETED','FAILED','BLOCKED','CANCELLED')),
  safe_error_summary TEXT,
  ordinal INTEGER NOT NULL,
  UNIQUE(run_id,adapter_profile_id)
);
CREATE INDEX idx_continuous_assurance_run_scan ON continuous_assurance_run_scans(scan_id);

CREATE TABLE continuous_assurance_leases (
  policy_id TEXT PRIMARY KEY REFERENCES continuous_assurance_policies(id) ON DELETE CASCADE,
  owner_installation_id TEXT NOT NULL,
  lease_token TEXT NOT NULL,
  lease_expires_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL
);

CREATE TABLE continuous_assurance_deployments (
  policy_id TEXT NOT NULL REFERENCES continuous_assurance_policies(id) ON DELETE CASCADE,
  deployment_id TEXT NOT NULL,
  build_fingerprint TEXT NOT NULL CHECK(length(build_fingerprint)=64),
  run_id TEXT REFERENCES continuous_assurance_runs(id) ON DELETE SET NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY(policy_id,deployment_id)
);

CREATE TABLE continuous_assurance_notifications (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES continuous_assurance_runs(id) ON DELETE CASCADE,
  category TEXT NOT NULL CHECK(category IN ('REGRESSION','FAILED','CLEANUP_REQUIRED','APPROVAL_REQUIRED')),
  severity TEXT NOT NULL CHECK(severity IN ('INFO','WARNING','CRITICAL')),
  safe_summary TEXT NOT NULL,
  created_at TEXT NOT NULL,
  acknowledged_by TEXT,
  acknowledged_at TEXT
);
CREATE INDEX idx_continuous_assurance_notifications ON continuous_assurance_notifications(acknowledged_at,created_at DESC);

CREATE TABLE evidence_governance_policy (
  id INTEGER PRIMARY KEY CHECK(id=1),
  retention_days INTEGER NOT NULL,
  preserve_failed_scans INTEGER NOT NULL CHECK(preserve_failed_scans IN (0,1)),
  preserve_unresolved_cleanup INTEGER NOT NULL CHECK(preserve_unresolved_cleanup IN (0,1)),
  preserve_unreviewed_findings INTEGER NOT NULL CHECK(preserve_unreviewed_findings IN (0,1)),
  maximum_export_bytes INTEGER NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE evidence_exports (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('CREATING','READY','FAILED','PURGING','DELETED')),
  scan_count INTEGER NOT NULL,
  artifact_count INTEGER NOT NULL DEFAULT 0,
  plaintext_bytes INTEGER NOT NULL DEFAULT 0,
  ciphertext_bytes INTEGER NOT NULL DEFAULT 0,
  manifest_digest TEXT,
  signature TEXT,
  algorithm TEXT NOT NULL,
  key_version TEXT NOT NULL,
  canonical_path TEXT,
  safe_error_summary TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  verified_at TEXT,
  deleted_at TEXT
);

CREATE TABLE evidence_export_scans (
  export_id TEXT NOT NULL REFERENCES evidence_exports(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
  PRIMARY KEY(export_id,scan_id)
);

CREATE TABLE evidence_purge_actions (
  id TEXT PRIMARY KEY,
  preview_digest TEXT NOT NULL CHECK(length(preview_digest)=64),
  candidate_count INTEGER NOT NULL,
  purged_count INTEGER NOT NULL,
  failed_count INTEGER NOT NULL,
  reclaimed_bytes INTEGER NOT NULL,
  safe_failures_json TEXT NOT NULL,
  executed_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`
  },
{
    version: 29,
    sql: `
ALTER TABLE live_acceptance_plans ADD COLUMN standard TEXT NOT NULL DEFAULT 'CUSTOM'
  CHECK(standard IN ('CUSTOM','BROADER_REAL_TARGET_V1'));
ALTER TABLE live_acceptance_runs ADD COLUMN standard TEXT NOT NULL DEFAULT 'CUSTOM'
  CHECK(standard IN ('CUSTOM','BROADER_REAL_TARGET_V1'));
ALTER TABLE live_acceptance_run_lanes ADD COLUMN proof_contract_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE live_acceptance_run_lanes ADD COLUMN baseline_scan_id TEXT REFERENCES scans(id) ON DELETE RESTRICT;
ALTER TABLE live_acceptance_run_lanes ADD COLUMN comparison_id TEXT REFERENCES scan_comparisons(id) ON DELETE RESTRICT;
CREATE INDEX idx_live_acceptance_lanes_baseline_scan ON live_acceptance_run_lanes(baseline_scan_id);
CREATE INDEX idx_live_acceptance_lanes_comparison ON live_acceptance_run_lanes(comparison_id);
`
  },
{
    version: 30,
    sql: `
CREATE TABLE organizations (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','SUSPENDED','ARCHIVED')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE organization_memberships (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('OWNER','ADMIN','ANALYST','VIEWER')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(organization_id,user_id)
);
CREATE INDEX idx_organization_members_user ON organization_memberships(user_id,organization_id);

CREATE TABLE sso_providers (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  authorization_endpoint TEXT NOT NULL,
  token_endpoint TEXT NOT NULL,
  jwks_uri TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret_env TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  allowed_domains_json TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(organization_id,name)
);

CREATE TABLE sso_identities (
  provider_id TEXT NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
  email_fingerprint TEXT,
  created_at TEXT NOT NULL,
  last_login_at TEXT,
  PRIMARY KEY(provider_id,subject)
);

CREATE TABLE sso_login_states (
  state_hash TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
  verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE notification_channels (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('WEBHOOK','SLACK','EMAIL','GITHUB','JIRA')),
  endpoint TEXT,
  secret_env TEXT,
  configuration_json TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(organization_id,name)
);

CREATE TABLE notification_deliveries (
  id TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  safe_payload_json TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING','DELIVERING','DELIVERED','RETRY','FAILED')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_attempt_at TEXT,
  delivered_at TEXT,
  response_status INTEGER,
  safe_error TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(channel_id,idempotency_key)
);
CREATE INDEX idx_notification_delivery_due ON notification_deliveries(status,next_attempt_at);

CREATE TABLE remote_worker_enrollments (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  name_hint TEXT,
  expires_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE remote_workers (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  public_key_pem TEXT NOT NULL,
  public_key_fingerprint TEXT NOT NULL UNIQUE,
  capabilities_json TEXT NOT NULL,
  labels_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ONLINE','OFFLINE','DRAINING','QUARANTINED','REVOKED')),
  generation INTEGER NOT NULL DEFAULT 1,
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_remote_workers_org ON remote_workers(organization_id,status,last_seen_at);

CREATE TABLE remote_worker_nonces (
  worker_id TEXT NOT NULL REFERENCES remote_workers(id) ON DELETE CASCADE,
  nonce TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY(worker_id,nonce)
);

CREATE TABLE remote_jobs (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('SCAN','EXPORT','MODULE','PING')),
  safe_payload_json TEXT NOT NULL,
  required_capabilities_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('QUEUED','LEASED','RUNNING','COMPLETED','FAILED','CANCELLED')),
  priority INTEGER NOT NULL DEFAULT 0,
  assigned_worker_id TEXT REFERENCES remote_workers(id) ON DELETE SET NULL,
  lease_token_hash TEXT,
  lease_expires_at TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  safe_result_json TEXT,
  safe_error TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);
CREATE INDEX idx_remote_jobs_dispatch ON remote_jobs(organization_id,status,priority DESC,created_at);

CREATE TABLE cloud_sync_peers (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  shared_secret_env TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  outbound_cursor INTEGER NOT NULL DEFAULT 0,
  inbound_cursor INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(organization_id,name)
);

CREATE TABLE cloud_sync_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL UNIQUE,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('UPSERT','DELETE')),
  safe_payload_json TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  origin_installation_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_cloud_sync_events_org ON cloud_sync_events(organization_id,sequence);

CREATE TABLE operational_backups (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('CREATING','READY','VERIFIED','RESTORE_STAGED','FAILED','DELETED')),
  path TEXT,
  manifest_digest TEXT,
  byte_size INTEGER NOT NULL DEFAULT 0,
  encrypted INTEGER NOT NULL CHECK(encrypted IN (0,1)),
  key_version TEXT,
  safe_error TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  verified_at TEXT,
  restore_staged_at TEXT
);

CREATE TABLE integration_exports (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  format TEXT NOT NULL CHECK(format IN ('SARIF','JUNIT','BURP_XML','JSON')),
  scan_id TEXT REFERENCES scans(id) ON DELETE RESTRICT,
  path TEXT NOT NULL,
  artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
  item_count INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE third_party_modules (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  module_id TEXT NOT NULL,
  version TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  package_path TEXT NOT NULL,
  package_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('REGISTERED','APPROVED','DISABLED','QUARANTINED')),
  approved_by TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(organization_id,module_id,version)
);
`
  }
];
