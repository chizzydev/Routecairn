export const dashboardSchemaVersion = 31;

export const dashboardMigrations: readonly {
  version: number;
  sql: string;
  requiresForeignKeysDisabled?: boolean;
}[] = [
  {
    version: 1,
    sql: `
CREATE TABLE IF NOT EXISTS dashboard_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  display_sequence INTEGER,
  source TEXT NOT NULL CHECK (source IN ('DASHBOARD','CLI_IMPORTED','REPORT_IMPORTED')),
  status TEXT NOT NULL CHECK (status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED','CANCELLED','COMPLETED','FAILED','INTERRUPTED','IMPORTED')),
  target_origin TEXT NOT NULL,
  safe_target_label TEXT NOT NULL,
  profile TEXT NOT NULL,
  legacy_mode TEXT,
  evidence_level TEXT NOT NULL,
  created_at TEXT NOT NULL,
  queued_at TEXT,
  started_at TEXT,
  completed_at TEXT,
  cancelled_at TEXT,
  duration_ms INTEGER,
  current_module TEXT,
  planned_module_count INTEGER NOT NULL DEFAULT 0,
  completed_module_count INTEGER NOT NULL DEFAULT 0,
  failed_module_count INTEGER NOT NULL DEFAULT 0,
  blocked_module_count INTEGER NOT NULL DEFAULT 0,
  finding_count INTEGER NOT NULL DEFAULT 0,
  observation_count INTEGER NOT NULL DEFAULT 0,
  error_summary TEXT,
  safe_configuration_summary TEXT NOT NULL,
  output_directory TEXT,
  json_report_artifact_id TEXT,
  markdown_report_artifact_id TEXT,
  html_report_artifact_id TEXT,
  import_limitation_summary TEXT,
  archived_at TEXT,
  deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_plan_snapshots (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
  planner_version TEXT NOT NULL,
  profile TEXT NOT NULL,
  modules_json TEXT NOT NULL,
  limits_json TEXT NOT NULL,
  evidence_policy_json TEXT NOT NULL,
  browser_policy_summary_json TEXT NOT NULL,
  scope_summary_json TEXT NOT NULL,
  authentication_summary_json TEXT NOT NULL,
  controlled_workflow_summary_json TEXT NOT NULL,
  redacted_plan_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_module_executions (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  module_id TEXT NOT NULL,
  module_label TEXT NOT NULL,
  planned_order INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','COMPLETED','BLOCKED','SKIPPED','FAILED','CANCELLED')),
  started_at TEXT,
  completed_at TEXT,
  duration_ms INTEGER,
  planned_request_count INTEGER,
  executed_request_count INTEGER NOT NULL DEFAULT 0,
  finding_count INTEGER NOT NULL DEFAULT 0,
  observation_count INTEGER NOT NULL DEFAULT 0,
  safe_failure_category TEXT,
  safe_failure_summary TEXT,
  UNIQUE(scan_id, planned_order, module_id)
);

CREATE TABLE IF NOT EXISTS scan_events (
  id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  module_id TEXT,
  safe_message TEXT NOT NULL,
  safe_metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(scan_id, seq)
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  target_identity TEXT NOT NULL,
  module TEXT NOT NULL,
  finding_category TEXT NOT NULL,
  safe_endpoint_identity TEXT NOT NULL,
  safe_authorization_boundary_identity TEXT NOT NULL,
  canonical_title TEXT NOT NULL,
  current_scanner_severity TEXT NOT NULL,
  current_scanner_confidence TEXT NOT NULL,
  human_review_status TEXT NOT NULL CHECK (human_review_status IN ('UNREVIEWED','IN_REVIEW','CONFIRMED','FALSE_POSITIVE','ACCEPTED_RISK','DUPLICATE','RESOLVED','REOPENED')),
  remediation_status TEXT NOT NULL CHECK (remediation_status IN ('OPEN','FIX_IN_PROGRESS','FIXED_PENDING_RETEST','FIXED_VERIFIED','WONT_FIX')),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_occurrence_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  duplicate_of_finding_id TEXT REFERENCES findings(id),
  assignee_label TEXT,
  archived_at TEXT
);

CREATE TABLE IF NOT EXISTS finding_occurrences (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  module TEXT NOT NULL,
  finding_category TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  title TEXT NOT NULL,
  safe_endpoint TEXT NOT NULL,
  safe_actor_relationship TEXT,
  safe_tenant_or_role_boundary TEXT,
  safe_state_boundary TEXT,
  description TEXT,
  impact TEXT,
  reproduction_steps TEXT,
  remediation TEXT,
  limitations TEXT,
  evidence_summary TEXT NOT NULL,
  finding_source_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_reviews (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  previous_review_status TEXT,
  new_review_status TEXT NOT NULL,
  reason TEXT,
  review_note TEXT,
  duplicate_target_finding_id TEXT REFERENCES findings(id),
  created_at TEXT NOT NULL,
  local_reviewer_label TEXT,
  source TEXT NOT NULL CHECK (source IN ('HUMAN','SYSTEM_REOPEN','IMPORT'))
);

CREATE TABLE IF NOT EXISTS evidence_records (
  id TEXT PRIMARY KEY,
  finding_occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  evidence_level TEXT NOT NULL,
  safe_summary TEXT NOT NULL,
  safe_structured_data_json TEXT NOT NULL,
  scoped_fingerprint TEXT,
  artifact_id TEXT,
  byte_count INTEGER,
  retention_classification TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  proof_pack_id TEXT,
  artifact_type TEXT NOT NULL,
  safe_display_name TEXT NOT NULL,
  canonical_path TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  content_type TEXT NOT NULL,
  scoped_or_full_safe_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  retention_state TEXT NOT NULL,
  missing_file_flag INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS proof_packs (
  id TEXT PRIMARY KEY,
  safe_title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL CHECK (status IN ('DRAFT','GENERATING','READY','FAILED')),
  version INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  generated_at TEXT,
  source_scan_ids_json TEXT NOT NULL,
  scope_summary TEXT NOT NULL,
  included_finding_count INTEGER NOT NULL DEFAULT 0,
  output_artifact_ids_json TEXT NOT NULL,
  generation_error TEXT,
  immutable_snapshot_metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proof_pack_findings (
  proof_pack_id TEXT NOT NULL REFERENCES proof_packs(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  selected_occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id),
  sort_order INTEGER NOT NULL,
  included_evidence_ids_json TEXT NOT NULL,
  snapshot_content_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(proof_pack_id, finding_id, selected_occurrence_id)
);

CREATE TABLE IF NOT EXISTS saved_scan_configurations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  target_template TEXT,
  profile TEXT NOT NULL,
  modules_json TEXT NOT NULL,
  limits_json TEXT NOT NULL,
  scope_settings_json TEXT NOT NULL,
  browser_policy_settings_json TEXT NOT NULL,
  evidence_level TEXT NOT NULL,
  non_secret_controlled_workflow_refs_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS import_records (
  id TEXT PRIMARY KEY,
  source_path_fingerprint TEXT NOT NULL,
  report_fingerprint TEXT NOT NULL,
  imported_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  import_status TEXT NOT NULL,
  import_warnings_json TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  UNIQUE(source_path_fingerprint, report_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_review ON findings(human_review_status);
CREATE INDEX IF NOT EXISTS idx_occurrences_scan ON finding_occurrences(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_scan_seq ON scan_events(scan_id, seq);
`
  }
  ,
  {
    version: 2,
    sql: `
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  tags_json TEXT NOT NULL,
  default_profile TEXT,
  default_scope_json TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT
);

CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  display_name TEXT NOT NULL,
  base_origin TEXT NOT NULL,
  description TEXT,
  tags_json TEXT NOT NULL,
  classification TEXT NOT NULL CHECK (classification IN ('PUBLIC','PRIVATE','LOCAL','UNKNOWN')),
  authorization_type TEXT NOT NULL CHECK (authorization_type IN ('OWNED','CLIENT_AUTHORIZED','BUG_BOUNTY','CONTROLLED_LAB','OTHER_AUTHORIZED')),
  authorization_summary TEXT NOT NULL,
  approved_scope_json TEXT NOT NULL,
  default_profile TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT,
  UNIQUE(project_id, base_origin, display_name)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_label TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  safe_summary TEXT NOT NULL,
  safe_metadata_json TEXT NOT NULL,
  request_correlation_id TEXT,
  created_at TEXT NOT NULL
);

ALTER TABLE scans ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN target_id TEXT REFERENCES targets(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN authorization_declaration TEXT;

CREATE INDEX IF NOT EXISTS idx_projects_archived ON projects(archived_at);
CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
CREATE INDEX IF NOT EXISTS idx_targets_origin ON targets(base_origin);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource_type, resource_id);
`
  }
  ,
  {
    version: 3,
    sql: `
CREATE TABLE IF NOT EXISTS dashboard_users (
  id TEXT PRIMARY KEY,
  login TEXT NOT NULL,
  normalized_login TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('OWNER','ANALYST','VIEWER')),
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_login_at TEXT,
  failed_login_count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  password_changed_at TEXT NOT NULL,
  created_by_user_id TEXT REFERENCES dashboard_users(id)
);

CREATE TABLE IF NOT EXISTS dashboard_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  safe_user_agent TEXT,
  safe_source TEXT,
  session_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id TEXT PRIMARY KEY,
  normalized_login_fingerprint TEXT NOT NULL,
  safe_source_fingerprint TEXT NOT NULL,
  success INTEGER NOT NULL,
  failure_category TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_workers (
  id TEXT PRIMARY KEY,
  process_id INTEGER,
  state TEXT NOT NULL CHECK (state IN ('STARTING','IDLE','RUNNING','UNHEALTHY','STOPPING','STOPPED','EXITED')),
  started_at TEXT NOT NULL,
  last_heartbeat_at TEXT,
  current_job_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  version TEXT NOT NULL,
  shutdown_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_job_leases (
  job_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  worker_id TEXT NOT NULL REFERENCES scan_workers(id) ON DELETE CASCADE,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_renewed_at TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  released_at TEXT,
  release_category TEXT
);

CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_user ON dashboard_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_token ON dashboard_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_login_attempts_login_time ON login_attempts(normalized_login_fingerprint, created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_source_time ON login_attempts(safe_source_fingerprint, created_at);
CREATE INDEX IF NOT EXISTS idx_workers_state ON scan_workers(state);
CREATE INDEX IF NOT EXISTS idx_leases_worker ON scan_job_leases(worker_id);
`
  }
  ,
  {
    version: 4,
    sql: `
CREATE TABLE IF NOT EXISTS credential_profiles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  safe_alias TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
  credential_type_summary TEXT NOT NULL,
  safe_identity_summary_json TEXT NOT NULL,
  expires_at TEXT,
  last_used_at TEXT,
  created_by_user_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  algorithm TEXT NOT NULL,
  key_version TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  auth_tag TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_profiles_enabled ON credential_profiles(enabled, deleted_at);
CREATE INDEX IF NOT EXISTS idx_credential_profiles_project ON credential_profiles(project_id);
CREATE INDEX IF NOT EXISTS idx_credential_profiles_target ON credential_profiles(target_id);
`
  },
  {
    version: 5,
    sql: `
ALTER TABLE findings ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN target_id TEXT REFERENCES targets(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN http_method TEXT NOT NULL DEFAULT 'GET';
ALTER TABLE findings ADD COLUMN canonical_description TEXT;
ALTER TABLE findings ADD COLUMN first_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN latest_occurrence_id TEXT REFERENCES finding_occurrences(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN effective_severity TEXT;
ALTER TABLE findings ADD COLUMN severity_override_reason TEXT;
ALTER TABLE findings ADD COLUMN severity_override_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN severity_override_at TEXT;
ALTER TABLE findings ADD COLUMN remediation_state_v2 TEXT NOT NULL DEFAULT 'OPEN';
ALTER TABLE findings ADD COLUMN assignee_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN assigned_by_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN assigned_at TEXT;
ALTER TABLE findings ADD COLUMN target_fix_date TEXT;
ALTER TABLE findings ADD COLUMN reviewer_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN review_started_at TEXT;
ALTER TABLE findings ADD COLUMN retest_state TEXT NOT NULL DEFAULT 'NOT_RETESTED';
ALTER TABLE findings ADD COLUMN retest_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN retest_occurrence_id TEXT REFERENCES finding_occurrences(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN retest_at TEXT;
ALTER TABLE findings ADD COLUMN verified_by_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN verification_reason TEXT;
ALTER TABLE findings ADD COLUMN verification_owner_override INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN new_occurrence_kind TEXT;
ALTER TABLE findings ADD COLUMN proof_readiness TEXT NOT NULL DEFAULT 'NOT_READY';
ALTER TABLE findings ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE findings ADD COLUMN created_at TEXT;
ALTER TABLE findings ADD COLUMN updated_at TEXT;

ALTER TABLE finding_occurrences ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE finding_occurrences ADD COLUMN target_id TEXT REFERENCES targets(id) ON DELETE SET NULL;
ALTER TABLE finding_occurrences ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'NATIVE';
ALTER TABLE finding_occurrences ADD COLUMN workflow_case_alias TEXT;
ALTER TABLE finding_occurrences ADD COLUMN coverage_reference_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE finding_occurrences ADD COLUMN safe_reproduction_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE finding_reviews ADD COLUMN user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL;
ALTER TABLE finding_reviews ADD COLUMN correlation_id TEXT;
ALTER TABLE finding_reviews ADD COLUMN safe_metadata_json TEXT NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS finding_remediation_history (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  previous_state TEXT,
  new_state TEXT NOT NULL,
  assignee_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  target_fix_date TEXT,
  safe_note TEXT,
  related_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  owner_override INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL CHECK (source IN ('HUMAN','SYSTEM_REOPEN','IMPORT')),
  correlation_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_retests (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  occurrence_id TEXT REFERENCES finding_occurrences(id) ON DELETE SET NULL,
  state TEXT NOT NULL,
  compatible INTEGER NOT NULL,
  compatibility_reasons_json TEXT NOT NULL,
  linked_by_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  verified_by_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  verification_reason TEXT,
  owner_override INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_notes (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  safe_text TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_finding_views (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT REFERENCES dashboard_users(id) ON DELETE CASCADE,
  safe_name TEXT NOT NULL,
  query_json TEXT NOT NULL,
  columns_json TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  shared_installation_wide INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

UPDATE findings
SET project_id = (SELECT project_id FROM scans WHERE scans.id = findings.last_occurrence_scan_id),
    target_id = (SELECT target_id FROM scans WHERE scans.id = findings.last_occurrence_scan_id),
    first_scan_id = COALESCE((SELECT scan_id FROM finding_occurrences WHERE finding_id = findings.id ORDER BY created_at ASC LIMIT 1), last_occurrence_scan_id),
    latest_occurrence_id = (SELECT id FROM finding_occurrences WHERE finding_id = findings.id ORDER BY created_at DESC LIMIT 1),
    effective_severity = current_scanner_severity,
    remediation_state_v2 = CASE WHEN remediation_status = 'FIX_IN_PROGRESS' THEN 'FIX_IN_PROGRESS' WHEN remediation_status = 'FIXED_PENDING_RETEST' THEN 'FIXED_PENDING_RETEST' WHEN remediation_status = 'FIXED_VERIFIED' THEN 'FIXED_VERIFIED' WHEN remediation_status = 'WONT_FIX' THEN 'WONT_FIX' ELSE 'OPEN' END,
    created_at = first_seen_at,
    updated_at = last_seen_at;

UPDATE finding_occurrences
SET project_id = (SELECT project_id FROM scans WHERE scans.id = finding_occurrences.scan_id),
    target_id = (SELECT target_id FROM scans WHERE scans.id = finding_occurrences.scan_id),
    source_kind = CASE WHEN (SELECT source FROM scans WHERE scans.id = finding_occurrences.scan_id) IN ('CLI_IMPORTED','REPORT_IMPORTED') THEN 'IMPORTED' ELSE 'NATIVE' END;

CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_remediation_v2 ON findings(remediation_state_v2);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(effective_severity);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_assignee ON findings(assignee_user_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_retest ON findings(retest_state);
CREATE INDEX IF NOT EXISTS idx_occurrences_finding_created ON finding_occurrences(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_history_finding ON finding_remediation_history(finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_retests_finding ON finding_retests(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notes_finding ON finding_notes(finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_saved_finding_views_owner ON saved_finding_views(owner_user_id, updated_at DESC);
`
  },
  {
    version: 6,
    sql: `
ALTER TABLE saved_finding_views ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS finding_retest_launches (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  source_occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
  source_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  new_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  retest_intent TEXT NOT NULL,
  created_by_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  launched_at TEXT,
  UNIQUE(new_scan_id)
);

CREATE INDEX IF NOT EXISTS idx_retest_launches_finding ON finding_retest_launches(finding_id, created_at DESC);
`
  },
  {
    version: 7,
    sql: `
CREATE TABLE IF NOT EXISTS scan_retest_templates (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL,
  key_version TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  workflow_count INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_retest_templates_created ON scan_retest_templates(created_at DESC);
`
  },
  {
    version: 8,
    sql: `
CREATE TABLE IF NOT EXISTS scan_workflow_case_executions (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  workflow_id TEXT NOT NULL,
  module_id TEXT NOT NULL,
  safe_case_alias TEXT NOT NULL,
  safe_case_fingerprint TEXT NOT NULL,
  execution_state TEXT NOT NULL CHECK (execution_state IN ('COMPLETED','BLOCKED','FAILED','BUDGET_EXHAUSTED','INCOMPARABLE')),
  request_transmitted INTEGER NOT NULL DEFAULT 0,
  matched_expectation INTEGER,
  evidence_strength TEXT NOT NULL,
  safe_semantics_json TEXT NOT NULL,
  safe_result_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(scan_id, workflow_id, safe_case_fingerprint)
);

CREATE TABLE IF NOT EXISTS scan_comparisons (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
  older_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
  newer_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
  state TEXT NOT NULL CHECK (state IN ('PENDING','ANALYZING','COMPLETED','PARTIAL','FAILED','STALE')),
  compatibility_state TEXT NOT NULL,
  source_quality_older TEXT NOT NULL,
  source_quality_newer TEXT NOT NULL,
  created_by_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  engine_version TEXT NOT NULL,
  coverage_algorithm_version TEXT NOT NULL,
  finding_fingerprint_version TEXT,
  older_plan_fingerprint TEXT,
  newer_plan_fingerprint TEXT,
  summary_json TEXT NOT NULL,
  coverage_summary_json TEXT NOT NULL,
  warning_json TEXT NOT NULL,
  failure_category TEXT,
  supersedes_comparison_id TEXT REFERENCES scan_comparisons(id) ON DELETE SET NULL,
  deleted_at TEXT,
  UNIQUE(older_scan_id, newer_scan_id, engine_version)
);

CREATE TABLE IF NOT EXISTS scan_comparison_module_coverage (
  comparison_id TEXT NOT NULL REFERENCES scan_comparisons(id) ON DELETE CASCADE,
  module_id TEXT NOT NULL,
  older_state TEXT NOT NULL,
  newer_state TEXT NOT NULL,
  comparable INTEGER NOT NULL,
  reason_code TEXT NOT NULL,
  safe_reason TEXT NOT NULL,
  PRIMARY KEY(comparison_id, module_id)
);

CREATE TABLE IF NOT EXISTS scan_comparison_workflow_coverage (
  comparison_id TEXT NOT NULL REFERENCES scan_comparisons(id) ON DELETE CASCADE,
  workflow_id TEXT NOT NULL,
  older_configured INTEGER NOT NULL,
  newer_configured INTEGER NOT NULL,
  older_case_count INTEGER NOT NULL,
  newer_case_count INTEGER NOT NULL,
  matched_case_count INTEGER NOT NULL,
  missing_case_count INTEGER NOT NULL,
  changed_case_count INTEGER NOT NULL,
  executed_matched_case_count INTEGER NOT NULL,
  comparable INTEGER NOT NULL,
  safe_reason TEXT NOT NULL,
  PRIMARY KEY(comparison_id, workflow_id)
);

CREATE TABLE IF NOT EXISTS scan_comparison_case_coverage (
  comparison_id TEXT NOT NULL REFERENCES scan_comparisons(id) ON DELETE CASCADE,
  workflow_id TEXT NOT NULL,
  safe_case_fingerprint TEXT NOT NULL,
  safe_case_alias TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('CASE_MATCHED_EXECUTED','CASE_MATCHED_NOT_EXECUTED','CASE_MISSING','CASE_CHANGED','CASE_BLOCKED','CASE_INCOMPARABLE')),
  compatibility TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  safe_reason TEXT NOT NULL,
  older_execution_id TEXT REFERENCES scan_workflow_case_executions(id) ON DELETE SET NULL,
  newer_execution_id TEXT REFERENCES scan_workflow_case_executions(id) ON DELETE SET NULL,
  PRIMARY KEY(comparison_id, workflow_id, safe_case_fingerprint)
);

CREATE TABLE IF NOT EXISTS scan_comparison_findings (
  id TEXT PRIMARY KEY,
  comparison_id TEXT NOT NULL REFERENCES scan_comparisons(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  older_occurrence_id TEXT REFERENCES finding_occurrences(id) ON DELETE SET NULL,
  newer_occurrence_id TEXT REFERENCES finding_occurrences(id) ON DELETE SET NULL,
  classification TEXT NOT NULL CHECK (classification IN ('NEW','PERSISTING','CHANGED','RESOLVED','NOT_RETESTED','INCOMPARABLE')),
  coverage_state TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  safe_explanation TEXT NOT NULL,
  material_changes_json TEXT NOT NULL,
  regression_flags_json TEXT NOT NULL,
  safe_evidence_delta_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(comparison_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_workflow_case_scan ON scan_workflow_case_executions(scan_id, workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_case_fingerprint ON scan_workflow_case_executions(workflow_id, safe_case_fingerprint);
CREATE INDEX IF NOT EXISTS idx_comparisons_target_created ON scan_comparisons(target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comparisons_project_created ON scan_comparisons(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comparison_findings_class ON scan_comparison_findings(comparison_id, classification);
CREATE INDEX IF NOT EXISTS idx_comparison_findings_finding ON scan_comparison_findings(finding_id, created_at DESC);
`
  },
  {
    version: 9,
    sql: `
CREATE INDEX IF NOT EXISTS idx_comparison_findings_page ON scan_comparison_findings(comparison_id, classification, reason_code, finding_id);
CREATE INDEX IF NOT EXISTS idx_comparison_findings_coverage ON scan_comparison_findings(comparison_id, coverage_state, finding_id);
CREATE INDEX IF NOT EXISTS idx_findings_comparison_module ON findings(module, effective_severity, id);
`
  },
  {
    version: 10,
    sql: `
ALTER TABLE projects ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE targets ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE targets ADD COLUMN default_configuration_id TEXT;
ALTER TABLE targets ADD COLUMN default_credential_profile_id TEXT;
ALTER TABLE targets ADD COLUMN default_evidence_level TEXT;
ALTER TABLE targets ADD COLUMN default_auth_template_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE saved_scan_configurations ADD COLUMN archived_at TEXT;
ALTER TABLE saved_scan_configurations ADD COLUMN row_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE saved_scan_configurations ADD COLUMN current_version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS saved_scan_configuration_versions (
  id TEXT PRIMARY KEY,
  configuration_id TEXT NOT NULL REFERENCES saved_scan_configurations(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  change_summary TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(configuration_id, version)
);

INSERT OR IGNORE INTO saved_scan_configuration_versions
  (id, configuration_id, version, snapshot_json, change_summary, created_at)
SELECT lower(hex(randomblob(16))), id, 1,
  json_object('name', name, 'description', description, 'targetTemplate', target_template,
    'profile', profile, 'modules', json(modules_json), 'limits', json(limits_json),
    'scopeSettings', json(scope_settings_json), 'browserPolicySettings', json(browser_policy_settings_json),
    'evidenceLevel', evidence_level, 'workflowRefs', json(non_secret_controlled_workflow_refs_json)),
  'Initial saved configuration', created_at
FROM saved_scan_configurations;

CREATE TABLE IF NOT EXISTS dashboard_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saved_configurations_archived ON saved_scan_configurations(archived_at, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_saved_configuration_versions ON saved_scan_configuration_versions(configuration_id, version DESC);
`
  },
  {
    version: 11,
    sql: `
CREATE TABLE IF NOT EXISTS dashboard_csrf_tokens (
  session_id TEXT NOT NULL REFERENCES dashboard_sessions(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(session_id, token_hash)
);
CREATE INDEX IF NOT EXISTS idx_dashboard_csrf_tokens_created ON dashboard_csrf_tokens(session_id, created_at DESC);
INSERT OR IGNORE INTO dashboard_csrf_tokens (session_id, token_hash, created_at)
SELECT id, csrf_token_hash, created_at FROM dashboard_sessions;
`
  },
  {
    version: 12,
    sql: `
CREATE TABLE IF NOT EXISTS controlled_mutation_approvals (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  target_id TEXT NOT NULL REFERENCES targets(id),
  target_origin TEXT NOT NULL,
  plan_identity TEXT NOT NULL,
  authorization_summary TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PREVIEWED','APPROVED','EXECUTING','COMPLETED','CLEANUP_REQUIRED','CLEANUP_FAILED','REJECTED','EXPIRED')),
  approved_by TEXT,
  approved_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(case_id, plan_identity)
);
CREATE INDEX IF NOT EXISTS idx_mutation_approvals_target_status ON controlled_mutation_approvals(target_id, status, updated_at DESC);
`
  },
  {
    version: 13,
    sql: `
ALTER TABLE controlled_mutation_approvals ADD COLUMN target_identity_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE controlled_mutation_approvals ADD COLUMN scope_digest TEXT NOT NULL DEFAULT '';
`
  },
  {
    version: 14,
    sql: `
ALTER TABLE controlled_mutation_approvals ADD COLUMN recovery_job_id TEXT;
ALTER TABLE controlled_mutation_approvals ADD COLUMN recovery_started_at TEXT;
ALTER TABLE controlled_mutation_approvals ADD COLUMN recovery_completed_at TEXT;
ALTER TABLE controlled_mutation_approvals ADD COLUMN recovery_error_summary TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mutation_approvals_recovery_job ON controlled_mutation_approvals(recovery_job_id) WHERE recovery_job_id IS NOT NULL;
`
  },
  {
    version: 15,
    sql: `
CREATE TABLE IF NOT EXISTS controlled_mutation_recovery_leases (
  job_id TEXT PRIMARY KEY,
  worker_id TEXT NOT NULL REFERENCES scan_workers(id) ON DELETE CASCADE,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_renewed_at TEXT NOT NULL,
  released_at TEXT,
  release_category TEXT
);
CREATE INDEX IF NOT EXISTS idx_mutation_recovery_leases_worker ON controlled_mutation_recovery_leases(worker_id);
`
  },
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
  },
  {
    version: 31,
    sql: `
ALTER TABLE remote_workers ADD COLUMN resources_json TEXT;
CREATE INDEX idx_remote_worker_nonces_expiry ON remote_worker_nonces(expires_at);
CREATE INDEX idx_remote_jobs_lease_expiry ON remote_jobs(status,lease_expires_at);
CREATE INDEX idx_sso_login_states_expiry ON sso_login_states(expires_at,consumed_at);
`
  }
];
