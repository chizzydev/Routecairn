export const dashboardSchemaVersion = 14;

export const dashboardMigrations: readonly { version: number; sql: string }[] = [
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
  }
];
