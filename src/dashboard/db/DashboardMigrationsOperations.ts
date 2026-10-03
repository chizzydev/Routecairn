export const DashboardMigrationsOperations: readonly {
  version: number;
  sql: string;
  requiresForeignKeysDisabled?: boolean;
}[] = [
{
    version: 31,
    sql: `
ALTER TABLE remote_workers ADD COLUMN resources_json TEXT;
CREATE INDEX idx_remote_worker_nonces_expiry ON remote_worker_nonces(expires_at);
CREATE INDEX idx_remote_jobs_lease_expiry ON remote_jobs(status,lease_expires_at);
CREATE INDEX idx_sso_login_states_expiry ON sso_login_states(expires_at,consumed_at);
`
  },
{
    version: 32,
    sql: `
ALTER TABLE cloud_sync_peers ADD COLUMN last_attempt_at TEXT;
ALTER TABLE cloud_sync_peers ADD COLUMN last_success_at TEXT;
ALTER TABLE cloud_sync_peers ADD COLUMN safe_error TEXT;

CREATE TABLE cloud_sync_replicas (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  origin_installation_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('UPSERT','DELETE')),
  safe_payload_json TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_created_at TEXT NOT NULL,
  materialized_at TEXT NOT NULL,
  PRIMARY KEY(organization_id,origin_installation_id,entity_type,entity_id)
);
CREATE INDEX idx_cloud_sync_replicas_org_type ON cloud_sync_replicas(organization_id,entity_type,materialized_at);

CREATE TABLE cloud_sync_legacy_state (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  event_id TEXT NOT NULL,
  synchronized_at TEXT NOT NULL,
  PRIMARY KEY(organization_id,entity_type,entity_id)
);
`
  },
{
    version: 33,
    sql: `
ALTER TABLE cloud_sync_peers ADD COLUMN remote_organization_id TEXT;
`
  },
{
    version: 34,
    sql: `
CREATE TABLE distributed_mutation_leases (
  id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  case_id TEXT NOT NULL,
  holder_id TEXT NOT NULL,
  lease_token_hash TEXT,
  recovery INTEGER NOT NULL CHECK(recovery IN (0,1)),
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','RELEASED','ORPHANED')),
  acquired_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  released_at TEXT
);
CREATE UNIQUE INDEX distributed_mutation_one_active ON distributed_mutation_leases(namespace) WHERE status='ACTIVE';
CREATE INDEX distributed_mutation_lease_history ON distributed_mutation_leases(namespace,acquired_at DESC);

CREATE TABLE distributed_mutation_obligations (
  namespace TEXT NOT NULL,
  case_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('UNRESOLVED','UNKNOWN','LEASE_ORPHANED')),
  stage TEXT,
  first_seen_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(namespace,case_id)
);

CREATE TABLE distributed_mutation_nonces (
  client_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY(client_id,nonce)
);
CREATE INDEX distributed_mutation_nonce_expiry ON distributed_mutation_nonces(expires_at);
`
  },
{
    version: 35,
    sql: `
ALTER TABLE projects ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE targets ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE scans ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE findings ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE credential_profiles ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;

CREATE INDEX idx_projects_organization ON projects(organization_id,archived_at,updated_at);
CREATE INDEX idx_targets_organization ON targets(organization_id,archived_at,updated_at);
CREATE INDEX idx_scans_organization ON scans(organization_id,deleted_at,created_at);
CREATE INDEX idx_findings_organization ON findings(organization_id,archived_at,last_seen_at);
CREATE INDEX idx_credentials_organization ON credential_profiles(organization_id,deleted_at,updated_at);

CREATE TRIGGER projects_assign_default_organization AFTER INSERT ON projects
WHEN NEW.organization_id IS NULL BEGIN
  UPDATE projects SET organization_id=(SELECT value FROM dashboard_meta WHERE key='default_organization_id') WHERE id=NEW.id;
END;
CREATE TRIGGER targets_assign_default_organization AFTER INSERT ON targets
WHEN NEW.organization_id IS NULL BEGIN
  UPDATE targets SET organization_id=COALESCE((SELECT organization_id FROM projects WHERE id=NEW.project_id),(SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE id=NEW.id;
END;
CREATE TRIGGER scans_assign_default_organization AFTER INSERT ON scans
WHEN NEW.organization_id IS NULL BEGIN
  UPDATE scans SET organization_id=COALESCE((SELECT organization_id FROM targets WHERE id=NEW.target_id),(SELECT organization_id FROM projects WHERE id=NEW.project_id),(SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE id=NEW.id;
END;
CREATE TRIGGER findings_assign_default_organization AFTER INSERT ON findings
WHEN NEW.organization_id IS NULL BEGIN
  UPDATE findings SET organization_id=COALESCE((SELECT organization_id FROM scans WHERE id=NEW.last_occurrence_scan_id),(SELECT organization_id FROM targets WHERE id=NEW.target_id),(SELECT organization_id FROM projects WHERE id=NEW.project_id),(SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE id=NEW.id;
END;
CREATE TRIGGER credentials_assign_default_organization AFTER INSERT ON credential_profiles
WHEN NEW.organization_id IS NULL BEGIN
  UPDATE credential_profiles SET organization_id=COALESCE((SELECT organization_id FROM targets WHERE id=NEW.target_id),(SELECT organization_id FROM projects WHERE id=NEW.project_id),(SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE id=NEW.id;
END;

CREATE TRIGGER targets_enforce_organization BEFORE INSERT ON targets
WHEN NEW.organization_id IS NOT NULL AND NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'TARGET_PROJECT_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER targets_enforce_organization_update BEFORE UPDATE OF organization_id,project_id ON targets
WHEN NEW.organization_id IS NOT NULL AND NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'TARGET_PROJECT_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER scans_enforce_organization BEFORE INSERT ON scans
WHEN NEW.organization_id IS NOT NULL AND ((NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)) OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE id=NEW.target_id AND organization_id=NEW.organization_id)))
BEGIN SELECT RAISE(ABORT,'SCAN_RESOURCE_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER scans_enforce_organization_update BEFORE UPDATE OF organization_id,project_id,target_id ON scans
WHEN NEW.organization_id IS NOT NULL AND ((NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)) OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE id=NEW.target_id AND organization_id=NEW.organization_id)))
BEGIN SELECT RAISE(ABORT,'SCAN_RESOURCE_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER findings_enforce_organization BEFORE INSERT ON findings
WHEN NEW.organization_id IS NOT NULL AND ((NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)) OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE id=NEW.target_id AND organization_id=NEW.organization_id)) OR NOT EXISTS(SELECT 1 FROM scans WHERE id=NEW.last_occurrence_scan_id AND organization_id=NEW.organization_id))
BEGIN SELECT RAISE(ABORT,'FINDING_RESOURCE_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER findings_enforce_organization_update BEFORE UPDATE OF organization_id,project_id,target_id,last_occurrence_scan_id ON findings
WHEN NEW.organization_id IS NOT NULL AND ((NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)) OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE id=NEW.target_id AND organization_id=NEW.organization_id)) OR NOT EXISTS(SELECT 1 FROM scans WHERE id=NEW.last_occurrence_scan_id AND organization_id=NEW.organization_id))
BEGIN SELECT RAISE(ABORT,'FINDING_RESOURCE_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER credentials_enforce_organization BEFORE INSERT ON credential_profiles
WHEN NEW.organization_id IS NOT NULL AND ((NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)) OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE id=NEW.target_id AND organization_id=NEW.organization_id)))
BEGIN SELECT RAISE(ABORT,'CREDENTIAL_RESOURCE_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER credentials_enforce_organization_update BEFORE UPDATE OF organization_id,project_id,target_id ON credential_profiles
WHEN NEW.organization_id IS NOT NULL AND ((NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects WHERE id=NEW.project_id AND organization_id=NEW.organization_id)) OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets WHERE id=NEW.target_id AND organization_id=NEW.organization_id)))
BEGIN SELECT RAISE(ABORT,'CREDENTIAL_RESOURCE_ORGANIZATION_MISMATCH'); END;

CREATE TRIGGER projects_prevent_partial_tenant_move BEFORE UPDATE OF organization_id ON projects
WHEN EXISTS(SELECT 1 FROM targets WHERE project_id=OLD.id AND organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM scans WHERE project_id=OLD.id AND organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM findings WHERE project_id=OLD.id AND organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM credential_profiles WHERE project_id=OLD.id AND organization_id<>NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'PROJECT_TENANT_MOVE_REQUIRES_ATOMIC_GRAPH_TRANSFER'); END;
CREATE TRIGGER targets_prevent_partial_tenant_move BEFORE UPDATE OF organization_id ON targets
WHEN EXISTS(SELECT 1 FROM scans WHERE target_id=OLD.id AND organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM findings WHERE target_id=OLD.id AND organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM credential_profiles WHERE target_id=OLD.id AND organization_id<>NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'TARGET_TENANT_MOVE_REQUIRES_ATOMIC_GRAPH_TRANSFER'); END;
CREATE TRIGGER scans_prevent_partial_tenant_move BEFORE UPDATE OF organization_id ON scans
WHEN EXISTS(SELECT 1 FROM findings WHERE last_occurrence_scan_id=OLD.id AND organization_id<>NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'SCAN_TENANT_MOVE_REQUIRES_ATOMIC_GRAPH_TRANSFER'); END;

ALTER TABLE cloud_sync_peers ADD COLUMN sync_mode TEXT NOT NULL DEFAULT 'FULL_STATE' CHECK(sync_mode IN ('FULL_STATE','SAFE_EVENTS'));
ALTER TABLE cloud_sync_peers ADD COLUMN last_state_digest TEXT;

CREATE TABLE cloud_sync_entity_versions (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  origin_installation_id TEXT NOT NULL,
  source_updated_at TEXT NOT NULL,
  source_row_version INTEGER NOT NULL,
  payload_digest TEXT NOT NULL,
  applied_at TEXT NOT NULL,
  PRIMARY KEY(organization_id,entity_type,entity_id)
);
CREATE INDEX idx_cloud_sync_entity_versions_origin ON cloud_sync_entity_versions(organization_id,origin_installation_id);
`
  },
{
    version: 36,
    sql: `
CREATE TRIGGER finding_occurrences_tenant_insert BEFORE INSERT ON finding_occurrences
WHEN NOT EXISTS(SELECT 1 FROM findings f JOIN scans s ON s.id=NEW.scan_id WHERE f.id=NEW.finding_id AND f.organization_id=s.organization_id)
  OR (NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects p JOIN findings f ON f.organization_id=p.organization_id WHERE p.id=NEW.project_id AND f.id=NEW.finding_id))
  OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets t JOIN findings f ON f.organization_id=t.organization_id WHERE t.id=NEW.target_id AND f.id=NEW.finding_id))
BEGIN SELECT RAISE(ABORT,'FINDING_OCCURRENCE_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER finding_occurrences_tenant_update BEFORE UPDATE OF finding_id,scan_id,project_id,target_id ON finding_occurrences
WHEN NOT EXISTS(SELECT 1 FROM findings f JOIN scans s ON s.id=NEW.scan_id WHERE f.id=NEW.finding_id AND f.organization_id=s.organization_id)
  OR (NEW.project_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM projects p JOIN findings f ON f.organization_id=p.organization_id WHERE p.id=NEW.project_id AND f.id=NEW.finding_id))
  OR (NEW.target_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM targets t JOIN findings f ON f.organization_id=t.organization_id WHERE t.id=NEW.target_id AND f.id=NEW.finding_id))
BEGIN SELECT RAISE(ABORT,'FINDING_OCCURRENCE_ORGANIZATION_MISMATCH'); END;

CREATE TRIGGER finding_retests_tenant_insert BEFORE INSERT ON finding_retests
WHEN NOT EXISTS(SELECT 1 FROM findings f JOIN scans s ON s.id=NEW.scan_id WHERE f.id=NEW.finding_id AND f.organization_id=s.organization_id)
BEGIN SELECT RAISE(ABORT,'FINDING_RETEST_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER finding_retests_tenant_update BEFORE UPDATE OF finding_id,scan_id ON finding_retests
WHEN NOT EXISTS(SELECT 1 FROM findings f JOIN scans s ON s.id=NEW.scan_id WHERE f.id=NEW.finding_id AND f.organization_id=s.organization_id)
BEGIN SELECT RAISE(ABORT,'FINDING_RETEST_ORGANIZATION_MISMATCH'); END;

CREATE TRIGGER scans_prevent_dependent_tenant_move BEFORE UPDATE OF organization_id ON scans
WHEN EXISTS(SELECT 1 FROM finding_occurrences o JOIN findings f ON f.id=o.finding_id WHERE o.scan_id=OLD.id AND f.organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM finding_retests r JOIN findings f ON f.id=r.finding_id WHERE r.scan_id=OLD.id AND f.organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM scan_comparisons c JOIN scans other ON other.id=CASE WHEN c.older_scan_id=OLD.id THEN c.newer_scan_id ELSE c.older_scan_id END WHERE (c.older_scan_id=OLD.id OR c.newer_scan_id=OLD.id) AND other.organization_id<>NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'SCAN_TENANT_MOVE_REQUIRES_ATOMIC_GRAPH_TRANSFER'); END;
CREATE TRIGGER findings_prevent_dependent_tenant_move BEFORE UPDATE OF organization_id ON findings
WHEN EXISTS(SELECT 1 FROM finding_occurrences o JOIN scans s ON s.id=o.scan_id WHERE o.finding_id=OLD.id AND s.organization_id<>NEW.organization_id)
  OR EXISTS(SELECT 1 FROM finding_retests r JOIN scans s ON s.id=r.scan_id WHERE r.finding_id=OLD.id AND s.organization_id<>NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'FINDING_TENANT_MOVE_REQUIRES_ATOMIC_GRAPH_TRANSFER'); END;

CREATE TRIGGER scan_comparisons_tenant_insert BEFORE INSERT ON scan_comparisons
WHEN NOT EXISTS(SELECT 1 FROM scans older JOIN scans newer ON newer.id=NEW.newer_scan_id WHERE older.id=NEW.older_scan_id AND older.organization_id=newer.organization_id)
BEGIN SELECT RAISE(ABORT,'SCAN_COMPARISON_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER scan_comparisons_tenant_update BEFORE UPDATE OF older_scan_id,newer_scan_id ON scan_comparisons
WHEN NOT EXISTS(SELECT 1 FROM scans older JOIN scans newer ON newer.id=NEW.newer_scan_id WHERE older.id=NEW.older_scan_id AND older.organization_id=newer.organization_id)
BEGIN SELECT RAISE(ABORT,'SCAN_COMPARISON_ORGANIZATION_MISMATCH'); END;
`
  },
{
    version: 37,
    sql: `
ALTER TABLE saved_scan_configurations ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;
UPDATE saved_scan_configurations SET organization_id=(SELECT value FROM dashboard_meta WHERE key='default_organization_id') WHERE organization_id IS NULL;
CREATE INDEX idx_saved_configurations_organization ON saved_scan_configurations(organization_id,archived_at,updated_at);
CREATE TRIGGER saved_configurations_assign_organization AFTER INSERT ON saved_scan_configurations
WHEN NEW.organization_id IS NULL BEGIN
  UPDATE saved_scan_configurations SET organization_id=(SELECT value FROM dashboard_meta WHERE key='default_organization_id') WHERE id=NEW.id;
END;
CREATE TRIGGER saved_configurations_prevent_tenant_move BEFORE UPDATE OF organization_id ON saved_scan_configurations
WHEN OLD.organization_id IS NOT NULL AND NEW.organization_id<>OLD.organization_id
BEGIN SELECT RAISE(ABORT,'CONFIGURATION_TENANT_MOVE_REJECTED'); END;
`
  },
{
    version: 38,
    sql: `
ALTER TABLE proof_packs ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;
ALTER TABLE artifacts ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT;
UPDATE proof_packs SET organization_id=COALESCE(
  (SELECT organization_id FROM scans WHERE id=CASE WHEN json_valid(proof_packs.source_scan_ids_json) THEN json_extract(proof_packs.source_scan_ids_json,'$[0]') ELSE NULL END),
  (SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE organization_id IS NULL;
UPDATE artifacts SET organization_id=COALESCE(
  (SELECT organization_id FROM scans WHERE scans.id=artifacts.scan_id),
  (SELECT organization_id FROM proof_packs WHERE proof_packs.id=artifacts.proof_pack_id),
  (SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE organization_id IS NULL;
CREATE INDEX idx_proof_packs_organization ON proof_packs(organization_id,created_at);
CREATE INDEX idx_artifacts_organization ON artifacts(organization_id,created_at);
CREATE TRIGGER proof_packs_assign_organization AFTER INSERT ON proof_packs WHEN NEW.organization_id IS NULL
BEGIN UPDATE proof_packs SET organization_id=COALESCE((SELECT organization_id FROM scans WHERE id=CASE WHEN json_valid(NEW.source_scan_ids_json) THEN json_extract(NEW.source_scan_ids_json,'$[0]') ELSE NULL END),(SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE id=NEW.id; END;
CREATE TRIGGER artifacts_assign_organization AFTER INSERT ON artifacts WHEN NEW.organization_id IS NULL
BEGIN UPDATE artifacts SET organization_id=COALESCE((SELECT organization_id FROM scans WHERE id=NEW.scan_id),(SELECT organization_id FROM proof_packs WHERE id=NEW.proof_pack_id),(SELECT value FROM dashboard_meta WHERE key='default_organization_id')) WHERE id=NEW.id; END;
CREATE TRIGGER artifacts_tenant_insert BEFORE INSERT ON artifacts WHEN NEW.organization_id IS NOT NULL AND
  ((NEW.scan_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM scans WHERE id=NEW.scan_id AND organization_id=NEW.organization_id)) OR
   (NEW.proof_pack_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM proof_packs WHERE id=NEW.proof_pack_id AND organization_id=NEW.organization_id)))
BEGIN SELECT RAISE(ABORT,'ARTIFACT_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER artifacts_tenant_update BEFORE UPDATE OF organization_id,scan_id,proof_pack_id ON artifacts WHEN NEW.organization_id IS NOT NULL AND
  ((NEW.scan_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM scans WHERE id=NEW.scan_id AND organization_id=NEW.organization_id)) OR
   (NEW.proof_pack_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM proof_packs WHERE id=NEW.proof_pack_id AND organization_id=NEW.organization_id)))
BEGIN SELECT RAISE(ABORT,'ARTIFACT_ORGANIZATION_MISMATCH'); END;
CREATE TRIGGER proof_pack_findings_tenant_insert BEFORE INSERT ON proof_pack_findings WHEN NOT EXISTS(
  SELECT 1 FROM proof_packs p JOIN findings f ON f.organization_id=p.organization_id JOIN finding_occurrences o ON o.finding_id=f.id
  WHERE p.id=NEW.proof_pack_id AND f.id=NEW.finding_id AND o.id=NEW.selected_occurrence_id)
BEGIN SELECT RAISE(ABORT,'PROOF_PACK_FINDING_ORGANIZATION_MISMATCH'); END;
`
  },
{
    version: 39,
    sql: `
CREATE TABLE cloud_sync_membership_tombstones (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  deleted_at TEXT NOT NULL,
  PRIMARY KEY(organization_id,user_id)
);
CREATE TABLE cloud_sync_membership_bindings (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  origin_installation_id TEXT NOT NULL,
  source_user_id TEXT NOT NULL,
  local_user_id TEXT REFERENCES dashboard_users(id) ON DELETE SET NULL,
  role TEXT NOT NULL CHECK(role IN ('OWNER','ADMIN','ANALYST','VIEWER')),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  status TEXT NOT NULL CHECK(status IN ('PENDING','BOUND','CONFLICT','REMOVED')),
  issuer TEXT,
  subject TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(organization_id,origin_installation_id,source_user_id)
);
CREATE INDEX idx_cloud_sync_membership_bindings_status ON cloud_sync_membership_bindings(organization_id,status,updated_at);
CREATE TRIGGER organization_membership_sync_tombstone AFTER DELETE ON organization_memberships
BEGIN INSERT INTO cloud_sync_membership_tombstones (organization_id,user_id,deleted_at) VALUES (OLD.organization_id,OLD.user_id,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT(organization_id,user_id) DO UPDATE SET deleted_at=excluded.deleted_at; END;
CREATE TRIGGER organization_membership_sync_restore AFTER INSERT ON organization_memberships
BEGIN DELETE FROM cloud_sync_membership_tombstones WHERE organization_id=NEW.organization_id AND user_id=NEW.user_id; END;
`
  },
{
    version: 40,
    sql: `
ALTER TABLE cloud_sync_peers ADD COLUMN state_cursor TEXT;
`
  },
{
    version: 41,
    sql: `
CREATE TABLE cloud_sync_artifact_pending (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  content_digest TEXT NOT NULL,
  expected_size INTEGER NOT NULL,
  chunk_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(organization_id,artifact_id)
);
CREATE TABLE cloud_sync_artifact_chunks (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  content_digest TEXT NOT NULL,
  chunk_index INTEGER NOT NULL,
  chunk_digest TEXT NOT NULL,
  content BLOB NOT NULL,
  PRIMARY KEY(organization_id,artifact_id,content_digest,chunk_index)
);
`
  },
{
    version: 42,
    sql: `
ALTER TABLE cloud_sync_peers ADD COLUMN state_cursor_digest TEXT;
`
  },
{
    version: 43,
    sql: `
ALTER TABLE remote_jobs ADD COLUMN network_zone TEXT;
CREATE INDEX idx_remote_jobs_zone_claim ON remote_jobs(organization_id,status,network_zone,priority,created_at);
`
  },
{
    version: 44,
    sql: `
CREATE TABLE third_party_module_signatures (
  module_id TEXT PRIMARY KEY REFERENCES third_party_modules(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL
);
`
  }
];
