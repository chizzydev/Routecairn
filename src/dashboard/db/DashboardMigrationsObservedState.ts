export const DashboardMigrationsObservedState = [
  {
    version: 53,
    sql: `
CREATE TABLE application_observation_policy_versions(
 id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),target_id TEXT NOT NULL REFERENCES targets(id),
 lineage_id TEXT NOT NULL,revision INTEGER NOT NULL,matrix_revision_id TEXT NOT NULL REFERENCES authorization_workbench_revisions(id),
 baseline_map_revision_id TEXT NOT NULL REFERENCES application_mapping_revisions(id),baseline_scan_id TEXT NOT NULL REFERENCES scans(id),
 supersedes TEXT UNIQUE REFERENCES application_observation_policy_versions(id),digest TEXT NOT NULL,snapshot_json TEXT NOT NULL,
 created_by TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(lineage_id,revision)
);
CREATE TABLE application_observation_policy_decisions(
 id TEXT PRIMARY KEY,version_id TEXT NOT NULL REFERENCES application_observation_policy_versions(id),action TEXT NOT NULL CHECK(action IN ('APPROVE','REVOKE')),
 receipt_json TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(version_id,action)
);
CREATE TABLE application_observation_assessments(
 id TEXT PRIMARY KEY,policy_version_id TEXT NOT NULL REFERENCES application_observation_policy_versions(id),
 map_revision_id TEXT REFERENCES application_mapping_revisions(id),source_scan_id TEXT REFERENCES scans(id),
 assurance_run_id TEXT NOT NULL UNIQUE REFERENCES continuous_assurance_runs(id),digest TEXT NOT NULL,snapshot_json TEXT NOT NULL,created_at TEXT NOT NULL
);
CREATE INDEX idx_observation_policies_org ON application_observation_policy_versions(organization_id,target_id,created_at DESC);
CREATE INDEX idx_observation_assessments_policy ON application_observation_assessments(policy_version_id,created_at DESC);
CREATE TRIGGER observation_policy_scope BEFORE INSERT ON application_observation_policy_versions WHEN
 NOT EXISTS(SELECT 1 FROM authorization_workbench_revisions m WHERE m.id=NEW.matrix_revision_id AND m.organization_id=NEW.organization_id AND m.target_id=NEW.target_id) OR
 NOT EXISTS(SELECT 1 FROM application_mapping_revisions m WHERE m.id=NEW.baseline_map_revision_id AND m.organization_id=NEW.organization_id AND m.target_id=NEW.target_id) OR
 NOT EXISTS(SELECT 1 FROM scans s WHERE s.id=NEW.baseline_scan_id AND s.organization_id=NEW.organization_id AND s.target_id=NEW.target_id) OR
 (NEW.supersedes IS NOT NULL AND NOT EXISTS(SELECT 1 FROM application_observation_policy_versions p WHERE p.id=NEW.supersedes AND p.organization_id=NEW.organization_id AND p.target_id=NEW.target_id))
 BEGIN SELECT RAISE(ABORT,'OBSERVATION_POLICY_SCOPE_MISMATCH'); END;
CREATE TRIGGER observation_assessment_scope BEFORE INSERT ON application_observation_assessments WHEN
 NOT EXISTS(SELECT 1 FROM application_observation_policy_versions p JOIN continuous_assurance_runs r ON r.id=NEW.assurance_run_id JOIN continuous_assurance_policies c ON c.id=r.policy_id JOIN targets t ON t.id=c.target_id WHERE p.id=NEW.policy_version_id AND c.target_id=p.target_id AND t.organization_id=p.organization_id) OR
 (NEW.map_revision_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM application_mapping_revisions m JOIN application_observation_policy_versions p ON p.id=NEW.policy_version_id WHERE m.id=NEW.map_revision_id AND m.organization_id=p.organization_id AND m.target_id=p.target_id))
 BEGIN SELECT RAISE(ABORT,'OBSERVATION_ASSESSMENT_SCOPE_MISMATCH'); END;
CREATE TRIGGER observation_policy_no_update BEFORE UPDATE ON application_observation_policy_versions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OBSERVATION_POLICY'); END;
CREATE TRIGGER observation_policy_no_delete BEFORE DELETE ON application_observation_policy_versions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OBSERVATION_POLICY'); END;
CREATE TRIGGER observation_decision_no_update BEFORE UPDATE ON application_observation_policy_decisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OBSERVATION_DECISION'); END;
CREATE TRIGGER observation_decision_no_delete BEFORE DELETE ON application_observation_policy_decisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OBSERVATION_DECISION'); END;
CREATE TRIGGER observation_assessment_no_update BEFORE UPDATE ON application_observation_assessments BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OBSERVATION_ASSESSMENT'); END;
CREATE TRIGGER observation_assessment_no_delete BEFORE DELETE ON application_observation_assessments BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OBSERVATION_ASSESSMENT'); END;
`
  }
];
