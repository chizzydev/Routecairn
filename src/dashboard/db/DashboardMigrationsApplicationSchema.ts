export const DashboardMigrationsApplicationSchema = [
  {
    version: 51,
    sql: `
CREATE TABLE application_schema_revisions(id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),target_id TEXT NOT NULL REFERENCES targets(id),context_digest TEXT NOT NULL,digest TEXT NOT NULL,summary_json TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE application_map_comparisons(id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),baseline_revision_id TEXT NOT NULL REFERENCES application_mapping_revisions(id),current_revision_id TEXT NOT NULL REFERENCES application_mapping_revisions(id),digest TEXT NOT NULL,snapshot_json TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TRIGGER application_schema_no_update BEFORE UPDATE ON application_schema_revisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_SCHEMA_REVISION'); END;
CREATE TRIGGER application_schema_no_delete BEFORE DELETE ON application_schema_revisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_SCHEMA_REVISION'); END;
CREATE TRIGGER application_map_comparison_no_update BEFORE UPDATE ON application_map_comparisons BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAP_COMPARISON'); END;
CREATE TRIGGER application_map_comparison_no_delete BEFORE DELETE ON application_map_comparisons BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAP_COMPARISON'); END;
`
  }
];
