export const DashboardMigrationsApplicationDiscovery = [
  {
    version: 54,
    sql: `
CREATE TABLE application_discovery_proposals (
 id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),target_id TEXT NOT NULL REFERENCES targets(id),
 source_revision_id TEXT NOT NULL REFERENCES application_mapping_revisions(id),digest TEXT NOT NULL,snapshot_json TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL
);
CREATE INDEX application_discovery_scope ON application_discovery_proposals(organization_id,target_id,created_at);
CREATE TRIGGER discovery_scope BEFORE INSERT ON application_discovery_proposals BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM application_mapping_revisions m WHERE m.id=NEW.source_revision_id AND m.organization_id=NEW.organization_id AND m.target_id=NEW.target_id) THEN RAISE(ABORT,'DISCOVERY_SOURCE_SCOPE') END;
END;
CREATE TRIGGER discovery_no_update BEFORE UPDATE ON application_discovery_proposals BEGIN SELECT RAISE(ABORT,'IMMUTABLE_DISCOVERY_PROPOSAL'); END;
CREATE TRIGGER discovery_no_delete BEFORE DELETE ON application_discovery_proposals BEGIN SELECT RAISE(ABORT,'IMMUTABLE_DISCOVERY_PROPOSAL'); END;
`
  }
];
