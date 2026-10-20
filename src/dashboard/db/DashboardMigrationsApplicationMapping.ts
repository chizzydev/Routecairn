export const DashboardMigrationsApplicationMapping = [
  {
    version: 50,
    sql: `
CREATE TABLE application_mapping_revisions (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),target_id TEXT NOT NULL REFERENCES targets(id),
 version INTEGER NOT NULL, input_json TEXT NOT NULL,request_json TEXT NOT NULL,
 context_digest TEXT NOT NULL,digest TEXT NOT NULL,preview_identity TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,review_json TEXT NOT NULL,
 UNIQUE(target_id,version)
);
CREATE TABLE application_mapping_dispatches(revision_id TEXT PRIMARY KEY REFERENCES application_mapping_revisions(id),requested_by TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE application_mapping_acknowledgements(revision_id TEXT PRIMARY KEY REFERENCES application_mapping_dispatches(revision_id),scan_id TEXT NOT NULL UNIQUE REFERENCES scans(id),created_at TEXT NOT NULL);
CREATE TRIGGER application_mapping_revision_no_update BEFORE UPDATE ON application_mapping_revisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAPPING_REVISION'); END;
CREATE TRIGGER application_mapping_revision_no_delete BEFORE DELETE ON application_mapping_revisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAPPING_REVISION'); END;
CREATE TRIGGER application_mapping_dispatch_no_update BEFORE UPDATE ON application_mapping_dispatches BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAPPING_DISPATCH'); END;
CREATE TRIGGER application_mapping_dispatch_no_delete BEFORE DELETE ON application_mapping_dispatches BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAPPING_DISPATCH'); END;
CREATE TRIGGER application_mapping_ack_no_update BEFORE UPDATE ON application_mapping_acknowledgements BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAPPING_ACK'); END;
CREATE TRIGGER application_mapping_ack_no_delete BEFORE DELETE ON application_mapping_acknowledgements BEGIN SELECT RAISE(ABORT,'IMMUTABLE_MAPPING_ACK'); END;
`
  }
];
