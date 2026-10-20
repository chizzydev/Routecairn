export const DashboardMigrationsAuthorizationWorkbench = [
  {
    version: 49,
    sql: `
CREATE TABLE authorization_workbench_revisions (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),target_id TEXT NOT NULL REFERENCES targets(id),
 version INTEGER NOT NULL, source_scan_id TEXT NOT NULL REFERENCES scans(id),input_json TEXT NOT NULL,request_json TEXT NOT NULL,
 context_digest TEXT NOT NULL,digest TEXT NOT NULL,preview_identity TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,review_json TEXT NOT NULL,
 UNIQUE(target_id,version)
);
CREATE TABLE authorization_workbench_dispatches(revision_id TEXT PRIMARY KEY REFERENCES authorization_workbench_revisions(id),requested_by TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE authorization_workbench_acknowledgements(revision_id TEXT PRIMARY KEY REFERENCES authorization_workbench_dispatches(revision_id),scan_id TEXT NOT NULL UNIQUE REFERENCES scans(id),created_at TEXT NOT NULL);
CREATE TRIGGER authorization_workbench_revision_no_update BEFORE UPDATE ON authorization_workbench_revisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_WORKBENCH_REVISION'); END;
CREATE TRIGGER authorization_workbench_revision_no_delete BEFORE DELETE ON authorization_workbench_revisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_WORKBENCH_REVISION'); END;
CREATE TRIGGER authorization_workbench_dispatch_no_update BEFORE UPDATE ON authorization_workbench_dispatches BEGIN SELECT RAISE(ABORT,'IMMUTABLE_WORKBENCH_DISPATCH'); END;
CREATE TRIGGER authorization_workbench_dispatch_no_delete BEFORE DELETE ON authorization_workbench_dispatches BEGIN SELECT RAISE(ABORT,'IMMUTABLE_WORKBENCH_DISPATCH'); END;
CREATE TRIGGER authorization_workbench_ack_no_update BEFORE UPDATE ON authorization_workbench_acknowledgements BEGIN SELECT RAISE(ABORT,'IMMUTABLE_WORKBENCH_ACK'); END;
CREATE TRIGGER authorization_workbench_ack_no_delete BEFORE DELETE ON authorization_workbench_acknowledgements BEGIN SELECT RAISE(ABORT,'IMMUTABLE_WORKBENCH_ACK'); END;
`
  }
];
