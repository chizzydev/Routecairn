export const DashboardMigrationsOwnedIntake = [
  {
    version: 56,
    sql: `CREATE TABLE application_owned_intakes(id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),target_id TEXT NOT NULL REFERENCES targets(id),context_digest TEXT NOT NULL,digest TEXT NOT NULL,snapshot_json TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TRIGGER owned_intake_no_update BEFORE UPDATE ON application_owned_intakes BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OWNED_INTAKE'); END;
CREATE TRIGGER owned_intake_no_delete BEFORE DELETE ON application_owned_intakes BEGIN SELECT RAISE(ABORT,'IMMUTABLE_OWNED_INTAKE'); END;
CREATE INDEX owned_intake_org_target ON application_owned_intakes(organization_id,target_id,created_at);`
  }
];
