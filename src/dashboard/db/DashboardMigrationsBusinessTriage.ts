export const DashboardMigrationsBusinessTriage = [
  {
    version: 55,
    sql: "\nCREATE TABLE application_triage_notes(id TEXT PRIMARY KEY,proposal_id TEXT NOT NULL REFERENCES application_hypothesis_proposals(id),evidence_digest TEXT NOT NULL,disposition TEXT NOT NULL CHECK(disposition IN ('INVESTIGATE','NEEDS_OWNER_CONTEXT','OWNER_EXPECTED_BEHAVIOR')),rationale TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL);\nCREATE INDEX application_triage_proposal ON application_triage_notes(proposal_id,created_at,id);\nCREATE TRIGGER application_triage_immutable_update BEFORE UPDATE ON application_triage_notes BEGIN SELECT RAISE(ABORT,'IMMUTABLE_TRIAGE_NOTE');END;\nCREATE TRIGGER application_triage_immutable_delete BEFORE DELETE ON application_triage_notes BEGIN SELECT RAISE(ABORT,'IMMUTABLE_TRIAGE_NOTE');END;\n"
  }
];
