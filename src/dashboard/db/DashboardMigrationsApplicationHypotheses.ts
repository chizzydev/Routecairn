export const DashboardMigrationsApplicationHypotheses = [
  {
    version: 52,
    sql: `
CREATE TABLE application_hypothesis_proposals(id TEXT PRIMARY KEY,organization_id TEXT NOT NULL REFERENCES organizations(id),target_id TEXT NOT NULL REFERENCES targets(id),map_revision_id TEXT NOT NULL REFERENCES application_mapping_revisions(id),context_digest TEXT NOT NULL,digest TEXT NOT NULL,snapshot_json TEXT NOT NULL,supersedes TEXT UNIQUE REFERENCES application_hypothesis_proposals(id),created_by TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE application_hypothesis_decisions(id TEXT PRIMARY KEY,proposal_id TEXT NOT NULL REFERENCES application_hypothesis_proposals(id),candidate_id TEXT NOT NULL,action TEXT NOT NULL CHECK(action IN ('REVIEW','REJECT')),policy_digest TEXT,receipt_json TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(proposal_id,candidate_id));
CREATE TRIGGER hypothesis_proposal_no_update BEFORE UPDATE ON application_hypothesis_proposals BEGIN SELECT RAISE(ABORT,'IMMUTABLE_HYPOTHESIS_PROPOSAL'); END;
CREATE TRIGGER hypothesis_proposal_no_delete BEFORE DELETE ON application_hypothesis_proposals BEGIN SELECT RAISE(ABORT,'IMMUTABLE_HYPOTHESIS_PROPOSAL'); END;
CREATE TRIGGER hypothesis_decision_no_update BEFORE UPDATE ON application_hypothesis_decisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_HYPOTHESIS_DECISION'); END;
CREATE TRIGGER hypothesis_decision_no_delete BEFORE DELETE ON application_hypothesis_decisions BEGIN SELECT RAISE(ABORT,'IMMUTABLE_HYPOTHESIS_DECISION'); END;
`
  }
];
