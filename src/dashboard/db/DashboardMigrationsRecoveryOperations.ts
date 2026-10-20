export const DashboardMigrationsRecoveryOperations = [
  {
    version: 47,
    sql: `
CREATE TABLE operator_uncertainty_reviews (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
 kind TEXT NOT NULL CHECK(kind IN ('CUSTODY','CLEANUP','ASSURANCE','DEPLOYMENT','COMPARISON','RECOVERY')),
 subject_id TEXT NOT NULL, snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
 reviewer TEXT NOT NULL, decision TEXT NOT NULL CHECK(decision IN ('ACKNOWLEDGED','ESCALATED')),
 reason TEXT NOT NULL CHECK(reason IN ('OWNER_INVESTIGATION','EVIDENCE_INCOMPLETE','RECOVERY_PLANNING')),
 created_at TEXT NOT NULL,
 UNIQUE(organization_id,kind,subject_id,snapshot_digest,reviewer,decision)
);
CREATE INDEX uncertainty_review_subject ON operator_uncertainty_reviews(organization_id,kind,subject_id,created_at);
CREATE TABLE operator_comparison_attempts (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
 subject_id TEXT NOT NULL REFERENCES scan_comparisons(id), snapshot_digest TEXT NOT NULL,
 request_id TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('COMPLETED','FAILED')),
 result_comparison_id TEXT REFERENCES scan_comparisons(id), created_at TEXT NOT NULL,
 UNIQUE(organization_id,request_id)
);
`
  }
] as const;
