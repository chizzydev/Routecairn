export const DashboardMigrationsCleanupAttempts = [
  {
    version: 48,
    sql: `
CREATE TABLE cleanup_attempts (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL UNIQUE, organization_id TEXT NOT NULL REFERENCES organizations(id),
 target_id TEXT NOT NULL REFERENCES targets(id), case_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('WORKFLOW','CONTROLLED')),
 authority_key TEXT NOT NULL UNIQUE, request_key TEXT NOT NULL, binding_json TEXT NOT NULL, binding_digest TEXT NOT NULL,
 requested_by TEXT NOT NULL, controller_id TEXT NOT NULL, created_at TEXT NOT NULL,
 UNIQUE(organization_id,request_key)
);
CREATE TABLE cleanup_attempt_events (
 attempt_id TEXT NOT NULL REFERENCES cleanup_attempts(id), sequence INTEGER NOT NULL CHECK(sequence>0),
 kind TEXT NOT NULL CHECK(kind IN ('REQUESTED','AUTHORIZED','WORKER_PENDING','WORKER_ACTIVATED','DISPATCH_ARMED','DISPATCH_ATTEMPTED','RESULT_RECEIVED','RESTORATION_VERIFIED','FAILED','UNKNOWN','NOT_EXECUTED')),
 evidence_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(attempt_id,sequence)
);
CREATE INDEX cleanup_attempt_case ON cleanup_attempts(target_id,case_id,created_at);
CREATE TRIGGER cleanup_attempt_immutable_update BEFORE UPDATE ON cleanup_attempts BEGIN SELECT RAISE(ABORT,'CLEANUP_ATTEMPT_IMMUTABLE'); END;
CREATE TRIGGER cleanup_attempt_immutable_delete BEFORE DELETE ON cleanup_attempts BEGIN SELECT RAISE(ABORT,'CLEANUP_ATTEMPT_IMMUTABLE'); END;
CREATE TRIGGER cleanup_event_immutable_update BEFORE UPDATE ON cleanup_attempt_events BEGIN SELECT RAISE(ABORT,'CLEANUP_EVENT_IMMUTABLE'); END;
CREATE TRIGGER cleanup_event_immutable_delete BEFORE DELETE ON cleanup_attempt_events BEGIN SELECT RAISE(ABORT,'CLEANUP_EVENT_IMMUTABLE'); END;
CREATE TRIGGER cleanup_event_sequence BEFORE INSERT ON cleanup_attempt_events WHEN NEW.sequence<>COALESCE((SELECT MAX(sequence)+1 FROM cleanup_attempt_events WHERE attempt_id=NEW.attempt_id),1) OR NEW.previous_hash<>COALESCE((SELECT event_hash FROM cleanup_attempt_events WHERE attempt_id=NEW.attempt_id ORDER BY sequence DESC LIMIT 1),(SELECT binding_digest FROM cleanup_attempts WHERE id=NEW.attempt_id)) BEGIN SELECT RAISE(ABORT,'CLEANUP_EVENT_SEQUENCE'); END;
`
  }
] as const;
