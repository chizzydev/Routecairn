/** Additive Stage A metadata only. These rows never contain native capabilities. */
export const DashboardMigrationsTrustedDiscovery = [
  {
    version: 45,
    sql: `
CREATE UNIQUE INDEX idx_trusted_target_tenant ON targets(organization_id,id);
CREATE TABLE trusted_discovery_reviews (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES dashboard_users(id) ON DELETE RESTRICT,
  session_binding TEXT NOT NULL CHECK(length(session_binding)=64),
  target_id TEXT NOT NULL,
  source_scan_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL CHECK(length(candidate_id)=64),
  source_digest TEXT NOT NULL CHECK(length(source_digest)=64),
  source_generation TEXT NOT NULL CHECK(length(source_generation)=64),
  target_generation TEXT NOT NULL CHECK(length(target_generation)=64),
  route_key TEXT NOT NULL CHECK(length(route_key)=64),
  attempt_identity TEXT NOT NULL CHECK(length(attempt_identity)=64),
  review_digest TEXT NOT NULL CHECK(length(review_digest)=64),
  state TEXT NOT NULL CHECK(state IN ('REVIEWED','PRECONSENTED','INVALIDATED')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=60000),
  preconsented_at INTEGER,
  FOREIGN KEY(organization_id,target_id) REFERENCES targets(organization_id,id) ON DELETE RESTRICT
);
CREATE INDEX idx_trusted_reviews_expiry ON trusted_discovery_reviews(expires_at,state);
CREATE TABLE trusted_discovery_review_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  review_id TEXT NOT NULL REFERENCES trusted_discovery_reviews(id) ON DELETE CASCADE,
  code TEXT NOT NULL CHECK(code IN ('REVIEWED','PRECONSENTED','INVALIDATED')),
  created_at INTEGER NOT NULL
);
CREATE TRIGGER trusted_review_event_tenant BEFORE INSERT ON trusted_discovery_review_events
WHEN NOT EXISTS(SELECT 1 FROM trusted_discovery_reviews WHERE id=NEW.review_id AND organization_id=NEW.organization_id)
BEGIN SELECT RAISE(ABORT,'TRUSTED_DISCOVERY_ORGANIZATION_MISMATCH'); END;
CREATE TABLE trusted_discovery_attempts (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  target_id TEXT NOT NULL,
  route_key TEXT NOT NULL CHECK(length(route_key)=64),
  review_id TEXT NOT NULL UNIQUE REFERENCES trusted_discovery_reviews(id) ON DELETE RESTRICT,
  source_scan_id TEXT NOT NULL,
  source_digest TEXT NOT NULL CHECK(length(source_digest)=64),
  source_generation TEXT NOT NULL CHECK(length(source_generation)=64),
  attempt_identity TEXT NOT NULL CHECK(length(attempt_identity)=64),
  reserved_at INTEGER NOT NULL,
  PRIMARY KEY(organization_id,target_id,route_key),
  FOREIGN KEY(organization_id,target_id) REFERENCES targets(organization_id,id) ON DELETE RESTRICT
);
CREATE TRIGGER trusted_attempt_binding BEFORE INSERT ON trusted_discovery_attempts
WHEN NOT EXISTS(SELECT 1 FROM trusted_discovery_reviews r WHERE r.id=NEW.review_id
AND r.state='PRECONSENTED' AND r.organization_id=NEW.organization_id AND r.target_id=NEW.target_id
AND r.route_key=NEW.route_key AND r.source_scan_id=NEW.source_scan_id AND r.source_digest=NEW.source_digest
AND r.source_generation=NEW.source_generation AND r.attempt_identity=NEW.attempt_identity
AND r.expires_at>NEW.reserved_at AND r.preconsented_at<=NEW.reserved_at)
BEGIN SELECT RAISE(ABORT,'TRUSTED_DISCOVERY_ATTEMPT_BINDING'); END;
CREATE TRIGGER trusted_attempt_no_delete BEFORE DELETE ON trusted_discovery_attempts
BEGIN SELECT RAISE(ABORT,'TRUSTED_DISCOVERY_ATTEMPT_IMMUTABLE'); END;
CREATE TRIGGER trusted_attempt_no_update BEFORE UPDATE ON trusted_discovery_attempts
BEGIN SELECT RAISE(ABORT,'TRUSTED_DISCOVERY_ATTEMPT_IMMUTABLE'); END;
`,
  },
] as const;
