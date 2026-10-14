import { withTrustedDiscoveryDatabaseDeadline } from "./TrustedDiscoveryDatabaseDeadline.js";
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { loadOrCreateHexKey } from "../security/BoundedFile.js";
import { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { TrustedDiscoverySnapshot, TrustedDiscoveryActor } from "./TrustedDiscoverySource.js";

export class TrustedDiscoveryStageAError extends Error {
  public constructor(
    public readonly code:
      | "DENIED_AUTHORITY"
      | "DENIED_REVIEW"
      | "DENIED_SOURCE"
      | "DENIED_CAPACITY"
      | "DENIED_DUPLICATE"
      | "DENIED_SCOPE"
      | "UNAVAILABLE",
    public readonly status = 409,
  ) {
    super(code);
  }
}
export interface DiscoveryReviewMetadata {
  id: string;
  actor: TrustedDiscoveryActor;
  sessionId: string;
  snapshot: TrustedDiscoverySnapshot;
  candidateId: string;
  route: string;
  createdAt: number;
  expiresAt: number;
  reviewDigest: string;
}
/** Durable metadata and future reservation foundation. No broker or operation issuance here.
 * This internal module is neither a public route nor a third-party module capability. */
export class TrustedDiscoveryReviewStore {
  readonly #key: Buffer;
  private disposed = false;
  public constructor(
    private readonly database: DashboardDatabase,
    keyPath: string,
  ) {
    if (!(database instanceof DashboardDatabase)) throw new Error("TRUSTED_DISCOVERY_NATIVE_DATABASE_REQUIRED");
    const existing = database.db
      .prepare("SELECT value FROM dashboard_meta WHERE key='trusted_discovery_namespace_v1'")
      .get() as { value: string } | undefined;
    const records = (
      database.db
        .prepare(
          "SELECT (SELECT count(*) FROM trusted_discovery_reviews)+(SELECT count(*) FROM trusted_discovery_attempts) AS n",
        )
        .get() as { n: number }
    ).n;
    if ((existing || records) && !existsSync(keyPath)) throw new Error("TRUSTED_DISCOVERY_KEY_MISSING");
    if (records && !existing) throw new Error("TRUSTED_DISCOVERY_KEY_NAMESPACE_MISSING");
    this.#key = loadOrCreateHexKey(keyPath);
    const verifier = this.hash("namespace-v1", []);
    try {
      withTrustedDiscoveryDatabaseDeadline(database, () =>
        database.db
          .transaction(() => {
            database.db
              .prepare(
                "INSERT OR IGNORE INTO dashboard_meta(key,value,updated_at) VALUES('trusted_discovery_namespace_v1',?,?)",
              )
              .run(verifier, new Date().toISOString());
            const stored = database.db
              .prepare("SELECT value FROM dashboard_meta WHERE key='trusted_discovery_namespace_v1'")
              .get() as { value: string };
            const actual = Buffer.from(stored.value),
              expected = Buffer.from(verifier);
            if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
              throw new Error("TRUSTED_DISCOVERY_KEY_CHANGED");
          })
          .immediate(),
      );
    } catch (error) {
      this.#key.fill(0);
      throw error;
    }
  }
  public hash(purpose: string, values: readonly string[]): string {
    if (this.disposed) throw new Error("TRUSTED_DISCOVERY_STORE_CLOSED");
    return createHmac("sha256", this.#key)
      .update("routecairn-trusted-discovery-stage-a-v1\0" + purpose + "\0" + JSON.stringify(values))
      .digest("hex");
  }
  public routeKey(actor: TrustedDiscoveryActor, targetId: string, route: string): string {
    return this.hash("route-tombstone", [actor.organizationId, targetId, "GET", route]);
  }
  public hasAttempt(actor: TrustedDiscoveryActor, targetId: string, route: string): boolean {
    return !!this.database.db
      .prepare("SELECT 1 FROM trusted_discovery_attempts WHERE organization_id=? AND target_id=? AND route_key=?")
      .get(actor.organizationId, targetId, this.routeKey(actor, targetId, route));
  }
  public save(input: DiscoveryReviewMetadata): void {
    const { actor, snapshot } = input;
    // The enclosing immediate transaction binds fresh native checks to metadata commit.
    this.database.db
      .prepare(
        "DELETE FROM trusted_discovery_reviews WHERE expires_at<? AND NOT EXISTS(SELECT 1 FROM trusted_discovery_attempts a WHERE a.review_id=trusted_discovery_reviews.id)",
      )
      .run(Date.now() - 30 * 24 * 60 * 60 * 1000);
    if (
      (this.database.db.prepare("SELECT count(*) AS n FROM trusted_discovery_reviews").get() as { n: number }).n >=
      10000
    )
      throw new TrustedDiscoveryStageAError("DENIED_CAPACITY");
    this.database.db
      .prepare(
        `INSERT INTO trusted_discovery_reviews(id,organization_id,user_id,session_binding,target_id,source_scan_id,candidate_id,source_digest,source_generation,target_generation,route_key,attempt_identity,review_digest,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'REVIEWED',?,?)`,
      )
      .run(
        input.id,
        actor.organizationId,
        actor.userId,
        this.hash("session", [input.sessionId]),
        snapshot.targetId,
        snapshot.scanId,
        input.candidateId,
        snapshot.digest,
        snapshot.generation,
        snapshot.targetGeneration,
        this.routeKey(actor, snapshot.targetId, input.route),
        this.hash("exact-attempt", [
          actor.organizationId,
          snapshot.targetId,
          "GET",
          input.route,
          snapshot.scanId,
          snapshot.digest,
          snapshot.generation,
        ]),
        input.reviewDigest,
        input.createdAt,
        input.expiresAt,
      );
    this.event(input.id, actor.organizationId, "REVIEWED");
  }
  public preconsent(id: string, actor: TrustedDiscoveryActor, sessionId: string): void {
    const changed = this.database.db
      .prepare(
        "UPDATE trusted_discovery_reviews SET state='PRECONSENTED',preconsented_at=? WHERE id=? AND organization_id=? AND user_id=? AND session_binding=? AND state='REVIEWED' AND expires_at>?",
      )
      .run(Date.now(), id, actor.organizationId, actor.userId, this.hash("session", [sessionId]), Date.now());
    if (changed.changes !== 1) throw new TrustedDiscoveryStageAError("DENIED_REVIEW");
    this.event(id, actor.organizationId, "PRECONSENTED");
  }
  public invalidate(id: string, organizationId: string): void {
    withTrustedDiscoveryDatabaseDeadline(this.database, () =>
      this.database.db
        .transaction(() => {
          const result = this.database.db
            .prepare(
              "UPDATE trusted_discovery_reviews SET state='INVALIDATED' WHERE id=? AND organization_id=? AND state='REVIEWED'",
            )
            .run(id, organizationId);
          if (result.changes) this.event(id, organizationId, "INVALIDATED");
        })
        .immediate(),
    );
  }
  /** Future Stage B must additionally bind native final-transport authority and live source checks.
   * This reserves a tombstone only; it grants no operation, transmission or automatic retry. */
  public reserveFutureAttempt(id: string): boolean {
    if (this.disposed) throw new Error("TRUSTED_DISCOVERY_STORE_CLOSED");
    return withTrustedDiscoveryDatabaseDeadline(this.database, () =>
      this.database.db
        .transaction(() => {
          if (
            (this.database.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get() as { n: number })
              .n >= 100000
          )
            throw new TrustedDiscoveryStageAError("DENIED_CAPACITY");
          const result = this.database.db
            .prepare(
              `INSERT INTO trusted_discovery_attempts(organization_id,target_id,route_key,review_id,source_scan_id,source_digest,source_generation,attempt_identity,reserved_at)
SELECT organization_id,target_id,route_key,id,source_scan_id,source_digest,source_generation,attempt_identity,? FROM trusted_discovery_reviews
WHERE id=? AND state='PRECONSENTED' AND expires_at>? ON CONFLICT DO NOTHING`,
            )
            .run(Date.now(), id, Date.now());
          return result.changes === 1;
        })
        .immediate(),
    );
  }
  public dispose(): void {
    this.disposed = true;
    this.#key.fill(0);
  }
  private event(id: string, organizationId: string, code: string): void {
    this.database.db
      .prepare(
        "INSERT INTO trusted_discovery_review_events(id,organization_id,review_id,code,created_at) VALUES(?,?,?,?,?)",
      )
      .run(randomUUID(), organizationId, id, code, Date.now());
  }
}
