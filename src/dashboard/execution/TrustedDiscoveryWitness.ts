import SqliteDatabase from "better-sqlite3";
import { createHmac, timingSafeEqual } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { types } from "node:util";
import { readBoundedFileSync } from "../security/BoundedFile.js";
import { DashboardDatabase } from "../db/DashboardDatabase.js";
import { TrustedDiscoveryReviewStore, type DiscoveryAttemptDescriptor } from "./TrustedDiscoveryReviewStore.js";
import type { TrustedDiscoveryFacts } from "./TrustedDiscoveryBinding.js";
import { withTrustedDiscoveryDatabaseDeadline } from "./TrustedDiscoveryDatabaseDeadline.js";

const marker = "trusted_discovery_stage_b_witness_v1";
const outcomeMarker = "trusted_discovery_outcome_checkpoint_v2";
const nativeWitnesses = new WeakSet<object>();
const capacity = 4096;
const fail = (): never => {
  throw new Error("TRUSTED_DISCOVERY_WITNESS_INCONSISTENT");
};
function canonical(path: string, directory: boolean): string {
  const value = resolve(path);
  if (!isAbsolute(path) || /^\\\\/.test(path) || value !== path || path.slice(3).includes(":")) fail();
  const stat = lstatSync(value);
  if (
    stat.isSymbolicLink() ||
    (directory ? !stat.isDirectory() : !stat.isFile()) ||
    realpathSync(value).toLowerCase() !== value.toLowerCase()
  )
    fail();
  return value;
}
function outside(root: string, data: string): void {
  const rel = relative(data, root);
  if (!rel || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(".." + sep))) fail();
}
function metadata(database: DashboardDatabase, key: string): string {
  const row = database.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as
    { value: string } | undefined;
  if (!row || row.value.length > 2048) return fail();
  return row.value;
}
function scope(database: DashboardDatabase, store: TrustedDiscoveryReviewStore, root: string, origin: string): string {
  return store.hash("independent-witness-scope-v1", [
    canonical(database.databasePath, false),
    root,
    metadata(database, "installation_id"),
    origin
  ]);
}
function values(row: DiscoveryAttemptDescriptor): readonly string[] {
  return [
    row.organization_id,
    row.target_id,
    row.route_key,
    row.review_id,
    row.source_scan_id,
    row.source_digest,
    row.source_generation,
    row.attempt_identity
  ];
}
interface Entry extends DiscoveryAttemptDescriptor {
  seq: number;
  previous: string;
  seal: string;
}
interface Checkpoint {
  binding: string;
  seq: number;
  tip: string;
}
interface Outcome {
  seq: number;
  review_id: string;
  initiated: number;
  observed: number;
  previous: string;
  seal: string;
}
interface OutcomeCheckpoint extends Checkpoint {
  seal: string;
}

/** Internal disposable-fixture witness. No CLI, HTTP, environment setting or SDK export.
 * Independent of ordinary SQLite backups; not an all-disks monotonic anchor. */
export class TrustedDiscoveryWitness {
  readonly #key: Buffer;
  readonly #db: SqliteDatabase.Database;
  private closed = false;
  public readonly protection = "DB_AND_DATA_DIRECTORY_ROLLBACK_ONLY" as const;
  private readonly binding: string;
  private readonly genesis: string;
  private readonly fileIdentity: { dev: number; ino: number };
  private readonly mainFileIdentity: { dev: number; ino: number };
  private constructor(
    private readonly databasePath: string,
    private readonly root: string,
    public readonly fixtureOrigin: string,
    database: DashboardDatabase,
    store: TrustedDiscoveryReviewStore
  ) {
    const url = new URL(fixtureOrigin);
    if (
      url.origin !== fixtureOrigin ||
      url.protocol !== "http:" ||
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      url.username ||
      url.password
    )
      fail();
    canonical(root, true);
    outside(root, resolve(databasePath, ".."));
    this.mainFileIdentity = lstatSync(canonical(databasePath, false));
    const key = readBoundedFileSync(canonical(join(root, "witness.key"), false), 64).toString("utf8");
    if (!/^[a-f0-9]{64}$/.test(key)) fail();
    this.#key = Buffer.from(key, "hex");
    this.binding = scope(database, store, root, fixtureOrigin);
    this.genesis = this.seal(["binding", this.binding]);
    const path = canonical(join(root, "witness.sqlite"), false);
    this.fileIdentity = lstatSync(path);
    this.#db = new SqliteDatabase(path, { fileMustExist: true, timeout: 100 });
    try {
      this.#db.pragma("synchronous=FULL");
      this.#db.pragma("foreign_keys=ON");
      this.assertConsistent(database, store);
      nativeWitnesses.add(this);
    } catch (error) {
      this.#db.close();
      this.#key.fill(0);
      throw error;
    }
  }
  /** Open pre-provisioned native fixture custody only. Product code cannot create,
   * reset, rotate or choose a new empty witness after a historical DB restore. */
  public static openFixture(
    database: DashboardDatabase,
    store: TrustedDiscoveryReviewStore,
    root: string,
    origin: string
  ): TrustedDiscoveryWitness {
    if (
      types.isProxy(database) ||
      types.isProxy(store) ||
      !(database instanceof DashboardDatabase) ||
      !(store instanceof TrustedDiscoveryReviewStore)
    )
      fail();
    return new TrustedDiscoveryWitness(database.databasePath, root, origin, database, store);
  }
  public static isNative(value: unknown): value is TrustedDiscoveryWitness {
    return !!value && typeof value === "object" && !types.isProxy(value) && nativeWitnesses.has(value);
  }
  public requireProtection(profile: string): void {
    if (profile !== this.protection) throw new Error("TRUSTED_DISCOVERY_EXTERNAL_ANCHOR_REQUIRED");
  }
  public toJSON(): never {
    throw Error("PRIVATE_WITNESS_NOT_SERIALIZABLE");
  }
  public assertConsistent(database: DashboardDatabase, store: TrustedDiscoveryReviewStore): void {
    this.checkFiles();
    store.assertKeyCustody();
    if (
      database.databasePath !== this.databasePath ||
      scope(database, store, this.root, this.fixtureOrigin) !== this.binding
    )
      fail();
    // Fresh read handle avoids treating cached SQLite pages as proof that the
    // independent backing file still contains the authenticated witness.
    const read = new SqliteDatabase(join(this.root, "witness.sqlite"), {
      readonly: true,
      fileMustExist: true,
      timeout: 100
    });
    let entries: Entry[];
    let outcomes: Outcome[];
    try {
      // One coherent witness read snapshot, never a mixture of concurrent heads.
      read.exec("BEGIN");
      const bound = read.prepare("SELECT value FROM binding").all() as { value: string }[];
      if (bound.length !== 1 || bound[0]!.value !== this.genesis) fail();
      const guards = read
        .prepare(
          "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN ('outcomes_no_delete','outcomes_no_update') LIMIT 3"
        )
        .all() as { name: string; sql: string }[];
      if (guards.length !== 2) fail();
      for (const guard of guards) {
        const event = guard.name === "outcomes_no_delete" ? "DELETE" : "UPDATE";
        const expected = `CREATE TRIGGER ${guard.name} BEFORE ${event} ON outcomes BEGIN SELECT RAISE(ABORT,'WITNESS_IMMUTABLE'); END`;
        if (guard.sql.replace(/\s+/g, " ").trim() !== expected) fail();
      }
      const count = read.prepare("SELECT count(*) AS n FROM attempts").get() as { n: number };
      if (count.n > capacity) fail();
      entries = read.prepare("SELECT * FROM attempts ORDER BY seq").all() as Entry[];
      outcomes = read.prepare("SELECT * FROM outcomes ORDER BY seq LIMIT 4097").all() as Outcome[];
      if (outcomes.length > capacity) fail();
    } finally {
      if (read.inTransaction) read.exec("ROLLBACK");
      read.close();
    }
    let tip = this.genesis;
    entries.forEach((entry, index) => {
      if (
        entry.seq !== index + 1 ||
        entry.previous !== tip ||
        entry.seal !== this.seal([String(entry.seq), tip, ...values(entry)])
      )
        fail();
      tip = entry.seal;
    });
    const checkpoint = JSON.parse(metadata(database, marker)) as Checkpoint;
    if (checkpoint.binding !== this.genesis || checkpoint.seq !== entries.length || checkpoint.tip !== tip) fail();
    if (
      (database.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get() as { n: number }).n > capacity
    )
      fail();
    const attempted = database.db
      .prepare("SELECT * FROM trusted_discovery_attempts ORDER BY organization_id,target_id,route_key")
      .all() as DiscoveryAttemptDescriptor[];
    if (attempted.length !== entries.length) fail();
    const byReview = new Map(entries.map((entry) => [entry.review_id, entry]));
    if (byReview.size !== entries.length) fail();
    const outcomeHead = this.outcomeCheckpoint(database),
      seenOutcomes = new Set<string>();
    let outcomeTip = this.outcomeGenesis();
    outcomes.forEach((outcome, index) => {
      const attempt = byReview.get(outcome.review_id);
      if (
        !attempt ||
        seenOutcomes.has(outcome.review_id) ||
        outcome.seq !== index + 1 ||
        outcome.previous !== outcomeTip ||
        ![0, 1].includes(outcome.initiated) ||
        ![0, 1].includes(outcome.observed) ||
        outcome.observed > outcome.initiated ||
        outcome.seal !==
          this.outcomeSeal(
            outcome.seq,
            outcomeTip,
            attempt.seal,
            outcome.review_id,
            outcome.initiated,
            outcome.observed
          )
      )
        fail();
      seenOutcomes.add(outcome.review_id);
      outcomeTip = outcome.seal;
    });
    if (outcomeHead.seq !== outcomes.length || outcomeHead.tip !== outcomeTip) fail();
    for (const row of attempted) {
      const entry = byReview.get(row.review_id);
      if (!entry || JSON.stringify(values(row)) !== JSON.stringify(values(entry))) fail();
    }
  }
  /** Called under the MAIN DB immediate transaction: witness commits first. A crash
   * before main commit leaves a permanent unmatched witness and denies future opens. */
  public spend(database: DashboardDatabase, store: TrustedDiscoveryReviewStore, row: DiscoveryAttemptDescriptor): void {
    if (!database.db.inTransaction) fail();
    this.assertConsistent(database, store);
    this.#db
      .transaction(() => {
        const head = JSON.parse(metadata(database, marker)) as Checkpoint;
        if (head.seq >= capacity) throw new Error("TRUSTED_DISCOVERY_WITNESS_CAPACITY");
        const seq = head.seq + 1,
          seal = this.seal([String(seq), head.tip, ...values(row)]);
        this.#db
          .prepare(
            "INSERT INTO attempts(seq,organization_id,target_id,route_key,review_id,source_scan_id,source_digest,source_generation,attempt_identity,previous,seal) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
          )
          .run(seq, ...values(row), head.tip, seal);
        const updated = database.db
          .prepare("UPDATE dashboard_meta SET value=?,updated_at=? WHERE key=? AND value=?")
          .run(
            JSON.stringify({ binding: this.genesis, seq, tip: seal }),
            new Date().toISOString(),
            marker,
            JSON.stringify(head)
          );
        if (updated.changes !== 1) fail();
      })
      .immediate();
  }
  public assertOwn(
    database: DashboardDatabase,
    store: TrustedDiscoveryReviewStore,
    expected: DiscoveryAttemptDescriptor
  ): void {
    this.assertConsistent(database, store);
    const row = database.db
      .prepare("SELECT * FROM trusted_discovery_attempts WHERE review_id=?")
      .get(expected.review_id) as DiscoveryAttemptDescriptor | undefined;
    if (!row || JSON.stringify(values(row)) !== JSON.stringify(values(expected))) fail();
  }
  public recordOutcome(
    database: DashboardDatabase,
    store: TrustedDiscoveryReviewStore,
    id: string,
    facts: TrustedDiscoveryFacts
  ): void {
    // A caller's outer transaction could otherwise keep the main commitment
    // uncommitted after this function returns. Only this transaction owns it.
    if (database.db.inTransaction) fail();
    withTrustedDiscoveryDatabaseDeadline(database, () =>
      database.db
        .transaction(() => {
          this.assertConsistent(database, store);
          if (
            ![0, 1].includes(facts.initiated) ||
            ![0, 1].includes(facts.responseObserved) ||
            facts.responseObserved > facts.initiated
          )
            fail();
          const attempt = this.#db.prepare("SELECT * FROM attempts WHERE review_id=?").get(id) as Entry | undefined;
          if (!attempt) return fail();
          const original = metadata(database, outcomeMarker),
            head = this.outcomeCheckpoint(database);
          if (head.seq >= capacity) throw Error("TRUSTED_DISCOVERY_WITNESS_CAPACITY");
          const seq = head.seq + 1,
            seal = this.outcomeSeal(seq, head.tip, attempt.seal, id, facts.initiated, facts.responseObserved);
          this.#db
            .transaction(() => {
              this.#db
                .prepare("INSERT INTO outcomes(seq,review_id,initiated,observed,previous,seal) VALUES(?,?,?,?,?,?)")
                .run(seq, id, facts.initiated, facts.responseObserved, head.tip, seal);
            })
            .immediate(); // Independent FULL-synchronous witness COMMIT FIRST.
          const binding = this.outcomeGenesis(),
            checkpoint = { binding, seq, tip: seal, seal: this.checkpointSeal(binding, seq, seal) };
          const changed = database.db
            .prepare("UPDATE dashboard_meta SET value=?,updated_at=? WHERE key=? AND value=?")
            .run(JSON.stringify(checkpoint), new Date().toISOString(), outcomeMarker, original);
          if (changed.changes !== 1) fail();
          this.assertConsistent(database, store);
        })
        .immediate()
    ); // Main COMMIT SECOND; rollback leaves divergence, never retry.
  }
  public close(): void {
    if (this.closed) return;
    this.closed = true;
    nativeWitnesses.delete(this);
    this.#db.close();
    this.#key.fill(0);
  }
  private seal(input: readonly string[]): string {
    return createHmac("sha256", this.#key).update(JSON.stringify(input)).digest("hex");
  }
  private outcomeGenesis(): string {
    return this.seal(["outcome-ledger-v2", this.genesis]);
  }
  private outcomeSeal(
    seq: number,
    previous: string,
    attemptSeal: string,
    id: string,
    initiated: number,
    observed: number
  ): string {
    return this.seal(["outcome-entry-v2", String(seq), previous, attemptSeal, id, String(initiated), String(observed)]);
  }
  private checkpointSeal(binding: string, seq: number, tip: string): string {
    return this.seal(["outcome-checkpoint-v2", binding, String(seq), tip]);
  }
  private outcomeCheckpoint(database: DashboardDatabase): OutcomeCheckpoint {
    const head = JSON.parse(metadata(database, outcomeMarker)) as OutcomeCheckpoint;
    if (
      !head ||
      head.binding !== this.outcomeGenesis() ||
      !Number.isSafeInteger(head.seq) ||
      head.seq < 0 ||
      head.seq > capacity ||
      !/^[a-f0-9]{64}$/.test(head.tip) ||
      head.seal !== this.checkpointSeal(head.binding, head.seq, head.tip)
    )
      fail();
    return head;
  }
  private checkFiles(): void {
    if (this.closed) fail();
    canonical(this.root, true);
    const main = lstatSync(canonical(this.databasePath, false));
    if (main.dev !== this.mainFileIdentity.dev || main.ino !== this.mainFileIdentity.ino) fail();
    const path = canonical(join(this.root, "witness.sqlite"), false),
      stat = lstatSync(path);
    if (stat.dev !== this.fileIdentity.dev || stat.ino !== this.fileIdentity.ino || stat.size > 8 * 1024 * 1024) fail();
    const key = readBoundedFileSync(canonical(join(this.root, "witness.key"), false), 64).toString("utf8");
    const actual = Buffer.from(key, "hex");
    if (!/^[a-f0-9]{64}$/.test(key) || actual.length !== this.#key.length || !timingSafeEqual(actual, this.#key))
      fail();
    actual.fill(0);
  }
}
