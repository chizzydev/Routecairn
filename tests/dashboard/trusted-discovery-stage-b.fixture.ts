import SqliteDatabase from "better-sqlite3";
import { createHmac, randomBytes } from "node:crypto";
import { chmodSync, existsSync, realpathSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { TrustedDiscoveryReviewStore } from "../../src/dashboard/execution/TrustedDiscoveryReviewStore.js";
import { TrustedDiscoveryWitness } from "../../src/dashboard/execution/TrustedDiscoveryWitness.js";

/** Disposable test bootstrap, not compiled, packaged, registered or imported by
 * production source. It cannot serve as an operator reinitialization API. */
export function provisionFixtureWitness(
  database: DashboardDatabase,
  store: TrustedDiscoveryReviewStore,
  root: string,
  origin: string
): TrustedDiscoveryWitness {
  const marker = "trusted_discovery_stage_b_witness_v1";
  const path = join(root, "witness.sqlite"),
    keyPath = join(root, "witness.key");
  database.db
    .transaction(() => {
      if (
        database.db.prepare("SELECT 1 FROM dashboard_meta WHERE key=?").get(marker) ||
        database.db.prepare("SELECT 1 FROM trusted_discovery_reviews LIMIT 1").get() ||
        database.db.prepare("SELECT 1 FROM trusted_discovery_attempts LIMIT 1").get() ||
        readdirSync(root).length ||
        existsSync(path) ||
        existsSync(keyPath)
      )
        throw Error("FIXTURE_WITNESS_ALREADY_BOUND");
      const installation = database.db
        .prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'")
        .get() as { value: string };
      const binding = store.hash("independent-witness-scope-v1", [
        realpathSync(database.databasePath),
        root,
        installation.value,
        origin
      ]);
      const key = randomBytes(32),
        genesis = createHmac("sha256", key)
          .update(JSON.stringify(["binding", binding]))
          .digest("hex");
      const outcomeGenesis = createHmac("sha256", key)
        .update(JSON.stringify(["outcome-ledger-v2", genesis]))
        .digest("hex");
      const outcomeCheckpoint = {
        binding: outcomeGenesis,
        seq: 0,
        tip: outcomeGenesis,
        seal: createHmac("sha256", key)
          .update(JSON.stringify(["outcome-checkpoint-v2", outcomeGenesis, "0", outcomeGenesis]))
          .digest("hex")
      };
      chmodSync(root, 0o700);
      writeFileSync(keyPath, key.toString("hex"), { flag: "wx", mode: 0o600 });
      key.fill(0);
      const witness = new SqliteDatabase(path, { timeout: 100 });
      try {
        chmodSync(path, 0o600);
        witness.pragma("journal_mode=DELETE");
        witness.pragma("synchronous=FULL");
        witness.pragma("foreign_keys=ON");
        witness.exec(`CREATE TABLE binding(value TEXT NOT NULL); CREATE TABLE attempts(seq INTEGER PRIMARY KEY,organization_id TEXT NOT NULL,target_id TEXT NOT NULL,route_key TEXT NOT NULL,review_id TEXT NOT NULL UNIQUE,source_scan_id TEXT NOT NULL,source_digest TEXT NOT NULL,source_generation TEXT NOT NULL,attempt_identity TEXT NOT NULL,previous TEXT NOT NULL,seal TEXT NOT NULL,UNIQUE(organization_id,target_id,route_key));
CREATE TRIGGER witness_no_delete BEFORE DELETE ON attempts BEGIN SELECT RAISE(ABORT,'WITNESS_IMMUTABLE'); END;
CREATE TRIGGER witness_no_update BEFORE UPDATE ON attempts BEGIN SELECT RAISE(ABORT,'WITNESS_IMMUTABLE'); END;
CREATE TABLE outcomes(seq INTEGER PRIMARY KEY,review_id TEXT NOT NULL UNIQUE REFERENCES attempts(review_id),initiated INTEGER NOT NULL CHECK(initiated IN(0,1)),observed INTEGER NOT NULL CHECK(observed IN(0,1) AND observed<=initiated),previous TEXT NOT NULL,seal TEXT NOT NULL);
CREATE TRIGGER outcomes_no_delete BEFORE DELETE ON outcomes BEGIN SELECT RAISE(ABORT,'WITNESS_IMMUTABLE'); END;
CREATE TRIGGER outcomes_no_update BEFORE UPDATE ON outcomes BEGIN SELECT RAISE(ABORT,'WITNESS_IMMUTABLE'); END;`);
        witness.prepare("INSERT INTO binding(value) VALUES(?)").run(genesis);
        database.db
          .prepare("INSERT INTO dashboard_meta(key,value,updated_at) VALUES(?,?,?)")
          .run(marker, JSON.stringify({ binding: genesis, seq: 0, tip: genesis }), new Date().toISOString());
        database.db
          .prepare("INSERT INTO dashboard_meta(key,value,updated_at) VALUES(?,?,?)")
          .run("trusted_discovery_outcome_checkpoint_v2", JSON.stringify(outcomeCheckpoint), new Date().toISOString());
      } finally {
        witness.close();
      }
    })
    .immediate();
  return TrustedDiscoveryWitness.openFixture(database, store, root, origin);
}
