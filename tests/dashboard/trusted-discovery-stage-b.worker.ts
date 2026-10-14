import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import { join } from "node:path";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ServerSessionManager, type ServerRuntimeSecurity } from "../../src/dashboard/auth/ServerSession.js";
import { TrustedDiscoveryReviewStore } from "../../src/dashboard/execution/TrustedDiscoveryReviewStore.js";
import { TrustedDiscoveryWitness } from "../../src/dashboard/execution/TrustedDiscoveryWitness.js";
import { TrustedDiscoveryOperatorService } from "../../src/dashboard/execution/TrustedDiscoveryOperatorService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

interface Input {
  root: string;
  witnessRoot: string;
  origin: string;
  organization: string;
  scanId: string;
  candidateId: string;
  security: ServerRuntimeSecurity;
  cookie: string;
  csrf: string;
  crashAfterWitness?: boolean;
  outcomeCrash?: "BEFORE_WRITE" | "AFTER_WITNESS_COMMIT";
}
process.on("uncaughtException", (error) => {
  process.send?.({ failure: /^[A-Z0-9_]+$/.test(error.message) ? error.message : "FIXTURE_NATIVE_STARTUP_FAILURE" });
  process.exit(1);
});
process.once("message", async (input: Input) => {
  const paths = resolveDashboardPaths(input.root),
    database = new DashboardDatabase(paths.databasePath);
  const store = new TrustedDiscoveryReviewStore(database, join(input.root, "keys", "trusted-discovery-review.key"));
  const witness = TrustedDiscoveryWitness.openFixture(database, store, input.witnessRoot, input.origin);
  const sessions = new ServerSessionManager(database, input.security);
  const service = new TrustedDiscoveryOperatorService(database, paths, sessions, witness);
  const authority = () => {
    const request = new IncomingMessage(new Socket());
    request.headers = {
      cookie: input.cookie,
      origin: input.security.publicOrigin,
      "x-forwarded-proto": "https",
      "content-type": "application/json"
    };
    return sessions.captureTrustedDiscoverySession(request, input.csrf);
  };
  try {
    const { review } = await service.review(
      { scanId: input.scanId, candidateId: input.candidateId },
      authority(),
      input.organization
    );
    process.send?.({ ready: true, pid: process.pid });
    await new Promise<void>((done) => process.once("message", () => done()));
    if (input.crashAfterWitness) {
      await service.preconsent(
        { ...review, confirmation: "I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET" },
        authority(),
        input.organization
      );
      const row = database.db
        .prepare("SELECT id FROM trusted_discovery_reviews ORDER BY created_at DESC LIMIT 1")
        .get() as { id: string };
      database.db
        .transaction(() => {
          witness.spend(database, store, store.attemptDescriptor(row.id));
          process.exit(86);
        })
        .immediate();
    }
    if (input.outcomeCrash === "BEFORE_WRITE") witness.recordOutcome = () => process.exit(87);
    if (input.outcomeCrash === "AFTER_WITNESS_COMMIT") {
      database.db.function("fixture_outcome_crash", () => process.exit(88));
      database.db.exec(
        "CREATE TEMP TRIGGER fixture_outcome_commit_crash BEFORE UPDATE ON dashboard_meta WHEN NEW.key='trusted_discovery_outcome_checkpoint_v2' BEGIN SELECT fixture_outcome_crash(); END"
      );
    }
    const result = await service.executeFresh(
      { ...review, confirmation: "I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET" },
      authority(),
      input.organization
    );
    process.send?.({ result, pid: process.pid });
  } finally {
    await service.shutdown();
    store.dispose();
    database.close();
    process.disconnect();
  }
});
