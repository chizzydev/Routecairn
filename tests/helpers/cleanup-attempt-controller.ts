import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ControlledMutationRecoveryService } from "../../src/dashboard/execution/ControlledMutationRecoveryService.js";
import { CleanupAttemptLedger, type CleanupPhase } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
const root = process.argv[2]!,
  phase = process.argv[3]!,
  input = JSON.parse(readFileSync(join(root, "CONTROLLER_INPUT.json"), "utf8")),
  paths = resolveDashboardPaths(root),
  database = new DashboardDatabase(paths.databasePath);
database.migrate();
const ledger = CleanupAttemptLedger.for(database);
function stop() {
  writeFileSync(
    join(root, "CONTROLLER_PHASE.json"),
    JSON.stringify({
      phase,
      pid: process.pid,
      attempts: database.db.prepare("SELECT id,job_id FROM cleanup_attempts").all()
    }),
    { flag: "wx" }
  );
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
}
const append = ledger.append.bind(ledger);
ledger.append = (id: string, kind: CleanupPhase, evidence: Record<string, unknown>) => {
  const result = append(id, kind, evidence);
  if (kind === phase && phase !== "AUTHORIZED") stop();
  return result;
};
if (phase === "AUTHORIZED") {
  const reserve = ledger.reserve.bind(ledger);
  ledger.reserve = (...args) => {
    const result = reserve(...args);
    stop();
    return result;
  };
}
const service = new ControlledMutationRecoveryService(
  database,
  paths,
  new TargetRepository(database),
  new CredentialVault(database, { bytes: Buffer.alloc(32, 6), version: "1" })
);
writeFileSync(
  join(root, "CONTROLLER_READY.json"),
  JSON.stringify({
    pid: process.pid,
    readyAt: new Date().toISOString(),
    synchronous: database.db.pragma("synchronous", { simple: true })
  }),
  { flag: "wx" }
);
const accepted = await service.startRecovery(input);
await accepted.completion;
if (phase === "COMMITTED") stop();
throw Error("EXPECTED_PHASE_NOT_REACHED");
