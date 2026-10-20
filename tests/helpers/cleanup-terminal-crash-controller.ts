import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { ControlledMutationRecoveryService } from "../../src/dashboard/execution/ControlledMutationRecoveryService.js";
import { WorkflowRecoveryService } from "../../src/dashboard/execution/WorkflowRecoveryService.js";
import { CleanupAttemptLedger } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
const root = process.argv[2]!,
  family = process.argv[3]!,
  paths = resolveDashboardPaths(root),
  database = new DashboardDatabase(paths.databasePath),
  ledger = CleanupAttemptLedger.for(database),
  input = JSON.parse(readFileSync(join(root, "TERMINAL_CONTROLLER_INPUT.json"), "utf8"));
ledger.gate = () => {
  throw Error("RECOVERY_FIXTURE_GRANT_REFUSED");
};
const interrupt = ledger.interrupt.bind(ledger);
ledger.interrupt = (id: string) => {
  interrupt(id);
  writeFileSync(
    join(root, "TERMINAL_INTERRUPT_BOUNDARY.json"),
    JSON.stringify(
      { family, pid: process.pid, history: ledger.history(id), insideTransaction: database.db.inTransaction },
      null,
      2
    ),
    { flag: "wx" }
  );
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
};
const targets = new TargetRepository(database),
  vault = new CredentialVault(database, { bytes: Buffer.alloc(32, 6), version: "1" });
writeFileSync(join(root, "TERMINAL_CONTROLLER_READY.json"), JSON.stringify({ pid: process.pid, family }), {
  flag: "wx"
});
if (family === "CONTROLLED") {
  const s = new ControlledMutationRecoveryService(database, paths, targets, vault);
  await (
    await s.startRecovery(input)
  ).completion;
} else {
  const s = new WorkflowRecoveryService(database, paths, targets, vault);
  await s.enqueue(input, "local-operator");
  setInterval(() => {}, 1000);
}
