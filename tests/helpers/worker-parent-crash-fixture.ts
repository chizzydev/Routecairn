// Standalone test controller. The owner test kills THIS generated controller by
// its live ChildProcess handle; the real ScanWorkerMain must handle IPC loss.
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { OwnedTemporaryResource } from "../../src/core/storage/OwnedTemporaryResource.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { exampleScope } from "../../src/config/defaults.js";

const parent = process.env.ROUTECAIRN_WORKER_LAB, target = process.env.ROUTECAIRN_PARENT_CRASH_TARGET;
if (!parent || !target || new URL(target).hostname !== "127.0.0.1" || !process.send) throw Error("Owned loopback IPC fixture required");
const resource = OwnedTemporaryResource.create(parent, { purpose: "real-worker-parent-crash" });
const paths = resolveDashboardPaths(resource.root), database = new DashboardDatabase(paths.databasePath); database.migrate();
const scopeFile = join(resource.root, "scope.json"); writeFileSync(scopeFile, JSON.stringify({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET"], concurrency: 1, rateLimitPerSecond: 20 }), { flag: "wx" });
const execution = new ScanExecutionService(database, paths);
const id = await execution.enqueue({ target, scopeFile, profile: "quick", includeModules: ["baseline"], maxRequests: 4, rateLimitPerSecond: 20, concurrency: 1 });
const timer = setInterval(() => {
  const row = database.db.prepare("SELECT process_identity_json FROM worker_resources WHERE job_id = ? AND state = 'RUNNING'").get(id) as { process_identity_json: string } | undefined;
  if (row) { clearInterval(timer); process.send?.({ type: "OWNED_ROOT_READY", root: resource.root, scanId: id, identity: JSON.parse(row.process_identity_json) }); }
}, 50);
process.on("disconnect", () => { void execution.shutdown().finally(() => { database.close(); resource.retain("CONTROLLER_DISCONNECTED"); process.exit(0); }); });
