import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import { join } from "node:path";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ServerSessionManager, type ServerRuntimeSecurity } from "../../src/dashboard/auth/ServerSession.js";
import { TrustedDiscoveryReviewStore } from "../../src/dashboard/execution/TrustedDiscoveryReviewStore.js";
import { TrustedDiscoveryWitness } from "../../src/dashboard/execution/TrustedDiscoveryWitness.js";
import { TrustedDiscoveryOperatorService } from "../../src/dashboard/execution/TrustedDiscoveryOperatorService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
interface Input { root: string; witnessRoot: string; origin: string; organization: string; scanId: string; candidateId: string; security: ServerRuntimeSecurity; cookie: string; csrf: string }
async function send(value: unknown) { await new Promise<void>((done, reject) => { if (!process.send) { reject(Error("D0_PRIVATE_IPC_REQUIRED")); return; } process.send(value, (error) => error ? reject(error) : done()); }); }
process.once("message", async (input: Input) => {
  let database: DashboardDatabase | undefined, store: TrustedDiscoveryReviewStore | undefined, witness: TrustedDiscoveryWitness | undefined, service: TrustedDiscoveryOperatorService | undefined;
  try {
    const paths = resolveDashboardPaths(input.root); database = new DashboardDatabase(paths.databasePath); store = new TrustedDiscoveryReviewStore(database, join(input.root, "keys", "trusted-discovery-review.key")); witness = TrustedDiscoveryWitness.openFixture(database, store, input.witnessRoot, input.origin);
    const sessions = new ServerSessionManager(database, input.security); service = new TrustedDiscoveryOperatorService(database, paths, sessions, witness);
    const authority = () => { const q = new IncomingMessage(new Socket()); q.headers = { cookie: input.cookie, origin: input.security.publicOrigin, "x-forwarded-proto": "https", "content-type": "application/json" }; return sessions.captureTrustedDiscoverySession(q, input.csrf); };
    const { review } = await service.review({ scanId: input.scanId, candidateId: input.candidateId }, authority(), input.organization);
    await send({ ready: true, pid: process.pid }); await new Promise<void>((done) => process.once("message", () => done()));
    const result = await service.executeFresh({ ...review, confirmation: "I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET" }, authority(), input.organization);
    await send({ result });
  } catch (error) { process.exitCode = 1; const message = error instanceof Error ? error.message : "D0_NATIVE_FAILURE"; await send({ failure: /^[A-Z0-9_]+$/.test(message) ? message : "D0_NATIVE_FAILURE" }); }
  finally { try { await service?.shutdown(); if (!service) witness?.close(); } catch { process.exitCode = 1; await send({ failure: "D0_NATIVE_DISPOSAL_FAILED" }); } finally { store?.dispose(); database?.close(); process.disconnect?.(); } }
});
