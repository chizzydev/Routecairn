import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DistributedMutationCoordinatorClient } from "../../src/core/offensive/DistributedMutationCoordinator.js";
import { GlobalMutationLock, MutationJournal } from "../../src/core/offensive/MutationJournal.js";
import { startDashboardServer, type DashboardServerHandle } from "../../src/dashboard/server/DashboardServer.js";

let server: DashboardServerHandle | undefined;
afterEach(async () => { await server?.close(); server = undefined; });

describe("distributed controlled-mutation coordination", () => {
  it("serializes independent hosts and propagates cleanup obligations through recovery", async () => {
    const root = await mkdtemp(join(tmpdir(), "routecairn-distributed-mutation-"));
    const secret = "distributed-coordinator-acceptance-secret-0123456789";
    server = await startDashboardServer({ host: "127.0.0.1", port: 0, dataDir: join(root, "control-plane"), mutationCoordinatorSecret: secret });
    const dashboard = await bootstrap(server.url, server.bootstrapUrl!);
    const namespace = "acceptance-staging";
    const hostA = join(root, "host-a"); const hostB = join(root, "host-b");
    const clientA = new DistributedMutationCoordinatorClient({ endpoint: server.url, namespace, sharedSecret: secret, clientId: "acceptance-host-a" });
    const clientB = new DistributedMutationCoordinatorClient({ endpoint: server.url, namespace, sharedSecret: secret, clientId: "acceptance-host-b" });

    const first = new GlobalMutationLock(join(hostA, "global-mutation.lock"), { coordinator: clientA });
    const contender = new GlobalMutationLock(join(hostB, "global-mutation.lock"), { coordinator: clientB });
    await first.acquire("case-a");
    const status = await apiGet<{ activeLease: { caseId: string; stale: boolean } | null }>(server.url, `/api/operations/mutation-coordination?namespace=${namespace}`, dashboard.cookie);
    expect(status.activeLease).toMatchObject({ caseId: "case-a", stale: false });
    const prematureOrphan = await fetch(`${server.url}/api/operations/mutation-coordination/orphan`, { method: "POST", headers: { cookie: dashboard.cookie, "x-csrf-token": dashboard.csrf, "content-type": "application/json", origin: server.url }, body: JSON.stringify({ namespace, confirmation: "MARK_STALE_LEASE_STATE_UNCERTAIN" }) });
    expect(prematureOrphan.status).toBe(409);
    await expect(contender.acquire("case-b")).rejects.toThrow("MUTATION_LOCK_HELD");
    await first.release();

    await contender.acquire("case-b");
    await new MutationJournal(join(hostB, "mutation-journal.json")).append({ caseId: "case-b", stage: "CLEANUP_FAILED", mode: "CONTROLLED_MUTATION", targetOrigin: "https://fixture.example.test", targetIdentityFingerprint: "fixture" });
    await contender.release();

    const blocked = new GlobalMutationLock(join(hostA, "global-mutation.lock"), { coordinator: clientA });
    await expect(blocked.acquire("case-c")).rejects.toThrow("UNRESOLVED_PRIOR_CLEANUP");

    const recovery = new GlobalMutationLock(join(hostB, "global-mutation.lock"), { coordinator: clientB });
    await recovery.acquire("case-b", true);
    await new MutationJournal(join(hostB, "mutation-journal.json")).append({ caseId: "case-b", stage: "ROLLBACK_VERIFIED", mode: "CONTROLLED_MUTATION", targetOrigin: "https://fixture.example.test", targetIdentityFingerprint: "fixture", outcome: "ROLLBACK_VERIFIED" });
    await recovery.release();

    const final = new GlobalMutationLock(join(hostA, "global-mutation.lock"), { coordinator: clientA });
    await final.acquire("case-c"); await final.release();
  }, 60_000);

  it("rejects unsigned or incorrectly signed coordinator clients", async () => {
    const root = await mkdtemp(join(tmpdir(), "routecairn-distributed-mutation-auth-"));
    server = await startDashboardServer({ host: "127.0.0.1", port: 0, dataDir: join(root, "control-plane"), mutationCoordinatorSecret: "correct-coordinator-secret-01234567890123456789" });
    const client = new DistributedMutationCoordinatorClient({ endpoint: server.url, namespace: "auth-test", sharedSecret: "incorrect-coordinator-secret-0123456789012345", clientId: "untrusted-host" });
    const lock = new GlobalMutationLock(join(root, "untrusted", "global-mutation.lock"), { coordinator: client });
    await expect(lock.acquire("case-auth")).rejects.toThrow("MUTATION_COORDINATOR_SIGNATURE_REJECTED");
  }, 30_000);
});

async function bootstrap(baseUrl: string, bootstrapUrl: string): Promise<{ cookie: string; csrf: string }> { const token=new URL(bootstrapUrl).hash.replace("#bootstrap=","");const response=await fetch(`${baseUrl}/api/session/bootstrap`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({token})});const body=await response.json() as {csrfToken:string};return{cookie:response.headers.get("set-cookie")?.split(";")[0]??"",csrf:body.csrfToken}; }
async function apiGet<T>(baseUrl:string,path:string,cookie:string):Promise<T>{const response=await fetch(`${baseUrl}${path}`,{headers:{cookie}});if(!response.ok)throw new Error(`${path}:${response.status}:${await response.text()}`);return response.json() as Promise<T>;}
