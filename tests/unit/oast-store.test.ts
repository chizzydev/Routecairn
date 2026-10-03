import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { OastStore } from "../../src/oast/OastStore.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("OAST lease store", () => {
  it("bounds retained leases, preserves delayed evidence after expiry and rejects silent key changes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-oast-retention-")); directories.push(directory); const path = join(directory, "oast.sqlite"); let clock = Date.now(); const key = Buffer.from("s".repeat(32));
    const open = () => new OastStore(path, key, "oast.example.test", undefined, undefined, 300, 3, () => clock, { maxLeases: 1, evidenceRetentionSeconds: 60 });
    let store = open(); const request = { tenantId: "tenant", workerId: "worker", jobId: "job", caseId: "case", ttlSeconds: 30, protocols: ["DNS"] as const }; const lease = store.createLease(request);
    expect(() => store.createLease(request)).toThrow("OAST_LEASE_LIMIT"); store.close(); store = open(); expect(store.poll(lease.leaseId, lease.pollToken)?.status).toBe("ACTIVE");
    clock += 31000; expect(store.prune()).toBe(0); expect(store.poll(lease.leaseId, lease.pollToken)?.status).toBe("EXPIRED"); clock += 60000; expect(store.prune()).toBe(1); expect(store.poll(lease.leaseId, lease.pollToken)).toBeUndefined(); store.createLease(request); store.close();
    expect(() => new OastStore(path, Buffer.from("different-key-that-has-32-bytes!!"), "oast.example.test", undefined, undefined, 300, 3)).toThrow("OAST_SIGNING_KEY_CHANGED");
  });
  it("binds signed identities, rejects replays, expires leases, and exposes only fingerprints", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-oast-store-")); directories.push(directory);
    let clock = Date.parse("2026-01-01T00:00:00.000Z");
    const store = new OastStore(join(directory, "oast.sqlite"), Buffer.from("s".repeat(32)), "oast.example.test", "http://oast.example.test/", "https://oast.example.test/", 300, 4, () => clock);
    const lease = store.createLease({ tenantId: "tenant-a", workerId: "worker-1", jobId: "job-1", caseId: "case-1", ttlSeconds: 60, protocols: ["DNS", "HTTP"] });
    const signature = lease.dnsName.split(".")[1]!;
    const httpSignature = new URL(lease.httpUrl!).pathname.split("/").at(-1)!;
    const httpsSignature = new URL(lease.httpsUrl!).pathname.split("/").at(-1)!;
    expect(new Set([signature, httpSignature, httpsSignature]).size).toBe(3);
    const second = store.createLease({ tenantId: "tenant-a", workerId: "worker-1", jobId: "job-1", caseId: "case-2", ttlSeconds: 60, protocols: ["DNS"] });
    expect(second.leaseId).not.toBe(lease.leaseId);
    expect(second.dnsName).not.toBe(lease.dnsName);
    const row = store.validateIdentity(lease.leaseId, httpSignature, "HTTP");
    expect(row).toBeDefined();
    expect(store.validateIdentity(lease.leaseId, "0".repeat(32), "HTTP")).toBeUndefined();
    expect(store.validateIdentity(lease.leaseId, signature, "HTTP")).toBeUndefined();
    expect(store.validateIdentity(lease.leaseId, httpsSignature, "HTTPS")).toBeUndefined();

    expect(store.record(row!, "HTTP", "198.51.100.10", "GET\0/c/id/sig\0\0accept\u00000\0empty")).toEqual({ accepted: true, replay: false });
    expect(store.record(row!, "HTTP", "198.51.100.10", "GET\0/c/id/sig\0\0accept\u00000\0empty")).toEqual({ accepted: false, replay: true });
    expect(store.record(row!, "HTTP", "198.51.100.11", "POST\0/c/id/sig\0q\0content-type\u00008\0different")).toEqual({ accepted: false, replay: true });
    const polled = store.poll(lease.leaseId, lease.pollToken)!;
    expect(polled.events).toHaveLength(1);
    expect(polled.events[0]).toMatchObject({ protocol: "HTTP", replayRejected: true, bindingFingerprint: lease.bindingFingerprint });
    expect(JSON.stringify(polled)).not.toContain("tenant-a");
    expect(JSON.stringify(polled)).not.toContain("198.51.100.10");
    expect(store.poll(lease.leaseId, "wrong-token-that-is-long-enough")).toBeUndefined();

    clock += 61_000;
    expect(store.validateIdentity(lease.leaseId, httpSignature, "HTTP")).toBeUndefined();
    expect(store.poll(lease.leaseId, lease.pollToken)?.status).toBe("EXPIRED");
    store.close();
  });

  it("revokes a lease through its unguessable polling token", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-oast-revoke-")); directories.push(directory);
    const store = new OastStore(join(directory, "oast.sqlite"), Buffer.from("k".repeat(32)), "oast.example.test", undefined, undefined, 300, 2);
    const lease = store.createLease({ tenantId: "tenant", workerId: "worker", jobId: "job", caseId: "case", ttlSeconds: 60, protocols: ["DNS"] });
    expect(store.revoke(lease.leaseId, "invalid")).toBe(false);
    expect(store.revoke(lease.leaseId, lease.pollToken)).toBe(true);
    expect(store.poll(lease.leaseId, lease.pollToken)?.status).toBe("REVOKED");
    expect(store.validateIdentity(lease.leaseId, lease.dnsName.split(".")[1]!, "DNS")).toBeUndefined();
    store.close();
  });
});
