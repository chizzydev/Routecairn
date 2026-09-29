import { afterEach, describe, expect, it } from "vitest";
import { createServer, type AddressInfo } from "node:net";
import { createSocket } from "node:dgram";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { OastServiceConfig } from "../../src/oast/OastConfig.js";
import { OastService } from "../../src/oast/OastService.js";
import type { OastLeaseIdentity, OastPollResponse } from "../../src/oast/OastTypes.js";

const services: OastService[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(services.splice(0).map((service) => service.close()));
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("native OAST collaborator service", () => {
  it("isolates tenants and correlates HTTP callbacks without retaining request secrets", async () => {
    const { service, origin } = await startService();
    expect(await (await fetch(`${origin}/healthz`)).json()).toEqual({ status: "ok", mode: "SELF_HOSTED" });
    const request = { tenantId: "tenant-a", workerId: "worker-7", jobId: "job-9", caseId: "ssrf-1", ttlSeconds: 60, protocols: ["HTTP"] };
    const wrongTenant = await fetch(`${origin}/v1/leases`, { method: "POST", headers: { authorization: `Bearer ${"b".repeat(32)}`, "content-type": "application/json" }, body: JSON.stringify(request) });
    expect(wrongTenant.status).toBe(401);
    const created = await fetch(`${origin}/v1/leases`, { method: "POST", headers: { authorization: `Bearer ${"a".repeat(32)}`, "content-type": "application/json" }, body: JSON.stringify(request) });
    expect(created.status).toBe(201);
    expect(created.headers.get("cache-control")).toBe("no-store");
    const lease = await created.json() as OastLeaseIdentity;
    const first = await fetch(`${lease.httpUrl}?secret=do-not-retain`, { method: "POST", headers: { "x-private-value": "sensitive" }, body: "private-body-value" });
    const replay = await fetch(`${lease.httpUrl}?secret=changed-value`, { method: "POST", headers: { "x-private-value": "different" }, body: "private-body-value" });
    expect(first.status).toBe(202);
    expect(replay.status).toBe(409);
    const polled = await fetch(new URL(lease.pollUrl, origin), { headers: { authorization: `Bearer ${lease.pollToken}` } });
    const evidence = await polled.json() as OastPollResponse;
    expect(evidence.events).toHaveLength(1);
    expect(evidence.events[0]).toMatchObject({ protocol: "HTTP", replayRejected: true, bindingFingerprint: lease.bindingFingerprint });
    const serialized = JSON.stringify(evidence);
    for (const secret of ["tenant-a", "worker-7", "job-9", "ssrf-1", "do-not-retain", "private-body-value", "sensitive"]) expect(serialized).not.toContain(secret);
    expect(service).toBeDefined();
  });

  it("correlates a signed DNS callback and rejects a modified signature", async () => {
    const { origin, config } = await startService();
    const created = await fetch(`${origin}/v1/leases`, { method: "POST", headers: { authorization: `Bearer ${"a".repeat(32)}`, "content-type": "application/json" }, body: JSON.stringify({ tenantId: "tenant-a", workerId: "worker", jobId: "job", caseId: "xxe", ttlSeconds: 60, protocols: ["DNS"] }) });
    const lease = await created.json() as OastLeaseIdentity;
    const accepted = await dnsQuery(lease.dnsName, config.dnsUdpPort);
    expect(accepted.readUInt16BE(6)).toBe(1);
    const labels = lease.dnsName.split("."); labels[1] = "0".repeat(32);
    const rejected = await dnsQuery(labels.join("."), config.dnsUdpPort);
    expect(rejected.readUInt16BE(2) & 0x0f).toBe(3);
    const evidence = await (await fetch(new URL(lease.pollUrl, origin), { headers: { authorization: `Bearer ${lease.pollToken}` } })).json() as OastPollResponse;
    expect(evidence.events).toHaveLength(1);
    expect(evidence.events[0]?.protocol).toBe("DNS");
  });
});

async function startService(): Promise<{ service: OastService; origin: string; config: OastServiceConfig }> {
  const [httpPort, udpPort, tcpPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const directory = await mkdtemp(join(tmpdir(), "routecairn-oast-service-")); directories.push(directory);
  const config: OastServiceConfig = { schemaVersion: 1, mode: "SELF_HOSTED", listenHost: "127.0.0.1", httpPort, dnsUdpPort: udpPort, dnsTcpPort: tcpPort, baseDomain: "oast.example.test", databasePath: join(directory, "oast.sqlite"), signingKeyEnv: "UNUSED", tenantTokensEnv: "UNUSED", maxLeaseSeconds: 300, maxEventsPerLease: 5, maxRequestBytes: 8192, dnsAnswerIpv4: "127.0.0.1", dnsAnswerIpv6: "::1" };
  const service = new OastService(config, { signingKey: Buffer.from("s".repeat(32)), tenantTokens: new Map([["tenant-a", "a".repeat(32)], ["tenant-b", "b".repeat(32)]]) });
  await service.start(); services.push(service);
  return { service, origin: `http://127.0.0.1:${httpPort}`, config };
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => { const server = createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const port = (server.address() as AddressInfo).port; server.close((error) => error ? reject(error) : resolve(port)); }); });
}

function dnsQuery(name: string, port: number): Promise<Buffer> {
  const id = Buffer.from([0x42, 0x42]); const flagsAndCounts = Buffer.from([0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
  const labels = Buffer.concat(name.split(".").flatMap((label) => [Buffer.from([label.length]), Buffer.from(label)]));
  const packet = Buffer.concat([id, flagsAndCounts, labels, Buffer.from([0, 0, 1, 0, 1])]);
  return new Promise((resolve, reject) => { const socket = createSocket("udp4"); const timer = setTimeout(() => { socket.close(); reject(new Error("DNS timeout")); }, 3000); socket.once("error", reject); socket.once("message", (message) => { clearTimeout(timer); socket.close(); resolve(message); }); socket.send(packet, port, "127.0.0.1"); });
}
