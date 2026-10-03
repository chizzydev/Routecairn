import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connect } from "node:net";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { OastClient } from "../../src/oast/OastClient.js";
import { exchangeOastDns } from "../../src/oast/OastDnsTransport.js";
import { createOastLab, queryOastDns } from "../helpers/oast-lab.js";
import type { OastLeaseIdentity } from "../../src/oast/OastTypes.js";

let lab: Awaited<ReturnType<typeof createOastLab>>;
const verified: string[] = [];
beforeAll(async () => { lab = await createOastLab(); }, 15000);
afterAll(async () => {
  if (lab) await lab.stop(); delete process.env.RC_OAST_HOSTED_TOKEN; delete process.env.RC_OAST_HOSTED_CA;
  if (process.env.ROUTECAIRN_OAST_LAB_OUTPUT) { const output = resolve(process.env.ROUTECAIRN_OAST_LAB_OUTPUT); await mkdir(output, { recursive: true }); await writeFile(join(output, "hosted-service-proof.json"), `${JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), provenance: "OWNER_OPERATED_HOSTED_MODE_LOOPBACK", publicDeploymentVerified: false, externalTargetsTested: false, independentlyOperated: false, cleanup: "CONFIRMED", checks: verified }, null, 2)}\n`); }
});
async function lease(protocols: string[] = ["DNS", "HTTP", "HTTPS"]) { const response = await lab.call(`${lab.httpsOrigin}/v1/leases`, "POST", lab.token, { tenantId: lab.tenantId, workerId: "worker", jobId: "job", caseId: "case", ttlSeconds: 60, protocols }); expect(response.statusCode).toBe(201); return JSON.parse(response.body.toString()) as OastLeaseIdentity; }

describe("hosted mode over real verified TLS and authoritative DNS", () => {
  it("requires HTTPS management, isolates tenants and verifies certificate trust", async () => {
    expect((await lab.call(`${lab.httpOrigin}/v1/leases`, "POST", lab.token, {})).statusCode).toBe(426);
    expect((await lab.call(`${lab.httpsOrigin}/v1/leases`, "POST", lab.token, { tenantId: "other-tenant", workerId: "worker", jobId: "job", caseId: "case", ttlSeconds: 60, protocols: ["HTTPS"] })).statusCode).toBe(401);
    await expect(lab.call(`${lab.httpsOrigin}/healthz`, "GET", undefined, undefined, "untrusted CA")).rejects.toThrow();
    expect((await lab.call(`${lab.httpsOrigin}/readyz`)).statusCode).toBe(200);
    verified.push("https-only-management-tenant-isolation-and-certificate-verification");
  });
  it("accepts signed HTTPS callbacks, rejects protocol confusion and replays, preserves evidence across restart", async () => {
    const identity = await lease();
    expect((await lab.call(identity.httpsUrl!)).statusCode).toBe(202);
    expect((await lab.call(identity.httpsUrl!)).statusCode).toBe(409);
    expect((await lab.call(identity.httpsUrl!.replace(lab.httpsOrigin, lab.httpOrigin))).statusCode).toBe(404);
    await lab.restart();
    const evidence = JSON.parse((await lab.call(`${lab.httpsOrigin}${identity.pollUrl}`, "GET", identity.pollToken)).body.toString());
    expect(evidence.events).toHaveLength(1); expect(evidence.events[0]).toMatchObject({ protocol: "HTTPS", replayRejected: true, bindingFingerprint: identity.bindingFingerprint });
    expect((await lab.call(`${lab.httpsOrigin}${identity.pollUrl}`, "GET", lab.token)).statusCode).toBe(401);
    expect((await lab.call(`${lab.httpsOrigin}${identity.pollUrl}`, "DELETE", identity.pollToken)).statusCode).toBe(204);
    expect((await lab.call(identity.httpsUrl!)).statusCode).toBe(404);
    for (const secret of [identity.pollToken, lab.token, lab.tenantId]) expect(JSON.stringify(evidence)).not.toContain(secret);
    verified.push("https-signatures-replay-persistence-revocation-and-redaction");
  });
  it("serves AA SOA/NS/glue, NODATA, NXDOMAIN and refuses recursion over UDP and TCP", async () => {
    for (const tcp of [false, true]) {
      expect(await exchangeOastDns(lab.config.baseDomain, "127.0.0.1", lab.dnsPort, tcp, 2)).toMatchObject({ authoritative: true, recursionAvailable: false, truncated: false, rcode: 0, nameservers: [`ns1.${lab.config.baseDomain}`] });
      for (const type of [2, 6]) { const response = await queryOastDns(lab.config.baseDomain, lab.dnsPort, tcp, type); expect(response.readUInt16BE(2) & 0x048f).toBe(0x0400); expect(response.readUInt16BE(6)).toBe(1); if (type === 2) expect(response.readUInt16BE(10)).toBe(2); }
      const nodata = await queryOastDns(lab.config.baseDomain, lab.dnsPort, tcp, 15); expect(nodata.readUInt16BE(2) & 15).toBe(0); expect(nodata.readUInt16BE(8)).toBe(1);
      const missing = await queryOastDns(`missing.${lab.config.baseDomain}`, lab.dnsPort, tcp); expect(missing.readUInt16BE(2) & 15).toBe(3); expect(missing.readUInt16BE(8)).toBe(1);
      const outside = await queryOastDns("unrelated.example.test", lab.dnsPort, tcp); expect(outside.readUInt16BE(2) & 0x048f).toBe(5); expect(outside.readUInt16BE(8)).toBe(0);
    }
    verified.push("authoritative-soa-ns-glue-nodata-nxdomain-and-no-recursion-udp-tcp");
  });
  it("correlates UDP and TCP callback retries once and revokes DNS identities", async () => {
    const identity = await lease(["DNS"]);
    for (const tcp of [false, true]) for (const type of [1, 28]) { const response = await queryOastDns(identity.dnsName, lab.dnsPort, tcp, type); expect(response.readUInt16BE(6)).toBe(1); expect(response.readUInt16BE(2) & 0x048f).toBe(0x0400); }
    const evidence = JSON.parse((await lab.call(`${lab.httpsOrigin}${identity.pollUrl}`, "GET", identity.pollToken)).body.toString());
    expect(evidence.events).toHaveLength(1); expect(evidence.events[0]).toMatchObject({ protocol: "DNS", replayRejected: true });
    await lab.call(`${lab.httpsOrigin}${identity.pollUrl}`, "DELETE", identity.pollToken);
    expect((await queryOastDns(identity.dnsName, lab.dnsPort)).readUInt16BE(2) & 15).toBe(3);
    verified.push("dns-udp-tcp-a-aaaa-correlation-replay-and-revocation");
  });
  it("uses the native client against HTTPS with a private CA without disabling TLS validation", async () => {
    process.env.RC_OAST_HOSTED_TOKEN = lab.token; process.env.RC_OAST_HOSTED_CA = lab.ca;
    const client = new OastClient({ mode: "SELF_HOSTED", apiBaseUrl: lab.httpsOrigin, apiTokenEnv: "RC_OAST_HOSTED_TOKEN", tlsCaEnv: "RC_OAST_HOSTED_CA", tenantId: lab.tenantId, workerId: "worker", jobId: "job", leaseSeconds: 60, pollIntervalMs: 100, maxPolls: 3, protocols: ["HTTPS"] }, 3000);
    const identity = await client.lease("case", "strategy"); await lab.call(identity.httpsUrl!); expect((await client.waitForEvent(identity, "HTTPS"))?.protocol).toBe("HTTPS"); expect(await client.revoke(identity)).toBe(true);
    await lab.service.reloadTls();
    verified.push("native-client-private-ca-https-polling-revocation-and-tls-reload");
  });
  it("closes stalled DNS connections promptly and supports idempotent shutdown", async () => {
    const stalled = connect(lab.dnsPort, "127.0.0.1"); stalled.on("error", () => undefined); await new Promise<void>((done) => stalled.once("connect", done)); stalled.write(Buffer.from([0, 50]));
    const started = Date.now(); await lab.service.close(); await lab.service.close(); expect(Date.now() - started).toBeLessThan(2000); stalled.destroy();
    verified.push("bounded-stalled-connection-shutdown-and-idempotence");
  });
  it("bounds lease and body capacity and revokes a lease even after scan cancellation", async () => {
    const bounded = await createOastLab({ maxLeases: 1, maxRequestBytes: 1024 });
    process.env.RC_OAST_HOSTED_TOKEN = bounded.token; process.env.RC_OAST_HOSTED_CA = bounded.ca;
    try {
      const controller = new AbortController(); const client = new OastClient({ mode: "SELF_HOSTED", apiBaseUrl: bounded.httpsOrigin, apiTokenEnv: "RC_OAST_HOSTED_TOKEN", tlsCaEnv: "RC_OAST_HOSTED_CA", tenantId: bounded.tenantId, workerId: "worker", jobId: "job", leaseSeconds: 60, pollIntervalMs: 100, maxPolls: 3, protocols: ["HTTPS"] }, 3000, controller.signal);
      const identity = await client.lease("case", "strategy"); await expect(client.lease("another", "strategy")).rejects.toThrow("OAST_LEASE_HTTP_429");
      expect((await bounded.call(identity.httpsUrl!, "POST", undefined, { padding: "x".repeat(2048) })).statusCode).toBe(413);
      controller.abort(); expect(await client.revoke(identity)).toBe(true); expect((await bounded.call(identity.httpsUrl!)).statusCode).toBe(404);
    } finally { await bounded.stop(); }
    verified.push("lease-body-capacity-and-revocation-after-scan-cancellation");
  });
});
