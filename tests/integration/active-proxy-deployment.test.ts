import { afterAll, describe, expect, it } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createActiveProxyLab } from "../helpers/active-proxy-lab.js";
import { sendRawHttp1 } from "../../src/core/http/RawHttp1Transport.js";
import { runHttp2, runHttp2Desync, runHttp3Authorization, runHttp3Desync } from "../../src/modules/protocolSecurity/ProtocolTransports.js";

const enabled = Boolean(process.env.ROUTECAIRN_CADDY_BINARY && process.env.ROUTECAIRN_NGINX_BINARY);
describe.runIf(enabled)("real Caddy → nginx → application deployment", () => {
  it("verifies H1/H2/H3 ingress and records bounded framing cells with backend proof", async () => {
    const lab = await createActiveProxyLab(process.env.ROUTECAIRN_CADDY_BINARY!, process.env.ROUTECAIRN_NGINX_BINARY!); const cells: unknown[] = []; let cleanup = "FAILED";
    const options = { allowedPrivateOrigins: [lab.origin], timeoutMs: 4000, maxBytes: 65536, tlsCa: lab.ca };
    try {
      const control = randomBytes(16).toString("hex"); const headers = { "X-RouteCairn-Chain-Canary": control };
      expect((await lab.readProof(control)).hopIds).toEqual(lab.hopIds);
      const h2 = await runHttp2(`${lab.origin}/sentinel`, "GET", headers, undefined, 1, options); expect(h2.statusCode).toBe(200); expect(h2.protocol).toBe("h2"); expect(JSON.parse(h2.body.toString()).hopIds).toEqual(lab.hopIds);
      const h3 = await runHttp3Authorization(`${lab.origin}/sentinel`, "GET", headers, options); expect(h3.statusCode).toBe(200); expect(h3.protocol).toBe("h3"); expect(JSON.parse(h3.body.toString()).hopIds).toEqual(lab.hopIds);
      for (const framing of ["CL_TE", "TE_CL", "H2_LENGTH", "H3_LENGTH"] as const) {
        const canary = randomBytes(16).toString("hex"); const headers = { "X-RouteCairn-Chain-Canary": canary }; const before = await lab.readProof(canary); expect(before.violation).toBe(false); let accepted = false, clean = true, errorClass: string | undefined; let statuses: readonly number[] = [];
        try {
          if (framing === "CL_TE" || framing === "TE_CL") { const result = await sendRawHttp1({ url: `${lab.origin}/probe`, method: "POST", headers, body: "bounded-fixture", sentinelPath: "/sentinel", variant: framing, timeoutMs: 4000, maxResponseBytes: 65536, userAgent: "RouteCairn-active-proxy-lab", targetOrigin: lab.origin, tlsCa: lab.ca, dnsResolver: async () => [{ address: "127.0.0.1", family: 4 }], marker: canary }); statuses = result.statusCodes; accepted = statuses.includes(200); errorClass = result.error?.name; }
          else if (framing === "H2_LENGTH") { const result = await runHttp2Desync(`${lab.origin}/probe`, "POST", headers, Buffer.from("bounded-fixture"), 16, "/sentinel", options); statuses = [result.probe.statusCode ?? 0, result.sentinel.statusCode ?? 0]; accepted = result.probe.statusCode === 200; clean = result.sentinel.statusCode === 200; errorClass = result.sentinel.errorCode ?? result.probe.errorCode; }
          else { const result = await runHttp3Desync(`${lab.origin}/probe`, headers, Buffer.from("bounded-fixture"), 16, "/sentinel", [200], options); statuses = [result.probeStatus, result.sentinelStatus]; accepted = result.probeAccepted; clean = result.sentinelClean; }
        } catch (error) { errorClass = error instanceof Error ? error.name : "TransportError"; }
        const after = await lab.readProof(canary); const outcome = after.violation ? "PROVEN" : accepted || !clean || errorClass && errorClass !== "ERR_HTTP2_STREAM_ERROR" ? "INCONCLUSIVE" : "SECURE_FOR_CASE";
        cells.push({ framing, outcome, statuses, accepted, clean, ...(framing.startsWith("H") ? { actualBodyBytes: 15, declaredBodyBytes: 16 } : {}), ...(errorClass ? { errorClass } : {}), before: { violation: before.violation }, after: { violation: after.violation, probe: after.probe, sentinel: after.sentinel }, topologyVerified: true });
        expect(after.violation).toBe(false);
      }
    } finally { await lab.stop(); cleanup = "CONFIRMED"; }
    expect(cells).toHaveLength(4);
    if (process.env.ROUTECAIRN_ACTIVE_LAB_OUTPUT) { const directory = resolve(process.env.ROUTECAIRN_ACTIVE_LAB_OUTPUT); await mkdir(directory, { recursive: true }); const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), provenance: "SELF_MAINTAINED_LOOPBACK_REAL_PROXY_DEPLOYMENT", externalTargetsTested: false, independentlyOperated: false, deploymentSha256: lab.deploymentSha256, binaries: lab.binaries, hopIds: lab.hopIds, positiveProtocols: ["H1", "H2", "H3"], cleanup, cells }, null, 2)}\n`); await writeFile(resolve(directory, "proxy-deployment.json"), bytes); await writeFile(resolve(directory, "proxy-SHA256SUMS"), `${createHash("sha256").update(bytes).digest("hex")}  proxy-deployment.json\n`); }
  }, 60000);
});
