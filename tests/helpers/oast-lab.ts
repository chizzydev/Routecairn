import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer, connect, type AddressInfo } from "node:net";
import { createSocket } from "node:dgram";
import { generate } from "selfsigned";
import { randomBytes } from "node:crypto";
import { OastService } from "../../src/oast/OastService.js";
import { oastServiceConfigSchema } from "../../src/oast/OastConfig.js";
import { runBoundedHttp } from "../../src/modules/protocolSecurity/ProtocolTransports.js";
import { oastDnsQuestion } from "../../src/oast/OastDns.js";

export async function freeOastPort() { const server = createServer(); await new Promise<void>((done) => server.listen(0, "127.0.0.1", done)); const port = (server.address() as AddressInfo).port; await new Promise<void>((done) => server.close(() => done())); return port; }
export async function createOastLab(overrides: Record<string, unknown> = {}) {
  const directory = await mkdtemp(join(tmpdir(), "routecairn-oast-lab-"));
  const cert = await generate([{ name: "commonName", value: "127.0.0.1" }], { keySize: 2048, days: 1, extensions: [{ name: "basicConstraints", cA: true }, { name: "keyUsage", keyCertSign: true, digitalSignature: true, keyEncipherment: true }, { name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] }] });
  const keyPath = join(directory, "tls.key"), caPath = join(directory, "tls.pem"); await writeFile(keyPath, cert.private, { mode: 0o600 }); await writeFile(caPath, cert.cert);
  const httpPort = await freeOastPort(), httpsPort = await freeOastPort(), dnsPort = await freeOastPort();
  const httpOrigin = `http://127.0.0.1:${httpPort}`, httpsOrigin = `https://127.0.0.1:${httpsPort}`;
  const config = oastServiceConfigSchema.parse({ mode: "HOSTED", listenHost: "127.0.0.1", httpPort, httpsPort, dnsUdpPort: dnsPort, dnsTcpPort: dnsPort, baseDomain: "callbacks.example.test", publicHttpBaseUrl: httpOrigin, publicHttpsBaseUrl: httpsOrigin, databasePath: join(directory, "oast.sqlite"), tlsKeyPath: keyPath, tlsCertPath: caPath, maxLeaseSeconds: 300, publishIpv6: true, ...overrides });
  const token = randomBytes(32).toString("base64url"), tenantId = "owned-lab-tenant";
  const secrets = { signingKey: randomBytes(32), tenantTokens: new Map([[tenantId, token], ["other-tenant", randomBytes(32).toString("base64url")]]) };
  let service = new OastService(config, secrets);
  try { await service.start(); } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
  const call = (url: string, method = "GET", bearer?: string, body?: unknown, ca = cert.cert) => runBoundedHttp(url, method, { ...(bearer ? { authorization: `Bearer ${bearer}` } : {}), ...(body ? { "content-type": "application/json" } : {}) }, body ? Buffer.from(JSON.stringify(body)) : undefined, { allowedPrivateOrigins: [httpOrigin, httpsOrigin], timeoutMs: 3000, maxBytes: 65536, tlsCa: ca });
  return { directory, caPath, ca: cert.cert, config, token, tenantId, httpOrigin, httpsOrigin, dnsPort, call, get service() { return service; }, async restart() { await service.close(); service = new OastService(config, secrets); await service.start(); }, async stop() { await service.close(); await rm(directory, { recursive: true, force: true }); } };
}

export function queryOastDns(name: string, port: number, tcp = false, type = 1): Promise<Buffer> {
  const question = oastDnsQuestion(name, type, randomBytes(2).readUInt16BE());
  return new Promise((done, reject) => {
    const socket = tcp ? connect(port, "127.0.0.1") : createSocket("udp4");
    const finish = (error?: Error, response?: Buffer) => { clearTimeout(timer); if (tcp) (socket as ReturnType<typeof connect>).destroy(); else (socket as ReturnType<typeof createSocket>).close(); if (error) reject(error); else done(response!); };
    const timer = setTimeout(() => finish(new Error("OAST_TEST_DNS_TIMEOUT")), 3000);
    socket.once("error", (error) => finish(error));
    if (tcp) { let bytes = Buffer.alloc(0); socket.on("data", (chunk: Buffer) => { bytes = Buffer.concat([bytes, chunk]); if (bytes.length >= 2 && bytes.length >= bytes.readUInt16BE(0) + 2) finish(undefined, bytes.subarray(2, bytes.readUInt16BE(0) + 2)); }); const prefix = Buffer.alloc(2); prefix.writeUInt16BE(question.length); (socket as ReturnType<typeof connect>).once("connect", () => (socket as ReturnType<typeof connect>).write(Buffer.concat([prefix, question]))); }
    else { (socket as ReturnType<typeof createSocket>).once("message", (response) => finish(undefined, response)); (socket as ReturnType<typeof createSocket>).send(question, port, "127.0.0.1"); }
  });
}
