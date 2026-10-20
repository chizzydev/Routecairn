import { createServer, request as httpRequest, type Server } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { connect, type Socket } from "node:net";
import { generate } from "selfsigned";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { ProjectRepository, TargetRepository, ScanRepository, ArtifactRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { planAdaptiveDiscoveryCandidates } from "../../src/dashboard/execution/AdaptiveDiscoveryCandidatePlanner.js";
import { exampleScope } from "../../src/config/defaults.js";
import { controlPlaneConfigFromEnv } from "../../src/controlPlane/ControlPlaneConfig.js";

const ownedSockets = new WeakMap<Server, Set<Socket>>();
async function listen(server: Server) { const sockets = new Set<Socket>(); ownedSockets.set(server, sockets); server.on("connection", (socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); }); await new Promise<void>((done, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", done); }); const a = server.address(); if (!a || typeof a === "string") throw Error("D0_FIXTURE_BIND_FAILED"); return a.port; }
async function stop(server: Server) { for (const socket of ownedSockets.get(server) || []) socket.destroy(); server.closeAllConnections(); await new Promise<void>((done, reject) => server.close((error) => error ? reject(error) : done())); }

/** Disposable TLS gateway: actual browser cookie/Origin/CSRF, original server/UI.
 * No test callback, key/witness factory or execution route is exposed over HTTP. */
export async function browserFixture(options: { preview?: boolean; local?: boolean } = {}) {
  const infrastructure = controlPlaneConfigFromEnv();
  if (infrastructure.mode !== "local" || infrastructure.objectStorage.kind !== "local" || infrastructure.telemetry.otlpEndpoint) throw Error("D0_FIXTURE_REQUIRES_LOCAL_INFRASTRUCTURE");
  const root = realpathSync(mkdtempSync(join(tmpdir(), "rcd-browser-")));
  const data = join(root, "data"); mkdirSync(data, { mode: 0o700 }); mkdirSync(join(data, "reports"));
  const disposers: Array<() => Promise<void>> = [];
  try {
  let targetReceipts = 0, backend = "";
  const targetServer = createServer((_q, r) => { targetReceipts++; r.end("owned disposable target"); });
  const targetOrigin = `http://127.0.0.1:${await listen(targetServer)}`; disposers.push(() => stop(targetServer));
  const secondTargetServer = createServer((_q, r) => { targetReceipts++; r.end("second owned disposable target"); });
  const secondTargetOrigin = `http://127.0.0.1:${await listen(secondTargetServer)}`; disposers.push(() => stop(secondTargetServer));
  const certificate = await generate([{ name: "commonName", value: "127.0.0.1" }], { algorithm: "sha256" });
  const front = createTlsServer({ key: certificate.private, cert: certificate.cert }, (q, r) => {
    if (!backend) { r.writeHead(503).end(); return; }
    const outgoing = httpRequest(backend + (q.url || "/"), { method: q.method, agent: false, headers: { ...q.headers, "x-forwarded-proto": "https" }, timeout: 5000 }, (upstream) => { r.writeHead(upstream.statusCode || 503, upstream.headers); upstream.pipe(r); });
    outgoing.on("timeout", () => outgoing.destroy()); outgoing.on("error", () => { if (!r.headersSent) r.writeHead(503); r.end(); }); q.pipe(outgoing);
  });
  const tlsOrigin = `https://127.0.0.1:${await listen(front)}`; disposers.push(() => stop(front));
  const database = new DashboardDatabase(join(data, "routecairn-dashboard.sqlite")); database.migrate(); disposers.push(async () => { database.close(); });
  const security = { publicOrigin: tlsOrigin, sessionSecret: randomBytes(32).toString("hex"), trustProxy: true, developmentInsecureHttp: false };
  const sessions = new ServerSessionManager(database, security), password = "D0-Disposable!" + randomBytes(16).toString("hex"), login = "operator@d0.fixture.invalid";
  const owner = await sessions.createFirstOwner(login, password), organizations = new OrganizationService(database), org = organizations.defaultOrganizationId(), otherOrg = organizations.create({ name: "Second disposable organization", slug: "d0-second" }, owner);
  const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], allowedMethods: ["GET"] as ["GET"], disallowedPaths: [], sameOriginOnly: true, includeSubdomains: false, rateLimitPerSecond: 1, concurrency: 1, maxDepth: 0 };
  const project = new ProjectRepository(database).create({ organizationId: org, name: "Disposable", tags: [], defaultScope: scope });
  function retained(name: string, origin = targetOrigin) {
    const target = new TargetRepository(database).create({ organizationId: org, projectId: project, displayName: "Disposable", baseOrigin: origin, tags: [], classification: "LOCAL", authorizationType: "CONTROLLED_LAB", authorizationSummary: "Only this self-maintained anonymous loopback fixture is authorized", approvedScope: scope });
    const scan = randomUUID(), file = join(data, "reports", scan + ".json");
    new ScanRepository(database).create({ id: scan, organizationId: org, projectId: project, targetId: target, source: "DASHBOARD", status: "COMPLETED", targetOrigin: origin, safeTargetLabel: "disposable", profile: "quick", evidenceLevel: "minimal", safeConfigurationSummary: {} });
    const report = { routeCairnVersion: "0.1.0", target: origin, execution: { status: "COMPLETED", partial: false, cleanup: { state: "CLEAR", cases: [] } }, requestAudit: [], responses: [], apiMapper: { endpoints: [{ endpoint: origin + "/api/" + name, method: "GET", hasObjectId: false, authRelevance: "low", riskTags: [] }], graphQlEndpoints: [], notes: [] } };
    const bytes = JSON.stringify(report); writeFileSync(file, bytes, { mode: 0o600 });
    const artifact = new ArtifactRepository(database).create({ organizationId: org, scanId: scan, type: "JSON_REPORT", name: "fixture", path: file, size: Buffer.byteLength(bytes), contentType: "application/json", hash: "fixture-content", retentionState: "RETAIN" }); new ScanRepository(database).attachArtifacts(scan, { json: artifact });
    const worker = randomUUID(), stamp = new Date().toISOString(); database.db.prepare("INSERT INTO scan_workers(id,state,started_at,version) VALUES(?,'EXITED',?,'d0-fixture')").run(worker, stamp); database.db.prepare("INSERT INTO scan_job_leases(job_id,worker_id,acquired_at,expires_at,last_renewed_at,attempt_number,released_at,release_category) VALUES(?,?,?,?,?,1,?,'COMPLETED')").run(scan, worker, stamp, stamp, stamp, stamp);
    return { target, scan, candidate: planAdaptiveDiscoveryCandidates(report as never).candidates[0]!.candidateId, file, bytes };
  }
  const primary = retained("health"), secondary = retained("catalog", secondTargetOrigin);
  const priorMutation = process.env.ROUTECAIRN_MUTATION_DIR; process.env.ROUTECAIRN_MUTATION_DIR = join(root, "journals");
  let handle: Awaited<ReturnType<typeof startDashboardServer>>;
  try { handle = await startDashboardServer({ dataDir: data, uiDistDir: resolve("apps/dashboard-ui/dist"), host: "127.0.0.1", port: 0, mode: options.local ? "local" : "server", publicOrigin: security.publicOrigin, sessionSecret: security.sessionSecret, trustProxy: true, trustedDiscoveryPreviewOnly: options.preview ?? true }); }
  finally { if (priorMutation === undefined) delete process.env.ROUTECAIRN_MUTATION_DIR; else process.env.ROUTECAIRN_MUTATION_DIR = priorMutation; }
  backend = handle.url; disposers.push(() => handle.close());
  let closed = false;
  async function close() {
    if (closed) return; closed = true;
    let failed = false; for (const dispose of [...disposers].reverse()) { try { await dispose(); } catch { failed = true; } }
    if (failed) throw Error("D0_FIXTURE_DISPOSAL_FAILED");
    const absolute = resolve(root), rel = relative(resolve(tmpdir()), absolute);
    if (!rel || rel.startsWith(".." + sep) || !rel.startsWith("rcd-browser-")) throw Error("D0_FIXTURE_CLEANUP_SCOPE");
    rmSync(absolute, { recursive: true, force: false });
  }
  return { origin: options.local ? handle.url : tlsOrigin, bootstrapUrl: handle.bootstrapUrl, database, sessions, owner, org, otherOrg, login, password, security, primary, secondary, root, targetReceipts: () => targetReceipts, close };
  } catch (error) { for (const dispose of [...disposers].reverse()) { try { await dispose(); } catch { /* Preserve original startup failure and generated root. */ } } throw error; }
}

/** Browser egress proxy permits only currently owned UI origins. All other
 * CONNECT/HTTP requests are denied before DNS or an upstream connection. */
export async function restrictedBrowserProxy() {
  const allowed = new Set<string>(), sockets = new Set<Socket>(); let denied = 0, forwarded = 0, connectedPeers = 0, nonLoopbackTransmissions = 0;
  const proxy = createServer((q, r) => {
    let u: URL; try { u = new URL(q.url || ""); } catch { r.writeHead(403).end(); return; }
    if (!allowed.has(u.origin) || u.hostname !== "127.0.0.1" || u.protocol !== "http:" || u.username || u.password) { denied++; r.writeHead(403).end(); return; }
    forwarded++; const out = httpRequest(u, { method: q.method, headers: q.headers, timeout: 5000 }, (up) => { r.writeHead(up.statusCode || 503, up.headers); up.pipe(r); }); out.on("socket", (socket) => socket.once("connect", () => { connectedPeers++; if (socket.remoteAddress !== "127.0.0.1") { nonLoopbackTransmissions++; out.destroy(); } })); out.on("error", () => r.end()); out.on("timeout", () => out.destroy()); q.pipe(out);
  });
  proxy.on("connect", (q, socket, head) => {
    const authority = q.url || "";
    if (!/^127\.0\.0\.1:\d{1,5}$/.test(authority) || !allowed.has("https://" + authority)) { denied++; socket.end("HTTP/1.1 403 Forbidden\r\n\r\n"); return; }
    forwarded++; const upstream = connect({ host: "127.0.0.1", port: Number(authority.split(":")[1]) }); sockets.add(upstream); upstream.on("close", () => sockets.delete(upstream)); upstream.once("connect", () => { connectedPeers++; if (upstream.remoteAddress !== "127.0.0.1") { nonLoopbackTransmissions++; upstream.destroy(); socket.destroy(); return; } socket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); }); upstream.on("error", () => socket.destroy()); socket.on("error", () => upstream.destroy()); socket.on("close", () => upstream.destroy());
  });
  return { server: `http://127.0.0.1:${await listen(proxy)}`, allowed, stats: () => ({ denied, forwarded, connectedPeers, nonLoopbackTransmissions }), close: async () => { for (const socket of sockets) socket.destroy(); await stop(proxy); } };
}
