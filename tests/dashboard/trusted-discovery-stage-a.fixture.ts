import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import {
  ScanRepository,
  TargetRepository,
  ProjectRepository,
  ArtifactRepository,
} from "../../src/dashboard/db/DashboardRepositories.js";
import { planAdaptiveDiscoveryCandidates } from "../../src/dashboard/execution/AdaptiveDiscoveryCandidatePlanner.js";
import { exampleScope } from "../../src/config/defaults.js";

export async function stageAFixture(
  options: { preview?: boolean; local?: boolean; targetHost?: "127.0.0.1" | "::1" } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "rcg-stagea-"));
  const targetServer = createServer((_q, r) => {
    wire++;
    r.end("owned disposable loopback");
  });
  let wire = 0;
  const targetHost = options.targetHost ?? "127.0.0.1";
  await new Promise<void>((done) => targetServer.listen(0, targetHost, done));
  const address = targetServer.address();
  if (!address || typeof address === "string") throw Error("FIXTURE_LISTEN");
  const targetOrigin = `http://${targetHost === "::1" ? "[::1]" : targetHost}:${address.port}`;
  const dbPath = join(root, "routecairn-dashboard.sqlite");
  const db = new DashboardDatabase(dbPath);
  db.migrate();
  const security = {
    publicOrigin: "https://dashboard.fixture.test",
    sessionSecret: "owned-loopback-stage-a-session-secret-2026",
    trustProxy: true,
    developmentInsecureHttp: false,
  };
  const sessions = new ServerSessionManager(db, security);
  const password = "Owned-Fixture-Only-Password-2026!";
  const owner = await sessions.createFirstOwner("owner@fixture.test", password);
  const org = new OrganizationService(db).defaultOrganizationId();
  const otherOrg = new OrganizationService(db).create({ name: "Other", slug: "other" }, owner);
  mkdirSync(join(root, "reports"), { recursive: true });
  const scope = {
    ...exampleScope,
    allowedDomains: [new URL(targetOrigin).hostname],
    allowedMethods: ["GET"] as ["GET"],
    disallowedPaths: [],
    sameOriginOnly: true,
    includeSubdomains: false,
    rateLimitPerSecond: 1,
    concurrency: 1,
    maxDepth: 0,
  };
  const project = new ProjectRepository(db).create({
    organizationId: org,
    name: "Owned",
    tags: [],
    defaultScope: scope,
  });
  const target = new TargetRepository(db).create({
    organizationId: org,
    projectId: project,
    displayName: "Owned",
    baseOrigin: targetOrigin,
    tags: [],
    classification: "LOCAL",
    authorizationType: "CONTROLLED_LAB",
    authorizationSummary: "Owner approves only disposable anonymous loopback GET",
    approvedScope: scope,
  });
  const handle = await startDashboardServer({
    dataDir: root,
    host: "127.0.0.1",
    mode: options.local ? "local" : "server",
    publicOrigin: security.publicOrigin,
    sessionSecret: security.sessionSecret,
    trustProxy: true,
    ...(options.preview === undefined ? {} : { trustedDiscoveryPreviewOnly: options.preview }),
    uiDistDir: join(root, "ui"),
  } as Parameters<typeof startDashboardServer>[0]);
  let auth: { cookie: string; csrf: string };
  async function login(login = "owner@fixture.test") {
    const response = await fetch(handle.url + "/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json", origin: security.publicOrigin, "x-forwarded-proto": "https" },
      body: JSON.stringify({ login, password }),
    });
    if (response.status !== 200) throw Error("FIXTURE_LOGIN");
    const body = (await response.json()) as { csrfToken: string };
    return { cookie: response.headers.get("set-cookie")!.split(";")[0]!, csrf: body.csrfToken };
  }
  if (options.local) {
    const token = new URL(handle.bootstrapUrl!).hash.slice("#bootstrap=".length);
    const r = await fetch(handle.url + "/api/session/bootstrap", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    auth = {
      cookie: r.headers.get("set-cookie")!.split(";")[0]!,
      csrf: ((await r.json()) as { csrfToken: string }).csrfToken,
    };
  } else auth = await login();
  function source(route = "/api/health") {
    const scan = randomUUID(),
      file = join(root, "reports", `${scan}.json`);
    new ScanRepository(db).create({
      id: scan,
      organizationId: org,
      projectId: project,
      targetId: target,
      source: "DASHBOARD",
      status: "COMPLETED",
      targetOrigin,
      safeTargetLabel: "fixture",
      profile: "quick",
      evidenceLevel: "minimal",
      safeConfigurationSummary: {},
    });
    const report: any = {
      routeCairnVersion: "0.1.0",
      target: targetOrigin,
      execution: { status: "COMPLETED", partial: false, cleanup: { state: "CLEAR", cases: [] } },
      requestAudit: [],
      responses: [],
      apiMapper: {
        endpoints: [
          { endpoint: targetOrigin + route, method: "GET", hasObjectId: false, authRelevance: "low", riskTags: [] },
        ],
        graphQlEndpoints: [],
        notes: [],
      },
    };
    const bytes = JSON.stringify(report);
    writeFileSync(file, bytes);
    const artifact = new ArtifactRepository(db).create({
      organizationId: org,
      scanId: scan,
      type: "JSON_REPORT",
      name: "source",
      path: file,
      size: Buffer.byteLength(bytes),
      contentType: "application/json",
      hash: "not-full-file-digest",
      retentionState: "RETAIN",
    });
    new ScanRepository(db).attachArtifacts(scan, { json: artifact });
    const candidateId = planAdaptiveDiscoveryCandidates(report).candidates[0]!.candidateId;
    return { scanId: scan, candidateId, file, artifact, bytes, report };
  }
  async function post(path: string, body: unknown, headers: Record<string, string> = {}, identity = auth) {
    return fetch(handle.url + path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: identity.cookie,
        origin: options.local ? handle.url : security.publicOrigin,
        "x-csrf-token": identity.csrf,
        "x-routecairn-organization-id": org,
        ...headers,
      },
      body: JSON.stringify(body),
    });
  }
  const initial = source();
  const worker = randomUUID(),
    stamp = new Date().toISOString();
  db.db
    .prepare("INSERT INTO scan_workers(id,state,started_at,version) VALUES(?,'EXITED',?,'owned-fixture')")
    .run(worker, stamp);
  db.db
    .prepare(
      "INSERT INTO scan_job_leases(job_id,worker_id,acquired_at,expires_at,last_renewed_at,attempt_number,released_at,release_category) VALUES(?,?,?,?,?,1,?,'COMPLETED')",
    )
    .run(initial.scanId, worker, stamp, stamp, stamp, stamp);
  let stopped = false;
  async function stop() {
    if (!stopped) {
      stopped = true;
      await handle.close();
    }
  }
  async function close() {
    await stop();
    db.close();
    await new Promise<void>((done) => targetServer.close(() => done()));
    const absolute = resolve(root);
    if (!absolute.startsWith(resolve(tmpdir()) + sep) || !absolute.includes("rcg-stagea-"))
      throw Error("FIXTURE_CLEANUP_SCOPE");
    rmSync(absolute, { recursive: true, force: true });
  }
  return {
    root,
    db,
    dbPath,
    handle,
    sessions,
    security,
    password,
    owner,
    org,
    otherOrg,
    project,
    target,
    targetOrigin,
    scope,
    auth,
    login,
    source,
    initial,
    post,
    stop,
    close,
    wire: () => wire,
  };
}
export type StageAFixture = Awaited<ReturnType<typeof stageAFixture>>;
export const consentFor = (review: Record<string, unknown>) => ({
  ...review,
  confirmation: "I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET",
});
