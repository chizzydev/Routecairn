import { request as nativeRequest } from "node:http";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { afterEach, describe, it, expect, vi } from "vitest";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { stageAFixture, consentFor, type StageAFixture } from "./trusted-discovery-stage-a.fixture.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
const fixtures: StageAFixture[] = [];
async function fixture(options: Parameters<typeof stageAFixture>[0] = { preview: true }) {
  const f = await stageAFixture(options);
  fixtures.push(f);
  vi.spyOn(RequestSafetyBroker.prototype, "dispatchTrustedDiscoveryGet");
  return f;
}
const selector = (f: StageAFixture) => ({ scanId: f.initial.scanId, candidateId: f.initial.candidateId });
async function review(f: StageAFixture) {
  const response = await f.post("/api/trusted-discovery/review", selector(f));
  expect(response.status).toBe(200);
  const body = (await response.json()) as { review: Record<string, unknown> };
  return body.review;
}
function emptyAttempts(f: StageAFixture) {
  expect(RequestSafetyBroker.prototype.dispatchTrustedDiscoveryGet).not.toHaveBeenCalled();
  expect(f.wire()).toBe(0);
  expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 0 });
}
afterEach(async () => {
  vi.restoreAllMocks();
  for (const f of fixtures.splice(0)) await f.close();
});

describe("NG5B2 Stage A real native dashboard authority", () => {
  it("S01 defaults OFF and persists no review or attempt", async () => {
    const f = await fixture({});
    const r = await f.post("/api/trusted-discovery/review", selector(f));
    expect(r.status).toBe(404);
    expect(await r.json()).toMatchObject({
      code: "DISABLED",
      status: "NOT_EXECUTED",
      attempted: 0,
      initiated: 0,
      observed: 0,
    });
    expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_reviews").get()).toEqual({ n: 0 });
    emptyAttempts(f);
  });
  it("S02 denies local synthetic owner even with opt-in", async () => {
    const f = await fixture({ preview: true, local: true });
    const r = await f.post("/api/trusted-discovery/review", selector(f));
    expect(r.status).toBe(404);
    emptyAttempts(f);
  });
  it.each([
    "no-session",
    "bad-csrf",
    "bad-origin",
    "owner-json",
    "analyst",
    "viewer",
    "wrong-org",
    "global-only",
    "org-only",
    "disabled",
    "locked",
    "demoted",
    "session-expired",
    "password-newer",
  ])("S03 native authority denies %s", async (attack) => {
    const f = await fixture(),
      headers: Record<string, string> = {};
    let body: unknown = selector(f);
    if (attack === "no-session") headers.cookie = "";
    if (attack === "bad-csrf") headers["x-csrf-token"] = "forged";
    if (attack === "bad-origin") headers.origin = "https://foreign.example.test";
    if (attack === "owner-json") body = { ...selector(f), ownerId: f.owner, isOwner: true };
    if (attack === "wrong-org") headers["x-routecairn-organization-id"] = f.otherOrg;
    if (["analyst", "viewer", "org-only", "demoted"].includes(attack))
      f.db.db
        .prepare("UPDATE dashboard_users SET role=? WHERE id=?")
        .run(attack === "viewer" ? "VIEWER" : "ANALYST", f.owner);
    if (attack === "global-only")
      f.db.db
        .prepare("UPDATE organization_memberships SET role='ADMIN' WHERE organization_id=? AND user_id=?")
        .run(f.org, f.owner);
    if (attack === "disabled") f.db.db.prepare("UPDATE dashboard_users SET enabled=0 WHERE id=?").run(f.owner);
    if (attack === "locked")
      f.db.db
        .prepare("UPDATE dashboard_users SET locked_until=? WHERE id=?")
        .run(new Date(Date.now() + 60_000).toISOString(), f.owner);
    if (attack === "session-expired")
      f.db.db.prepare("UPDATE dashboard_sessions SET expires_at='2000-01-01T00:00:00.000Z'").run();
    if (attack === "password-newer")
      f.db.db
        .prepare("UPDATE dashboard_users SET password_changed_at=? WHERE id=?")
        .run(new Date(Date.now() + 1).toISOString(), f.owner);
    const r = await f.post("/api/trusted-discovery/review", body, headers);
    expect([400, 401, 403, 404]).toContain(r.status);
    expect(await r.text()).not.toMatch(/canonical_path|password_hash|stack|sqlite|source\.json/);
    emptyAttempts(f);
  });
  it("S04 review and exact pre-consent are NOT_EXECUTED, persist private keyed metadata only", async () => {
    const f = await fixture();
    const preview = await review(f);
    expect(preview).toMatchObject({
      scanId: f.initial.scanId,
      candidateId: f.initial.candidateId,
      targetId: f.target,
      method: "GET",
      effect: "NON_MUTATING",
      routeLabel: "/api/health",
    });
    expect(JSON.stringify(preview)).not.toContain(f.root);
    expect(JSON.stringify(preview)).not.toContain(f.auth.cookie);
    const r = await f.post("/api/trusted-discovery/pre-consent", consentFor(preview));
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({
      code: "PRECONSENT_RECORDED",
      status: "NOT_EXECUTED",
      attempted: 0,
      initiated: 0,
      observed: 0,
    });
    const row = f.db.db.prepare("SELECT * FROM trusted_discovery_reviews").get() as any;
    expect(row.state).toBe("PRECONSENTED");
    expect(row.source_digest).toMatch(/^[a-f0-9]{64}$/);
    expect(row.route_key).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(row)).not.toContain("/api/health");
    expect(JSON.stringify(row)).not.toContain(f.auth.cookie);
    emptyAttempts(f);
  });
  it.each([
    "replay",
    "guessed",
    "scan-switch",
    "org-switch",
    "user-switch",
    "session-switch",
    "expired",
    "digest-switch",
    "route-switch",
    "effect-switch",
    "expiry-switch",
    "confirmation-switch",
  ])("S05 exact pre-consent denies %s", async (attack) => {
    const f = await fixture();
    const preview = await review(f);
    const body = consentFor(preview) as any;
    const headers: Record<string, string> = {};
    let auth = f.auth;
    if (attack === "replay") expect((await f.post("/api/trusted-discovery/pre-consent", body)).status).toBe(200);
    if (attack === "guessed") body.reviewId = "A".repeat(43);
    if (attack === "scan-switch") body.scanId = f.source().scanId;
    if (attack === "org-switch") headers["x-routecairn-organization-id"] = f.otherOrg;
    if (attack === "user-switch") {
      await f.sessions.createUser({ login: "second@fixture.test", password: f.password, role: "OWNER" });
      auth = await f.login("second@fixture.test");
    }
    if (attack === "session-switch") auth = await f.login();
    if (attack === "expired") {
      const now = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(now + 60_001);
    }
    if (attack === "digest-switch") body.reviewDigest = "0".repeat(64);
    if (attack === "route-switch") body.routeLabel = "/api/status";
    if (attack === "effect-switch") body.effect = "MUTATION";
    if (attack === "expiry-switch") body.expiresAt = new Date(Date.now() + 120_000).toISOString();
    if (attack === "confirmation-switch") body.confirmation = "I_APPROVED_ANOTHER_FEATURE";
    const r = await f.post("/api/trusted-discovery/pre-consent", body, headers, auth);
    expect([400, 401, 403, 404, 409]).toContain(r.status);
    emptyAttempts(f);
  });
  it.each([
    "revoke",
    "disable",
    "global-demote",
    "member-demote",
    "member-delete",
    "org-suspend",
    "target-archive",
    "target-auth",
    "target-scope",
    "target-generation",
    "target-credential",
    "source-delete",
    "source-archive",
    "source-generation",
    "source-worker",
    "artifact-missing",
    "artifact-bytes",
    "password-change",
    "session-expiry",
    "locked",
  ])("S06 live %s invalidates pending native review", async (change) => {
    const f = await fixture();
    const preview = await review(f);
    const db = f.db.db;
    const targetUpdates: Record<string, string> = {
      "target-archive": "archived_at='changed'",
      "target-auth": "authorization_type='CLIENT_AUTHORIZED'",
      "target-scope": "approved_scope_json='{}'",
      "target-generation": "row_version=row_version+1",
      "target-credential": "default_auth_template_json='{} '",
    };
    if (targetUpdates[change]) db.prepare(`UPDATE targets SET ${targetUpdates[change]} WHERE id=?`).run(f.target);
    if (change === "revoke") f.sessions.revokeUserSessions(f.owner);
    if (change === "disable") db.prepare("UPDATE dashboard_users SET enabled=0 WHERE id=?").run(f.owner);
    if (change === "global-demote") db.prepare("UPDATE dashboard_users SET role='ANALYST' WHERE id=?").run(f.owner);
    if (change === "member-demote")
      db.prepare("UPDATE organization_memberships SET role='VIEWER' WHERE user_id=? AND organization_id=?").run(
        f.owner,
        f.org,
      );
    if (change === "member-delete")
      db.prepare("DELETE FROM organization_memberships WHERE user_id=? AND organization_id=?").run(f.owner, f.org);
    if (change === "org-suspend") db.prepare("UPDATE organizations SET status='SUSPENDED' WHERE id=?").run(f.org);
    if (change === "source-delete")
      db.prepare("UPDATE scans SET deleted_at='changed' WHERE id=?").run(f.initial.scanId);
    if (change === "source-archive")
      db.prepare("UPDATE scans SET archived_at='changed' WHERE id=?").run(f.initial.scanId);
    if (change === "source-generation")
      db.prepare("UPDATE scans SET error_summary='changed' WHERE id=?").run(f.initial.scanId);
    if (change === "source-worker")
      db.prepare("UPDATE scan_job_leases SET attempt_number=attempt_number+1 WHERE job_id=?").run(f.initial.scanId);
    if (change === "artifact-missing")
      db.prepare("UPDATE artifacts SET missing_file_flag=1 WHERE id=?").run(f.initial.artifact);
    if (change === "artifact-bytes") writeFileSync(f.initial.file, f.initial.bytes + " ");
    if (change === "password-change")
      db.prepare("UPDATE dashboard_users SET password_changed_at=? WHERE id=?").run(
        new Date(Date.now() + 1).toISOString(),
        f.owner,
      );
    if (change === "session-expiry")
      db.prepare("UPDATE dashboard_sessions SET expires_at='2000-01-01T00:00:00.000Z'").run();
    if (change === "locked")
      db.prepare("UPDATE dashboard_users SET locked_until=? WHERE id=?").run(
        new Date(Date.now() + 60_000).toISOString(),
        f.owner,
      );
    const r = await f.post("/api/trusted-discovery/pre-consent", consentFor(preview));
    expect([401, 403, 404, 409]).toContain(r.status);
    expect(f.db.db.prepare("SELECT state FROM trusted_discovery_reviews").get()).toEqual({ state: "INVALIDATED" });
    emptyAttempts(f);
  });
  it.each(["path", "url", "candidate", "extra", "noncanonical"])("S07 refuses client authority %s", async (attack) => {
    const f = await fixture();
    let body: any = selector(f);
    if (attack === "path") body.reportPath = f.initial.file;
    if (attack === "url") body.url = f.targetOrigin + "/api/health";
    if (attack === "candidate") body.candidateId = "0".repeat(64);
    if (attack === "extra") body.operation = {};
    if (attack === "noncanonical") {
      const source = f.source("/api/%68ealth");
      body = { scanId: source.scanId, candidateId: source.candidateId };
    }
    const r = await f.post("/api/trusted-discovery/review", body);
    expect([400, 403, 409]).toContain(r.status);
    expect(await r.text()).not.toContain(f.root);
    emptyAttempts(f);
  });
  it("S08 every execute spelling and non-POST feature operation returns404 without wire", async () => {
    const f = await fixture();
    const preview = await review(f);
    for (const path of [
      "execute",
      "dispatch",
      "operations/execute",
      "reviews/" + preview.reviewId + "/execute",
      "review/execute",
      "consent/execute",
    ]) {
      const r = await f.post("/api/trusted-discovery/" + path, { ...preview, execute: true });
      expect(r.status).toBe(404);
    }
    for (const method of ["GET", "PUT", "DELETE", "HEAD"]) {
      const r = await fetch(f.handle.url + "/api/trusted-discovery/review", {
        method,
        headers: { cookie: f.auth.cookie },
      });
      expect(r.status).toBe(404);
    }
    emptyAttempts(f);
  });
  it("S10 restart leaves audit but cannot revive an opaque review from DB", async () => {
    const f = await fixture();
    const preview = await review(f);
    await f.stop();
    const handle = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      publicOrigin: f.security.publicOrigin,
      sessionSecret: f.security.sessionSecret,
      trustProxy: true,
      trustedDiscoveryPreviewOnly: true,
    } as Parameters<typeof startDashboardServer>[0]);
    try {
      const r = await fetch(handle.url + "/api/trusted-discovery/pre-consent", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: f.auth.cookie,
          origin: f.security.publicOrigin,
          "x-csrf-token": f.auth.csrf,
          "x-routecairn-organization-id": f.org,
        },
        body: JSON.stringify(consentFor(preview)),
      });
      expect(r.status).toBe(409);
      expect(f.db.db.prepare("SELECT state FROM trusted_discovery_reviews").get()).toEqual({ state: "INVALIDATED" });
      expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_review_events").get()).toMatchObject({
        n: expect.any(Number),
      });
      emptyAttempts(f);
    } finally {
      await handle.close();
    }
  });
  it("S11 unrelated organization API and native source persist unchanged, fixed public redaction", async () => {
    const f = await fixture();
    const r = await fetch(f.handle.url + "/api/operations/organizations", { headers: { cookie: f.auth.cookie } });
    expect(r.status).toBe(200);
    const before = f.initial.bytes;
    const preview = await review(f);
    expect(JSON.stringify(preview)).not.toMatch(/127\.0\.0\.1|csrf|canonical|password|native|receipt/);
    expect(f.db.db.prepare("SELECT status FROM scans WHERE id=?").get(f.initial.scanId)).toEqual({
      status: "COMPLETED",
    });
    expect(before).toBe(f.initial.bytes);
    emptyAttempts(f);
  });
  it("S12 disposal aborts contexts and busy SQLite cannot become in-memory consent success", async () => {
    const f = await fixture();
    const dispose = vi.spyOn(ScanContext.prototype, "dispose");
    const preview = await review(f);
    const blocker = new DashboardDatabase(f.dbPath);
    blocker.db.pragma("busy_timeout=0");
    blocker.db.exec("BEGIN IMMEDIATE");
    try {
      const r = await f.post("/api/trusted-discovery/pre-consent", consentFor(preview));
      expect(r.status).toBe(503);
    } finally {
      blocker.db.exec("ROLLBACK");
      blocker.close();
    }
    const replay = await f.post("/api/trusted-discovery/pre-consent", consentFor(preview));
    expect(replay.status).toBe(409);
    await f.stop();
    expect(dispose).toHaveBeenCalled();
    emptyAttempts(f);
  });
  it("S05 concurrent exact consent records once without issuing any operation", async () => {
    const f = await fixture();
    const preview = await review(f);
    const responses = await Promise.all([
      f.post("/api/trusted-discovery/pre-consent", consentFor(preview)),
      f.post("/api/trusted-discovery/pre-consent", consentFor(preview)),
    ]);
    expect(responses.map((r) => r.status).sort()).toEqual([200, 409]);
    expect(
      f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_review_events WHERE code='PRECONSENTED'").get(),
    ).toEqual({ n: 1 });
    emptyAttempts(f);
  });
  it("S06 real streaming request body cannot retain pre-authentication after revocation", async () => {
    const f = await fixture();
    const preview = await review(f),
      body = JSON.stringify(consentFor(preview));
    const result = new Promise<number>((done, fail) => {
      const req = nativeRequest(
        f.handle.url + "/api/trusted-discovery/pre-consent",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: f.auth.cookie,
            origin: f.security.publicOrigin,
            "x-csrf-token": f.auth.csrf,
            "x-routecairn-organization-id": f.org,
            "content-length": Buffer.byteLength(body),
          },
        },
        (r) => {
          r.resume();
          r.on("end", () => done(r.statusCode!));
        },
      );
      req.on("error", fail);
      req.write(body.slice(0, 20));
      setTimeout(() => {
        f.sessions.revokeUserSessions(f.owner);
        req.end(body.slice(20));
      }, 60);
    });
    expect(await result).toBe(401);
    expect(f.db.db.prepare("SELECT state FROM trusted_discovery_reviews").get()).toEqual({ state: "INVALIDATED" });
    emptyAttempts(f);
  });
  it("S07 native authority rejects forged descriptors and proxies without evaluating getters", async () => {
    const f = await fixture();
    let touched = 0;
    const value = Object.defineProperty({}, "sessionId", {
      get() {
        touched++;
        throw Error("PRIVATE_GETTER_SENTINEL");
      },
    });
    const proxy = new Proxy(
      {},
      {
        get() {
          touched++;
          throw Error("PRIVATE_PROXY_SENTINEL");
        },
      },
    );
    expect(() => f.sessions.revalidateTrustedDiscoverySession(value)).toThrow(/session/);
    expect(() => f.sessions.revalidateTrustedDiscoverySession(proxy)).toThrow(/session/);
    expect(touched).toBe(0);
    emptyAttempts(f);
  });
  it("S07 body limit and malformed JSON return fixed input denials", async () => {
    const f = await fixture();
    for (const [body, status] of [
      ["{", 400],
      [JSON.stringify({ padding: "x".repeat(1024 * 1024) }), 413],
    ] as const) {
      const r = await fetch(f.handle.url + "/api/trusted-discovery/review", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: f.auth.cookie,
          origin: f.security.publicOrigin,
          "x-csrf-token": f.auth.csrf,
          "x-routecairn-organization-id": f.org,
        },
        body,
      });
      expect(r.status).toBe(status);
      expect(await r.json()).toMatchObject({ code: "DENIED_INPUT", status: "NOT_EXECUTED" });
    }
    emptyAttempts(f);
  });
  it("S12 private registry admits at most64 and hard expiry disposes every context", async () => {
    const f = await fixture();
    const dispose = vi.spyOn(ScanContext.prototype, "dispose");
    for (let i = 0; i < 64; i++) expect((await f.post("/api/trusted-discovery/review", selector(f))).status).toBe(200);
    expect((await f.post("/api/trusted-discovery/review", selector(f))).status).toBe(409);
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now + 60_001);
    expect((await f.post("/api/trusted-discovery/review", selector(f))).status).toBe(200);
    expect(dispose).toHaveBeenCalledTimes(64);
    for (const instance of dispose.mock.instances) expect(instance.options.abortSignal!.aborted).toBe(true);
    emptyAttempts(f);
  });
  it("S12 shutdown aborts every pending disposable context", async () => {
    const f = await fixture();
    const dispose = vi.spyOn(ScanContext.prototype, "dispose");
    const preview = await review(f);
    await f.stop();
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(dispose.mock.instances[0]!.options.abortSignal!.aborted).toBe(true);
    expect(f.db.db.prepare("SELECT state FROM trusted_discovery_reviews").get()).toEqual({ state: "INVALIDATED" });
    expect(preview.reviewId).toBeTruthy();
    emptyAttempts(f);
  });
});
