import pg from "pg";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { consentFor } from "./trusted-discovery-stage-a.fixture.js";
import { describe, it, expect, vi } from "vitest";
import { stageAFixture } from "./trusted-discovery-stage-a.fixture.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";

describe("Stage A final native lifetime and startup boundary", () => {
  it("S01 distributed preview is refused before any infrastructure connection", async () => {
    const f = await stageAFixture();
    const connect = vi.spyOn(pg.Client.prototype, "connect");
    try {
      vi.stubEnv("ROUTECAIRN_CONTROL_PLANE_MODE", "distributed");
      vi.stubEnv("ROUTECAIRN_DATABASE_URL_FILE", "");
      vi.stubEnv(
        "ROUTECAIRN_DATABASE_URL",
        `postgresql://fixture:fixture@127.0.0.1:${new URL(f.targetOrigin).port}/fixture`,
      );
      await expect(
        startDashboardServer({
          dataDir: f.root,
          mode: "server",
          publicOrigin: f.security.publicOrigin,
          sessionSecret: f.security.sessionSecret,
          trustProxy: true,
          trustedDiscoveryPreviewOnly: true,
        }),
      ).rejects.toThrow("TRUSTED_DISCOVERY_REQUIRES_LOCAL_CONTROL_PLANE");
      expect(connect).not.toHaveBeenCalled();
      expect(f.wire()).toBe(0);
    } finally {
      vi.unstubAllEnvs();
      connect.mockRestore();
      await f.close();
    }
  });
  it("S03 malformed input from another tenant cannot cancel an owner review", async () => {
    const f = await stageAFixture({ preview: true });
    try {
      const reviewResponse = await f.post("/api/trusted-discovery/review", {
        scanId: f.initial.scanId,
        candidateId: f.initial.candidateId,
      });
      expect(reviewResponse.status).toBe(200);
      const body = (await reviewResponse.json()) as any;
      const otherUser = await f.sessions.createUser({
        login: "other-tenant@fixture.test",
        password: f.password,
        role: "OWNER",
      });
      const otherOrg = new OrganizationService(f.db).create({ name: "Isolated", slug: "isolated" }, otherUser);
      const otherAuth = await f.login("other-tenant@fixture.test");
      const malformed = await fetch(f.handle.url + "/api/trusted-discovery/review", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: otherAuth.cookie,
          origin: f.security.publicOrigin,
          "x-csrf-token": otherAuth.csrf,
          "x-routecairn-organization-id": otherOrg,
        },
        body: "{",
      });
      expect(malformed.status).toBe(400);
      expect((await f.post("/api/trusted-discovery/pre-consent", consentFor(body.review))).status).toBe(200);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S04 exact approved IPv6 loopback retains native hostname semantics", async () => {
    const f = await stageAFixture({ preview: true, targetHost: "::1" });
    try {
      const r = await f.post("/api/trusted-discovery/review", {
        scanId: f.initial.scanId,
        candidateId: f.initial.candidateId,
      });
      expect(r.status).toBe(200);
      expect(await r.json()).toMatchObject({ status: "NOT_EXECUTED", attempted: 0, initiated: 0, observed: 0 });
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
  it("S12 uncertain source producer denies before constructing a context", async () => {
    const f = await stageAFixture({ preview: true });
    const create = vi.spyOn(ScanContext.prototype, "createHttpClient");
    try {
      f.db.db.prepare("UPDATE scan_job_leases SET released_at=NULL WHERE job_id=?").run(f.initial.scanId);
      const r = await f.post("/api/trusted-discovery/review", {
        scanId: f.initial.scanId,
        candidateId: f.initial.candidateId,
      });
      expect(r.status).toBe(409);
      expect(create).not.toHaveBeenCalled();
      expect(f.wire()).toBe(0);
    } finally {
      create.mockRestore();
      await f.close();
    }
  });
  it("S05 native session handle itself expires within60seconds", async () => {
    const f = await stageAFixture({ preview: true });
    try {
      const authority = f.sessions.captureTrustedDiscoverySession(
        {
          headers: {
            cookie: f.auth.cookie,
            origin: f.security.publicOrigin,
            "content-type": "application/json",
            host: "dashboard.fixture.test",
            "x-forwarded-proto": "https",
          },
        } as any,
        f.auth.csrf,
      );
      expect(() => JSON.stringify(authority)).toThrow(/PRIVATE/);
      const now = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(now + 60_001);
      expect(() => f.sessions.revalidateTrustedDiscoverySession(authority)).toThrow(/session/);
    } finally {
      vi.restoreAllMocks();
      await f.close();
    }
  });
  it("S01 an invalid startup flag cannot be mistaken for explicit opt-in", async () => {
    const f = await stageAFixture();
    let extra: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
    try {
      try {
        extra = await startDashboardServer({
          dataDir: f.root,
          mode: "server",
          publicOrigin: f.security.publicOrigin,
          sessionSecret: f.security.sessionSecret,
          trustProxy: true,
          trustedDiscoveryPreviewOnly: "false",
        } as any);
      } catch (error) {
        expect(error instanceof Error ? error.message : "unknown").toBe("TRUSTED_DISCOVERY_PREVIEW_OPTION_INVALID");
        return;
      }
      throw Error("INVALID_FLAG_ACCEPTED");
    } finally {
      await extra?.close();
      await f.close();
    }
  });
  it("S01 HTTP settings cannot enable preview, and a broad listener is rejected", async () => {
    const f = await stageAFixture();
    try {
      const r = await fetch(f.handle.url + "/api/settings", {
        method: "PATCH",
        headers: {
          "content-type": "application/json",
          cookie: f.auth.cookie,
          origin: f.security.publicOrigin,
          "x-csrf-token": f.auth.csrf,
        },
        body: JSON.stringify({ values: { trustedDiscoveryPreviewOnly: true } }),
      });
      expect(r.status).toBe(400);
      expect(
        (
          await f.post("/api/trusted-discovery/review", {
            scanId: f.initial.scanId,
            candidateId: f.initial.candidateId,
          })
        ).status,
      ).toBe(404);
      await expect(
        startDashboardServer({
          host: "0.0.0.0",
          mode: "server",
          dataDir: f.root,
          publicOrigin: f.security.publicOrigin,
          sessionSecret: f.security.sessionSecret,
          trustProxy: true,
          trustedDiscoveryPreviewOnly: true,
        }),
      ).rejects.toThrow(/LOOPBACK/);
      expect(f.wire()).toBe(0);
    } finally {
      await f.close();
    }
  });
});
