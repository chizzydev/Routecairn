import { it, expect } from "vitest";
import { deepBusinessFixture } from "../helpers/deep-businessflow-fixture.js";
import { ownedIntakeExport } from "../helpers/owned-intake-export.js";
import { OwnedApplicationIntakeService } from "../../src/dashboard/execution/OwnedApplicationIntake.js";
import { identityFingerprint } from "../../src/dashboard/execution/ObservedActorEvidence.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("retrieves a committed offline intake over authenticated HTTP without replay or target requests after lost acknowledgement", async () => {
  const f = await deepBusinessFixture();
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined;
  try {
    const receipt = new OwnedApplicationIntakeService(f.database).create(
      f.org,
      {
        targetId: f.targetId,
        credentials: f.credentials,
        artifact: ownedIntakeExport(f),
        ownerScopeConfirmed: true,
        offlineOnlyConfirmed: true
      },
      "operator"
    );
    await f.execution.shutdown();
    const origin = "https://receipt.fixture.test",
      secret = "owned-receipt-session-secret-strong-2026",
      sessions = new ServerSessionManager(f.database, {
        publicOrigin: origin,
        sessionSecret: secret,
        trustProxy: true,
        developmentInsecureHttp: false
      });
    await sessions.createFirstOwner("owner@fixture.test", "Disposable password 49!");
    await sessions.createUser({ login: "viewer@fixture.test", password: "Disposable password 49!", role: "VIEWER" });
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "server",
      port: 0,
      publicOrigin: origin,
      sessionSecret: secret,
      trustProxy: true,
      masterKey: f.key.toString("base64url")
    });
    const login = await fetch(server.url + "/api/auth/login", {
      method: "POST",
      headers: { origin, "content-type": "application/json", "x-forwarded-proto": "https" },
      body: JSON.stringify({ login: "owner@fixture.test", password: "Disposable password 49!" })
    });
    expect(login.status).toBe(200);
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!,
      headers = { cookie, origin, "x-forwarded-proto": "https" },
      base = server.url + "/api/authorization-workbench/mapping/intakes";
    const list = await fetch(base + "?targetId=" + f.targetId, { headers }),
      body = await list.json();
    f.capture("INTAKE_RECEIPT_READ_RED_GREEN", { status: list.status, body, receipt, wire: f.wire });
    expect(list.status).toBe(200);
    const r = await fetch(base + "/" + receipt.revisionId, { headers });
    expect(r.status).toBe(200);
    const saved = (await r.json()) as { digest: string; freshness: string };
    expect(saved.digest).toBe(receipt.digest);
    expect(saved.freshness).toBe("CURRENT");
    expect(f.wire).toHaveLength(0);
    expect(f.database.db.prepare("SELECT count(*) n FROM application_owned_intakes").get()).toEqual({ n: 1 });
    const viewer = await fetch(server.url + "/api/auth/login", {
        method: "POST",
        headers: { origin, "content-type": "application/json", "x-forwarded-proto": "https" },
        body: JSON.stringify({ login: "viewer@fixture.test", password: "Disposable password 49!" })
      }),
      vc = viewer.headers.get("set-cookie")!.split(";")[0]!;
    expect((await fetch(base + "/" + receipt.revisionId, { headers: { ...headers, cookie: vc } })).status).toBe(403);
    f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.targetId);
    const stale = (await (await fetch(base + "/" + receipt.revisionId, { headers })).json()) as { freshness: string };
    expect(stale.freshness).toBe("STALE");
    expect(f.wire).toHaveLength(0);
  } finally {
    await server?.close();
    await f.close();
  }
});
for (const bad of ["missing", "blank", "duplicate"] as const)
  it("refuses " + bad + " registered actor evidence instead of validating placeholder fingerprints", async () => {
    const f = await deepBusinessFixture();
    try {
      const artifact = ownedIntakeExport(f),
        original = f.truth.actors.primary,
        summary =
          bad === "missing"
            ? {}
            : bad === "blank"
              ? { principalId: " ", tenantId: " ", role: " " }
              : { principalId: original.principal, tenantId: original.tenant, role: original.role };
      f.database.db
        .prepare("UPDATE credential_profiles SET safe_identity_summary_json=? WHERE id=?")
        .run(JSON.stringify(summary), f.credentials.account_a);
      const value = summary as { principalId?: string; tenantId?: string; role?: string },
        actors = artifact.actors.map((a) =>
          a.slot === "account_a"
            ? {
                ...a,
                principalFingerprint: identityFingerprint(String(value.principalId)),
                tenantFingerprint: identityFingerprint(String(value.tenantId)),
                roleFingerprint: identityFingerprint(String(value.role))
              }
            : a
        );
      let error = "",
        accepted: unknown;
      try {
        accepted = new OwnedApplicationIntakeService(f.database).create(
          f.org,
          {
            targetId: f.targetId,
            credentials: f.credentials,
            artifact: { ...artifact, actors },
            ownerScopeConfirmed: true,
            offlineOnlyConfirmed: true
          },
          "operator"
        );
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
      f.capture("INVALID_REGISTERED_ACTOR_" + bad + "_RED_GREEN", {
        accepted,
        error,
        rows: f.database.db.prepare("SELECT * FROM application_owned_intakes").all(),
        wire: f.wire
      });
      expect(error).toMatch(/EXPLICIT_ACTOR_METADATA_REQUIRED|DISTINCT_ACTOR_CONTEXTS_REQUIRED/);
      expect(f.database.db.prepare("SELECT count(*) n FROM application_owned_intakes").get()).toEqual({ n: 0 });
      expect(f.wire).toHaveLength(0);
    } finally {
      await f.close();
    }
  });
