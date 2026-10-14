import { afterEach, describe, expect, it } from "vitest";
import { appendFileSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { stageAFixture, consentFor, type StageAFixture } from "./trusted-discovery-stage-a.fixture.js";
import { handleDiscoveryWorkspaceRead } from "../../src/dashboard/server/TrustedDiscoveryWorkspaceApi.js";
import type { ApiContext } from "../../src/dashboard/server/DashboardApiContext.js";

const fixtures: StageAFixture[] = [];
async function fixture(options: Parameters<typeof stageAFixture>[0] = { preview: true }) {
  const value = await stageAFixture(options);
  fixtures.push(value);
  return value;
}
async function get(f: StageAFixture, path = "/api/trusted-discovery/status", headers: Record<string, string> = {}) {
  return fetch(f.handle.url + path, { headers: { cookie: f.auth.cookie, "x-routecairn-organization-id": f.org, ...headers } });
}
afterEach(async () => { for (const f of fixtures.splice(0)) { expect(f.wire()).toBe(0); if (process.env.ROUTECAIRN_STAGE_C_WIRE_EVIDENCE) appendFileSync(process.env.ROUTECAIRN_STAGE_C_WIRE_EVIDENCE, JSON.stringify({ fixture: "self-maintained-native-preview", targetReceipts: f.wire(), attempts: (f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get() as { n: number }).n }) + "\n"); await f.close(); } });
describe("Stage C metadata-only native workspace", () => {
  it("C01/C03 exposes only authenticated owner preview metadata with zero target traffic", async () => {
    const f = await fixture();
    const response = await get(f);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toMatchObject({ availability: "PREVIEW_ONLY", execution: "UNAVAILABLE", targets: [{ id: f.target }], scans: [{ id: f.initial.scanId, targetId: f.target }] });
    expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_reviews").get()).toEqual({ n: 0 });
    expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_attempts").get()).toEqual({ n: 0 });
  });
  it.each([{}, { preview: false }, { preview: true, local: true }])("C01 denies disabled/local preview %j", async (options) => {
    const f = await fixture(options);
    expect((await get(f)).status).toBe(404);
    expect((await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`)).status).toBe(404);
  });
  it.each(["session-missing", "expired", "revoked", "analyst", "viewer", "membership-demoted", "membership-revoked", "locked", "disabled", "password-changed", "org-inactive", "missing-header", "cross-site"])("C02 refuses current native authority: %s", async (attack) => {
    const f = await fixture(); const headers: Record<string, string> = {};
    if (attack === "session-missing") headers.cookie = "";
    if (attack === "missing-header") headers["x-routecairn-organization-id"] = "";
    if (attack === "cross-site") headers["sec-fetch-site"] = "cross-site";
    if (attack === "expired") f.db.db.prepare("UPDATE dashboard_sessions SET expires_at='2000-01-01T00:00:00.000Z'").run();
    if (attack === "revoked") f.db.db.prepare("UPDATE dashboard_sessions SET revoked_at=?").run(new Date().toISOString());
    if (["analyst", "viewer"].includes(attack)) f.db.db.prepare("UPDATE dashboard_users SET role=? WHERE id=?").run(attack.toUpperCase(), f.owner);
    if (attack === "membership-demoted") f.db.db.prepare("UPDATE organization_memberships SET role='ADMIN' WHERE organization_id=? AND user_id=?").run(f.org, f.owner);
    if (attack === "membership-revoked") f.db.db.prepare("DELETE FROM organization_memberships WHERE organization_id=? AND user_id=?").run(f.org, f.owner);
    if (attack === "locked") f.db.db.prepare("UPDATE dashboard_users SET locked_until=? WHERE id=?").run(new Date(Date.now() + 60_000).toISOString(), f.owner);
    if (attack === "disabled") f.db.db.prepare("UPDATE dashboard_users SET enabled=0 WHERE id=?").run(f.owner);
    if (attack === "password-changed") f.db.db.prepare("UPDATE dashboard_users SET password_changed_at=? WHERE id=?").run(new Date(Date.now() + 1).toISOString(), f.owner);
    if (attack === "org-inactive") f.db.db.prepare("UPDATE organizations SET status='ARCHIVED' WHERE id=?").run(f.org);
    for (const path of ["/api/trusted-discovery/status", `/api/trusted-discovery/candidates/${f.initial.scanId}`]) {
      const response = await get(f, path, headers); expect([401, 403]).toContain(response.status);
      expect(await response.text()).not.toMatch(/cookie|stack|canonical_path|sqlite|password|api\/health/);
    }
  });
  it("C02 distributed infrastructure denies projection without invoking a service", async () => {
    const f = await fixture();
    const request = { method: "GET", headers: { cookie: f.auth.cookie, "x-routecairn-organization-id": f.org } };
    let body = ""; const response = { setHeader() {}, end(value: string) { body = value; }, statusCode: 0 };
    handleDiscoveryWorkspaceRead({ request, response, mode: "server", serverSessions: f.sessions, database: f.db, trustedDiscovery: {}, infrastructure: { config: { mode: "distributed" } }, url: new URL("http://localhost/api/trusted-discovery/status") } as unknown as ApiContext);
    expect(response.statusCode).toBe(404); expect(JSON.parse(body)).toMatchObject({ execution: "UNAVAILABLE" });
  });
  it("C03 projects exact canonical candidate IDs with bounded sanitized facts and no authority allocation", async () => {
    const f = await fixture(); const response = await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`);
    expect(response.status).toBe(200); const text = await response.text(); const body = JSON.parse(text);
    expect(body).toMatchObject({ scanId: f.initial.scanId, targetId: f.target, executionAuthority: "NONE", candidates: [{ candidateId: f.initial.candidateId, method: "GET", executionAuthority: "NONE" }] });
    expect(Buffer.byteLength(text)).toBeLessThan(48 * 1024); expect(text).not.toContain(f.root); expect(text).not.toContain(f.targetOrigin); expect(text).not.toContain("/api/health"); expect(text).not.toContain(f.auth.cookie);
    expect(f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_reviews").get()).toEqual({ n: 0 });
  });
  it.each(["archive", "foreign-org", "corrupt", "missing", "artifact-stale", "incomplete"])("C03 denies retained source: %s", async (attack) => {
    const f = await fixture(); const headers: Record<string, string> = {};
    if (attack === "archive") f.db.db.prepare("UPDATE scans SET archived_at=? WHERE id=?").run(new Date().toISOString(), f.initial.scanId);
    if (attack === "foreign-org") headers["x-routecairn-organization-id"] = f.otherOrg;
    if (attack === "corrupt") writeFileSync(f.initial.file, "{not a report");
    if (attack === "missing") unlinkSync(f.initial.file);
    if (attack === "artifact-stale") f.db.db.prepare("UPDATE artifacts SET missing_file_flag=1 WHERE id=?").run(f.initial.artifact);
    if (attack === "incomplete") { const report = JSON.parse(f.initial.bytes); report.execution.partial = true; writeFileSync(f.initial.file, JSON.stringify(report)); }
    const response = await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`, headers); expect(response.status).toBe(409); expect(await response.text()).not.toContain(f.root);
  });
  it("C03 filters unsafe discovery routes without leaking query/fragment credentials", async () => {
    const f = await fixture(); const report = JSON.parse(f.initial.bytes);
    report.apiMapper.endpoints = ["/api/health?token=private-canary", "/api/admin", "/api/item/123", "/api/health#secret"].map((path) => ({ endpoint: f.targetOrigin + path, method: "GET", hasObjectId: false, authRelevance: "low", riskTags: [] }));
    writeFileSync(f.initial.file, JSON.stringify(report));
    const r = await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`); expect(r.status).toBe(200); const text = await r.text(); expect(JSON.parse(text).candidates).toEqual([]); expect(text).not.toMatch(/private-canary|secret|admin|api\/item/);
  });
  it("C03 caps actual retained candidates at64 with honest truncation", async () => {
    const f = await fixture(); const report = JSON.parse(f.initial.bytes);
    report.apiMapper.endpoints = Array.from({ length: 70 }, (_, n) => ({ endpoint: `${f.targetOrigin}/api/f${String.fromCharCode(97 + Math.floor(n / 26))}${String.fromCharCode(97 + n % 26)}`, method: "GET", hasObjectId: false, authRelevance: "low", riskTags: [] }));
    writeFileSync(f.initial.file, JSON.stringify(report)); const r = await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`); expect(r.status).toBe(200); expect(await r.json()).toMatchObject({ truncated: true, candidates: expect.any(Array) });
    const again = await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`); expect((await again.json()).candidates).toHaveLength(64);
  });
  it("C04/C05 candidate review requires exact server source then deliberate NOT_EXECUTED preconsent", async () => {
    const f = await fixture(); await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`);
    const reviewed = await f.post("/api/trusted-discovery/review", { scanId: f.initial.scanId, candidateId: f.initial.candidateId }); expect(reviewed.status).toBe(200);
    const body = await reviewed.json(); expect(body).toMatchObject({ status: "NOT_EXECUTED", attempted: 0, initiated: 0, observed: 0, executionAuthority: "NONE" });
    expect((await f.post("/api/trusted-discovery/pre-consent", { ...body.review, confirmation: "confirm" })).status).toBe(400);
    const saved = await f.post("/api/trusted-discovery/pre-consent", consentFor(body.review)); expect(saved.status).toBe(200); expect(await saved.json()).toMatchObject({ code: "PRECONSENT_RECORDED", status: "NOT_EXECUTED", observed: 0 });
    expect((await f.post("/api/trusted-discovery/pre-consent", consentFor(body.review))).status).toBe(409);
  });
  it("C04 current generation change after projection still refuses original review", async () => {
    const f = await fixture(); await get(f, `/api/trusted-discovery/candidates/${f.initial.scanId}`);
    writeFileSync(f.initial.file, JSON.stringify({ ...f.initial.report, apiMapper: { endpoints: [], notes: [], graphQlEndpoints: [] } }));
    expect((await f.post("/api/trusted-discovery/review", { scanId: f.initial.scanId, candidateId: f.initial.candidateId })).status).toBe(409);
  });
  it("C07 concurrent real POSTs cannot consume one review twice", async () => {
    const f = await fixture(); const body = await (await f.post("/api/trusted-discovery/review", { scanId: f.initial.scanId, candidateId: f.initial.candidateId })).json();
    const results = await Promise.all([f.post("/api/trusted-discovery/pre-consent", consentFor(body.review)), f.post("/api/trusted-discovery/pre-consent", consentFor(body.review))]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
  });
  it("C10 exact method/path/query allowlist preserves authenticated404 and unauthenticated401", async () => {
    const f = await fixture();
    const paths = ["/api/trusted-discovery/execute", "/api/trusted-discovery/Execute", "/api/trusted-discovery/execute/", "/api/trusted-discovery/executeFresh", "/api/trusted-discovery/ex%65cute", "/api/trusted-discovery/status/", "/api/trusted-discovery/status?execute=true", "/api/trusted-discovery/candidates/guess", "/api/trusted-discovery", "/api/trusted-discovery/unknown"];
    for (const path of paths) for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE"]) {
      const r = await fetch(f.handle.url + path, { method, headers: { cookie: f.auth.cookie } }); expect(r.status, `${method} ${path}`).toBe(404);
    }
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) expect((await fetch(f.handle.url + "/api/trusted-discovery/status", { method, headers: { cookie: f.auth.cookie } })).status).toBe(404);
    expect((await get(f, "/api/trusted-discovery/execute", { cookie: "" })).status).toBe(401);
  });
  it("C13 shipping routes contain no execution dispatch or fixture imports", () => {
    for (const path of ["src/dashboard/server/TrustedDiscoveryWorkspaceApi.ts", "src/dashboard/execution/TrustedDiscoveryProjection.ts", "apps/dashboard-ui/src/TrustedDiscoveryWorkspace.tsx"]) {
      expect(readFileSync(path, "utf8")).not.toMatch(/executeFresh\(|openFixture\(|stage[AB]Fixture|witness\.key|process\.env|localStorage|sessionStorage|dangerouslySetInnerHTML/);
    }
  });
});
