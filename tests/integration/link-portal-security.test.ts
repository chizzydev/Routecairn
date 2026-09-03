import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { LinkPortalSecurityReport } from "../../src/reports/LinkPortalSecurityReport.js";

let server: Server | undefined; const directories: string[] = [];
afterEach(async () => { if (server) await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve())); server = undefined; await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("signed link, portal, invite, and export security integration", () => {
  it("executes all thirteen categories through the CLI with redacted evidence and durable mutation boundaries", async () => {
    const exportBody = "%PDF-1.7 controlled report export"; let redeemed = 0; let revoked = false; let inviteAccepted = false; const receivedUrls: string[] = [];
    server = createServer(async (request, response) => {
      receivedUrls.push(request.url ?? ""); const auth = String(request.headers.authorization ?? ""); const url = new URL(request.url ?? "/", "http://localhost");
      if (url.pathname === "/") return void response.writeHead(200).end("ok");
      if (url.pathname === "/links/issue") return json(response, 200, { signedUrl: `http://${request.headers.host}/signed/link-a?signature=active-signature-abc` });
      if (url.pathname === "/signed/redeem" && request.method === "POST") { await body(request); redeemed++; return json(response, 200, { accepted: true, count: redeemed }); }
      if (url.pathname === "/signed/link-a/restore" && request.method === "POST") { revoked = false; return void response.writeHead(204).end(); }
      if (url.pathname === "/signed/link-a" && request.method === "DELETE") { revoked = true; return void response.writeHead(204).end(); }
      if (url.pathname === "/signed/link-a") {
        const signature = url.searchParams.get("signature");
        if (signature === "expired-signature") return void response.writeHead(403).end();
        if (signature !== "active-signature-abc" || revoked) return void response.writeHead(403).end();
        return json(response, 200, { object: "owner-object-private-171", tenant: "tenant-alpha-private-4471" });
      }
      if (url.pathname === "/objects/owner-object-private-171") return json(response, 200, { id: "owner-object-private-171" });
      if (url.pathname === "/objects/foreign-object-private-992") return json(response, 200, { id: "foreign-object-private-992" });
      if (url.pathname === "/invites/expired-invite-private") return void response.writeHead(410).end();
      if (url.pathname === "/invites/invite-private-661" && request.method === "GET") return json(response, 200, { recipient: { email: "invite-recipient-private@example.test" } });
      if (url.pathname === "/invites/invite-private-661/accept" && request.method === "POST") { await body(request); if (auth.includes("account-b-auth-private")) return void response.writeHead(403).end(); if (inviteAccepted) return void response.writeHead(409).end(); inviteAccepted = true; return void response.writeHead(200).end(); }
      if (url.pathname === "/portal/portal-private-818") return json(response, 200, { tenant: "tenant-alpha-private-4471" });
      if (url.pathname === "/exports/export-private-272") return void response.writeHead(200, { "content-type": "application/pdf" }).end(exportBody);
      if (url.pathname === "/evidence/evidence-private-737") return auth.includes("account-a-auth-private") ? void response.writeHead(200, { "content-type": "application/octet-stream" }).end("evidence-bytes-private") : void response.writeHead(403).end();
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-link-portal-")); directories.push(directory);
    const scope = await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "DELETE"], rateLimitPerSecond: 50, concurrency: 2 });
    const authA = await writeJson(directory, "auth-a.json", authProfile("account-a", "tenant-alpha-private-4471", "account-a-auth-private", { signed_path: "link-a", signed_token: "active-signature-abc", expired_token: "expired-signature", owner_object_id: "owner-object-private-171", foreign_object_id: "foreign-object-private-992", invite_token: "invite-private-661", expired_invite_token: "expired-invite-private", invite_email: "invite-recipient-private@example.test", portal_id: "portal-private-818", export_id: "export-private-272", evidence_id: "evidence-private-737" }));
    const authB = await writeJson(directory, "auth-b.json", authProfile("account-b", "tenant-beta-private-9928", "account-b-auth-private", { foreign_email: "foreign-private@example.test" }));
    const manifest = await writeJson(directory, "link-portal.json", manifestFor(origin, createHash("sha256").update(exportBody).digest("hex")));
    const result = await runScanCommand(`${origin}/`, { scope, authA, authB, linkPortalSecurity: manifest, output: join(directory, "reports") });
    const raw = await readFile(result.reportPath, "utf8"); const markdown = await readFile(result.markdownReportPath, "utf8"); const html = await readFile(result.htmlReportPath, "utf8"); const journal = await readFile(join(process.env.ROUTECAIRN_MUTATION_DIR!, "mutation-journal.json"), "utf8"); const report = JSON.parse(raw) as { linkPortalSecurity: LinkPortalSecurityReport; findings: Array<{ type: string }>; requestAudit: Array<{ requestedUrl: string }> };
    expect(report.linkPortalSecurity).toMatchObject({ enabled: true, plannedCases: 13, executedCases: 13, passedCases: 7, failedCases: 6, inconclusiveCases: 0, blockedCases: 0, requestsTransmitted: 28, requestBudget: 40, cleanupRequired: 1, cleanupFailed: 0 });
    expect(Object.values(report.linkPortalSecurity.coverage).filter((value) => value.planned === 1)).toHaveLength(13);
    expect(report.linkPortalSecurity.observations.find((item) => item.caseId === "signature-tamper")).toMatchObject({ outcome: "PASS", steps: [expect.objectContaining({ capturesRecorded: ["issued_link"] }), expect.objectContaining({ tampered: false }), expect.objectContaining({ tampered: true })] });
    expect(report.linkPortalSecurity.observations.find((item) => item.caseId === "signed-replay")).toMatchObject({ outcome: "FAIL", cleanupOutcome: "NOT_REQUIRED" });
    expect(report.linkPortalSecurity.observations.find((item) => item.caseId === "signed-revocation")).toMatchObject({ outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED" });
    expect(report.findings.map((item) => item.type)).toEqual(expect.arrayContaining(["Signed Link Security Issue", "Portal Tenant Isolation Issue", "Export Authorization Issue", "Object Path Authorization Issue"]));
    expect(report.requestAudit.filter((entry) => (entry.requestedUrl === "redacted://link-portal-request" || entry.requestedUrl === "redacted://workflow-cleanup"))).toHaveLength(28);
    expect(receivedUrls.some((value) => value.includes("active-signature-aba"))).toBe(true);
    expect(journal).toContain("ROLLBACK_VERIFIED");
    expect(markdown).toContain("## Signed Links, Portals, Invites, and Exports"); expect(html).toContain("linkPortalSecurity");
    const secrets = ["account-a-auth-private", "account-b-auth-private", "active-signature-abc", "expired-signature", "owner-object-private-171", "foreign-object-private-992", "invite-private-661", "invite-recipient-private@example.test", "portal-private-818", "export-private-272", "evidence-private-737", "tenant-alpha-private-4471", "tenant-beta-private-9928", "evidence-bytes-private", "operator-private-811", "ticket-private-944"];
    for (const secret of secrets) for (const output of [raw, markdown, html, journal]) expect(output, `persisted ${secret}`).not.toContain(secret);
  }, 30_000);
});

function manifestFor(origin: string, exportHash: string): unknown {
  const observe = { mode: "OBSERVE_ONLY", environment: "TEST" }; const controlled = { mode: "CONTROLLED_LINK_FLOW", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_LINK_PORTAL_EXPORT_TESTING", authorizedBy: "operator-private-811", changeTicket: "ticket-private-944", authorizedAt: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString(), disposableResource: true };
  const actors = [{ id: "anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" }, { id: "owner", safeAlias: "owner", authSlot: "account_a", relationship: "OWNER", principalId: "account-a", tenantId: "tenant-alpha-private-4471" }, { id: "foreign", safeAlias: "foreign", authSlot: "account_b", relationship: "CROSS_TENANT_MEMBER", principalId: "account-b", tenantId: "tenant-beta-private-9928" }];
  const resource = (id: string, kind: string, pathTemplate: string) => ({ id, safeAlias: id, kind, pathTemplate, allowedOrigins: [origin], ownerActorId: "owner", tenantId: "tenant-alpha-private-4471" });
  const resources = [resource("signed", "SIGNED_LINK", "/signed/{object}"), resource("invite", "INVITE", "/invites/{token}"), resource("portal", "PORTAL", "/portal/{portal}"), resource("export", "EXPORT", "/exports/{export}"), resource("evidence", "EVIDENCE_ARTIFACT", "/evidence/{artifact}"), resource("object", "OBJECT_PATH", "/objects/{object}")];
  const request = (urlTemplate: string, secretSource: string = "account_a", extra: Record<string, unknown> = {}) => ({ method: "GET", urlTemplate, secretSource, ...extra });
  const decision = (expected: "ALLOW" | "DENY") => [{ kind: "DECISION", expected }];
  const step = (id: string, phase: string, actorId: string, resourceId: string, req: unknown, assertions: unknown[]) => ({ id, phase, actorId, resourceId, request: req, assertions });
  const signed = `${origin}/signed/{{SECRET:signed_path}}?signature={{SECRET:signed_token}}`; const activeInvite = `${origin}/invites/{{SECRET:invite_token}}`;
  const cases = [
    { id: "signed-expiry", label: "expiry", category: "SIGNED_LINK_EXPIRY", authorization: observe, steps: [step("expired", "VERIFY", "anonymous", "signed", request(`${origin}/signed/{{SECRET:signed_path}}?signature={{SECRET:expired_token}}`), decision("DENY"))] },
    { id: "signature-tamper", label: "tamper", category: "SIGNATURE_TAMPERING", authorization: observe, steps: [{ ...step("issue", "CONTROL", "owner", "signed", request(`${origin}/links/issue`), [{ kind: "STATUS_IN", values: [200] }]), captures: [{ name: "issued_link", source: "JSON", path: "signedUrl" }] }, step("control", "CONTROL", "anonymous", "signed", request("{{CAPTURE:issued_link}}"), decision("ALLOW")), step("tampered", "VERIFY", "anonymous", "signed", request("{{CAPTURE:issued_link}}", "anonymous", { tamper: { kind: "QUERY_PARAMETER", parameter: "signature", strategy: "FLIP_LAST_CHARACTER" } }), decision("DENY"))] },
    { id: "id-substitution", label: "substitution", category: "ID_SUBSTITUTION", authorization: observe, steps: [step("owner", "CONTROL", "owner", "object", request(`${origin}/objects/{{SECRET:owner_object_id}}?signature={{SECRET:signed_token}}`), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "object", request(`${origin}/objects/{{SECRET:foreign_object_id}}?signature={{SECRET:signed_token}}`), decision("DENY"))] },
    { id: "cross-tenant-link", label: "tenant link", category: "CROSS_TENANT_SIGNED_LINK", authorization: observe, steps: [step("owner", "CONTROL", "owner", "signed", request(signed), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "signed", request(signed), decision("DENY"))] },
    { id: "signed-replay", label: "link replay", category: "SIGNED_LINK_REPLAY", authorization: controlled, steps: [step("first", "ACTION", "owner", "signed", request(`${origin}/signed/redeem`, "account_a", { method: "POST", stateChanging: true, fields: { token: "{{SECRET:signed_token}}" } }), decision("ALLOW")), step("replay", "VERIFY", "owner", "signed", request(`${origin}/signed/redeem`, "account_a", { method: "POST", stateChanging: true, fields: { token: "{{SECRET:signed_token}}" } }), decision("DENY"))] },
    { id: "signed-revocation", label: "revocation", category: "SIGNED_LINK_REVOCATION", authorization: { ...controlled, disposableResource: false }, cleanupRequired: true, steps: [step("before", "CONTROL", "owner", "signed", request(signed), decision("ALLOW")), step("revoke", "ACTION", "owner", "signed", request(`${origin}/signed/{{SECRET:signed_path}}`, "account_a", { method: "DELETE", stateChanging: true }), [{ kind: "STATUS_IN", values: [204] }]), step("after", "VERIFY", "owner", "signed", request(signed), decision("DENY")), step("restore", "CLEANUP", "owner", "signed", request(`${origin}/signed/{{SECRET:signed_path}}/restore`, "account_a", { method: "POST", stateChanging: true }), [{ kind: "STATUS_IN", values: [204] }]), step("restored", "CLEANUP", "owner", "signed", request(signed), decision("ALLOW"))] },
    { id: "invite-binding", label: "binding", category: "INVITE_EMAIL_BINDING", authorization: controlled, steps: [step("inspect", "CONTROL", "owner", "invite", request(activeInvite), [{ kind: "JSON_EQUALS_SECRET", path: "recipient.email", secretSource: "account_a", secretRef: "invite_email" }]), step("foreign", "VERIFY", "foreign", "invite", request(`${activeInvite}/accept`, "account_a", { method: "POST", stateChanging: true }), decision("DENY"))] },
    { id: "invite-replay", label: "invite replay", category: "INVITE_REPLAY", authorization: controlled, steps: [step("accept", "ACTION", "owner", "invite", request(`${activeInvite}/accept`, "account_a", { method: "POST", stateChanging: true }), decision("ALLOW")), step("again", "VERIFY", "owner", "invite", request(`${activeInvite}/accept`, "account_a", { method: "POST", stateChanging: true }), decision("DENY"))] },
    { id: "invite-expiration", label: "invite expiry", category: "INVITE_EXPIRATION", authorization: observe, steps: [step("expired", "VERIFY", "anonymous", "invite", request(`${origin}/invites/{{SECRET:expired_invite_token}}`), decision("DENY"))] },
    { id: "portal-tenant", label: "portal tenant", category: "PORTAL_TENANT_BINDING", authorization: observe, steps: [step("owner", "CONTROL", "owner", "portal", request(`${origin}/portal/{{SECRET:portal_id}}`), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "portal", request(`${origin}/portal/{{SECRET:portal_id}}`), decision("DENY"))] },
    { id: "export-auth", label: "export", category: "EXPORT_AUTHORIZATION", authorization: observe, steps: [step("owner", "CONTROL", "owner", "export", request(`${origin}/exports/{{SECRET:export_id}}`), [...decision("ALLOW"), { kind: "BODY_FINGERPRINT", expectedSha256: exportHash }]), step("foreign", "VERIFY", "foreign", "export", request(`${origin}/exports/{{SECRET:export_id}}`), decision("DENY"))] },
    { id: "evidence-auth", label: "evidence", category: "EVIDENCE_ARTIFACT_AUTHORIZATION", authorization: observe, steps: [step("owner", "CONTROL", "owner", "evidence", request(`${origin}/evidence/{{SECRET:evidence_id}}`), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "evidence", request(`${origin}/evidence/{{SECRET:evidence_id}}`), decision("DENY"))] },
    { id: "object-ownership", label: "ownership", category: "OBJECT_PATH_OWNERSHIP", authorization: observe, steps: [step("owner", "CONTROL", "owner", "object", request(`${origin}/objects/{{SECRET:owner_object_id}}`), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "object", request(`${origin}/objects/{{SECRET:owner_object_id}}`), decision("DENY"))] }
  ];
  return { schemaVersion: 1, maxCases: 20, maxStepsPerCase: 8, maxRequests: 40, maxResponseBytes: 131072, actors, resources, cases };
}

function authProfile(principalId: string, tenantId: string, token: string, lifecycleSecrets: Record<string, string>): unknown { return { label: principalId, safeAlias: principalId, principalId, tenantId, headers: { Authorization: `Bearer ${token}` }, cookies: [], lifecycleSecrets, notes: [] }; }
function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); }
async function body(request: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks).toString("utf8"); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, JSON.stringify(value)); return path; }
