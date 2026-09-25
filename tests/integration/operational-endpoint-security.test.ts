import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { OperationalEndpointSecurityReport } from "../../src/reports/OperationalEndpointSecurityReport.js";

const webhookKey = "webhook-key-private-711";
const webhookTimestamp = "1788091200";
let server: Server | undefined;
const directories: string[] = [];

afterEach(async () => {
  if (server) await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
  server = undefined;
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("operational endpoint security integration", () => {
  it("executes all twelve categories with raw-body signing, actor isolation, redacted evidence, and verified cleanup", async () => {
    const state = { idempotencyCount: 0, idempotencyEvents: new Set<string>(), orderStatus: "baseline", payload: { amount: "0", currency: "NONE", product: "baseline" }, cronWork: 0 };
    let exactSignatures = 0;
    let tamperedSignatures = 0;
    server = createServer(async (request, response) => {
      const url = new URL(request.url ?? "/", "http://localhost");
      const authorization = String(request.headers.authorization ?? "");
      if (url.pathname === "/") return json(response, 200, { ok: true });
      if (url.pathname.startsWith("/webhook/") && request.method === "POST") {
        const raw = await body(request);
        if (!validSignature(request, raw)) { tamperedSignatures++; return json(response, 401, { accepted: false }); }
        exactSignatures++;
        const value = JSON.parse(raw) as Record<string, string | number>;
        if (url.pathname === "/webhook/signature") return json(response, 202, { accepted: true });
        if (url.pathname === "/webhook/replay") return json(response, 202, { accepted: true });
        if (url.pathname === "/webhook/idempotency") { const eventId = String(value.eventId); if (!state.idempotencyEvents.has(eventId)) { state.idempotencyEvents.add(eventId); state.idempotencyCount++; } return json(response, 202, { accepted: true }); }
        if (url.pathname === "/webhook/order") { state.orderStatus = String(value.status); return json(response, 202, { accepted: true }); }
        if (url.pathname === "/webhook/payload") { state.payload = { amount: String(value.amount), currency: String(value.currency), product: "wrong-product" }; return json(response, 202, { accepted: true }); }
      }
      if (url.pathname === "/state/idempotency") return json(response, 200, { count: state.idempotencyCount });
      if (url.pathname === "/state/order") return json(response, 200, { status: state.orderStatus });
      if (url.pathname === "/state/payload") return json(response, 200, state.payload);
      if (url.pathname === "/state/cron") return json(response, 200, { work: state.cronWork });
      if (url.pathname === "/cron/auth") return authorization === "Bearer ops-admin-private-811" ? json(response, 200, { scheduled: true }) : json(response, 401, { scheduled: false });
      if (url.pathname === "/cron/replay" && request.method === "POST") { await body(request); return json(response, 202, { accepted: true }); }
      if (url.pathname === "/cron/workload" && request.method === "POST") { const value = JSON.parse(await body(request)) as { requested: number }; state.cronWork += value.requested; return json(response, 202, { accepted: true }); }
      if (url.pathname === "/jobs/job-private-440") return authorization.includes("account-") ? json(response, 200, { state: "queued" }) : json(response, 401, { state: "denied" });
      if (url.pathname === "/incidents/incident-private-550") return authorization === "Bearer account-a-private-221" ? json(response, 200, { state: "open" }) : json(response, 403, { state: "denied" });
      if (url.pathname === "/health") return json(response, 200, { status: "ok", databaseUrl: "postgres://internal-private-host/db" });
      if (url.pathname === "/admin/workers") return authorization === "Bearer ops-admin-private-811" || authorization === "Bearer account-b-private-331" ? json(response, 200, { workers: 4 }) : json(response, 403, { workers: 0 });
      if (url.pathname === "/admin/reset-payload" && request.method === "POST") { state.payload = { amount: "0", currency: "NONE", product: "baseline" }; return void response.writeHead(204).end(); }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-operational-")); directories.push(directory);
    const scope = await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"], rateLimitPerSecond: 50, concurrency: 2 });
    const primary = await writeJson(directory, "primary.json", profile("ops-admin", "tenant-ops", "ops-admin-private-811", primarySecrets()));
    const accountA = await writeJson(directory, "account-a.json", profile("account-a", "tenant-a", "account-a-private-221", { job_id: "job-private-440", incident_id: "incident-private-550" }));
    const accountB = await writeJson(directory, "account-b.json", profile("account-b", "tenant-b", "account-b-private-331", {}));
    const manifest = await writeJson(directory, "operational.json", manifestFor(origin));
    const result = await runScanCommand(`${origin}/`, { scope, auth: primary, authA: accountA, authB: accountB, operationalEndpoints: manifest, output: join(directory, "reports") });
    const raw = await readFile(result.reportPath, "utf8");
    const markdown = await readFile(result.markdownReportPath, "utf8");
    const html = await readFile(result.htmlReportPath, "utf8");
    const journal = await readFile(join(process.env.ROUTECAIRN_MUTATION_DIR!, "mutation-journal.json"), "utf8");
    const report = JSON.parse(raw) as { operationalEndpointSecurity: OperationalEndpointSecurityReport; findings: Array<{ type: string }>; requestAudit: Array<{ requestedUrl: string }> };
    expect(report.operationalEndpointSecurity).toMatchObject({ enabled: true, plannedCases: 12, executedCases: 12, passedCases: 4, failedCases: 8, inconclusiveCases: 0, blockedCases: 0, requestsTransmitted: 29, requestBudget: 40, cleanupRequired: 1, cleanupFailed: 0 });
    expect(Object.values(report.operationalEndpointSecurity.coverage).filter((entry) => entry.planned === 1)).toHaveLength(12);
    expect(report.operationalEndpointSecurity.observations.find((item) => item.caseId === "signature-rejection")).toMatchObject({ outcome: "PASS", steps: [expect.objectContaining({ signed: true, signatureTampered: false }), expect.objectContaining({ signed: true, signatureTampered: true })] });
    expect(report.operationalEndpointSecurity.observations.find((item) => item.caseId === "payload-integrity")).toMatchObject({ outcome: "FAIL", cleanupOutcome: "ROLLBACK_VERIFIED" });
    expect(report.operationalEndpointSecurity.observations.find((item) => item.caseId === "cron-authentication")).toMatchObject({ outcome: "PASS" });
    expect(exactSignatures).toBe(8); expect(tamperedSignatures).toBe(1);
    expect(report.findings.map((finding) => finding.type)).toEqual(expect.arrayContaining(["Webhook Security Issue", "Cron Security Issue", "Job Authorization Issue", "Operational Endpoint Authorization Issue", "Operational Information Exposure"]));
    expect(report.requestAudit.filter((entry) => (entry.requestedUrl === "redacted://operational-endpoint-request" || entry.requestedUrl === "redacted://workflow-cleanup"))).toHaveLength(29);
    expect(journal).toContain("ROLLBACK_VERIFIED");
    expect(markdown).toContain("## Webhook, Cron, and Operational Endpoints"); expect(html).toContain("operationalEndpointSecurity");
    const secrets = [webhookKey, webhookTimestamp, "ops-admin-private-811", "account-a-private-221", "account-b-private-331", "event-signature-private", "event-replay-private", "event-idempotency-private", "expected-product-private", "job-private-440", "incident-private-550", "postgres://internal-private-host/db", "operator-private-611", "OPS-private-877"];
    for (const secret of secrets) for (const artifact of [raw, markdown, html, journal]) expect(artifact, `persisted ${secret}`).not.toContain(secret);
  }, 180_000);
});

function manifestFor(origin: string): unknown {
  const observe = { mode: "OBSERVE_ONLY", environment: "TEST" };
  const controlled = { mode: "CONTROLLED_OPERATIONAL_FLOW", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_OPERATIONAL_ENDPOINT_TESTING", authorizedBy: "operator-private-611", changeTicket: "OPS-private-877", authorizedAt: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString(), disposableTarget: true };
  const actors = [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "PUBLIC" }, { id: "service", safeAlias: "service", authSlot: "primary", relationship: "OPERATOR", principalId: "ops-admin", tenantId: "tenant-ops" }, { id: "owner", safeAlias: "owner", authSlot: "account_a", relationship: "OWNER", principalId: "account-a", tenantId: "tenant-a" }, { id: "foreign", safeAlias: "foreign", authSlot: "account_b", relationship: "CROSS_TENANT", principalId: "account-b", tenantId: "tenant-b" }];
  const endpoint = (id: string, kind: string, pathTemplate: string, declaredWorkloadLimit?: number) => ({ id, safeAlias: id, kind, pathTemplate, allowedOrigins: [origin], ...(declaredWorkloadLimit === undefined ? {} : { declaredWorkloadLimit }) });
  const endpoints = [endpoint("webhook", "WEBHOOK", "/webhook/{event}"), endpoint("cron", "CRON", "/cron/{job}", 2), endpoint("state", "JOB", "/state/{workflow}"), endpoint("job", "JOB", "/jobs/{job}"), endpoint("incident", "INCIDENT", "/incidents/{incident}"), endpoint("health", "HEALTH", "/health"), endpoint("admin", "ADMIN", "/admin/{operation}")];
  const decision = (expected: "ALLOW" | "DENY") => [{ kind: "DECISION", expected }];
  const request = (method: string, urlTemplate: string, secretSource: string = "anonymous", fields?: unknown) => ({ method, urlTemplate, secretSource, ...(fields === undefined ? {} : { stateChanging: true, bodyFormat: "JSON", fields }) });
  const signed = (path: string, fields: unknown, tamper = false) => ({ ...request("POST", `${origin}${path}`, "primary", fields), hmac: { kind: "HMAC", algorithm: "sha256", secretSource: "primary", secretRef: "webhook_secret", header: "X-Webhook-Signature", encoding: "HEX", prefix: "sha256=", messageFormat: "TIMESTAMP_DOT_BODY", timestampHeader: "X-Webhook-Timestamp", timestampSecretRef: "webhook_timestamp", tamper } });
  const step = (id: string, phase: string, actorId: string, endpointId: string, req: unknown, assertions: unknown[], captures?: unknown[]) => ({ id, phase, actorId, endpointId, request: req, assertions, ...(captures ? { captures } : {}) });
  const cases = [
    { id: "signature-rejection", label: "signature rejection", category: "WEBHOOK_SIGNATURE_REJECTION", authorization: controlled, steps: [step("valid", "ACTION", "public", "webhook", signed("/webhook/signature", { eventId: "{{SECRET:signature_event}}" }), decision("ALLOW")), step("tampered", "VERIFY", "public", "webhook", signed("/webhook/signature", { eventId: "{{SECRET:signature_event}}" }, true), decision("DENY"))] },
    { id: "webhook-replay", label: "webhook replay", category: "WEBHOOK_REPLAY_PROTECTION", authorization: controlled, steps: [step("first", "ACTION", "public", "webhook", signed("/webhook/replay", { eventId: "{{SECRET:replay_event}}" }), decision("ALLOW")), step("second", "VERIFY", "public", "webhook", signed("/webhook/replay", { eventId: "{{SECRET:replay_event}}" }), decision("DENY"))] },
    { id: "webhook-idempotency", label: "webhook idempotency", category: "WEBHOOK_IDEMPOTENCY", authorization: controlled, steps: [step("before", "PRE_STATE", "service", "state", request("GET", `${origin}/state/idempotency`), [{ kind: "STATUS_IN", values: [200] }], [{ name: "idempotency_before", source: "JSON", path: "count" }]), step("first", "ACTION", "public", "webhook", signed("/webhook/idempotency", { eventId: "{{SECRET:idempotency_event}}" }), decision("ALLOW")), step("second", "ACTION", "public", "webhook", signed("/webhook/idempotency", { eventId: "{{SECRET:idempotency_event}}" }), decision("ALLOW")), step("after", "VERIFY", "service", "state", request("GET", `${origin}/state/idempotency`), [{ kind: "NUMERIC_DELTA", before: "idempotency_before", after: "idempotency_after", operator: "LTE", expected: 1 }], [{ name: "idempotency_after", source: "JSON", path: "count" }])] },
    { id: "event-ordering", label: "event ordering", category: "WEBHOOK_EVENT_ORDERING", authorization: controlled, steps: [step("new", "ACTION", "public", "webhook", signed("/webhook/order", { eventId: "{{SECRET:new_event}}", sequence: 2, status: "{{SECRET:expected_order_status}}" }), decision("ALLOW")), step("old", "ACTION", "public", "webhook", signed("/webhook/order", { eventId: "{{SECRET:old_event}}", sequence: 1, status: "{{SECRET:old_order_status}}" }), decision("ALLOW")), step("verify", "VERIFY", "service", "state", request("GET", `${origin}/state/order`), [{ kind: "JSON_EQUALS_SECRET", path: "status", secretSource: "primary", secretRef: "expected_order_status" }])] },
    { id: "payload-integrity", label: "payload integrity", category: "WEBHOOK_PAYLOAD_INTEGRITY", authorization: { ...controlled, disposableTarget: false }, cleanupRequired: true, steps: [step("action", "ACTION", "public", "webhook", signed("/webhook/payload", { eventId: "{{SECRET:payload_event}}", amount: "{{SECRET:expected_amount}}", currency: "{{SECRET:expected_currency}}", product: "{{SECRET:expected_product}}" }), decision("ALLOW")), step("verify", "VERIFY", "service", "state", request("GET", `${origin}/state/payload`), [{ kind: "JSON_EQUALS_SECRET", path: "amount", secretSource: "primary", secretRef: "expected_amount" }, { kind: "JSON_EQUALS_SECRET", path: "currency", secretSource: "primary", secretRef: "expected_currency" }, { kind: "JSON_EQUALS_SECRET", path: "product", secretSource: "primary", secretRef: "expected_product" }]), step("reset", "CLEANUP", "service", "admin", request("POST", `${origin}/admin/reset-payload`, "primary", {}), [{ kind: "STATUS_IN", values: [204] }]), step("restored", "CLEANUP", "service", "state", request("GET", `${origin}/state/payload`), [{ kind: "JSON_EQUALS_SECRET", path: "product", secretSource: "primary", secretRef: "baseline_product" }])] },
    { id: "cron-authentication", label: "cron authentication", category: "CRON_AUTHENTICATION", authorization: observe, steps: [step("public", "VERIFY", "public", "cron", request("GET", `${origin}/cron/auth`), decision("DENY")), step("service", "VERIFY", "service", "cron", request("GET", `${origin}/cron/auth`), decision("ALLOW"))] },
    { id: "cron-replay", label: "cron replay", category: "CRON_REPLAY_PROTECTION", authorization: controlled, steps: [step("first", "ACTION", "service", "cron", request("POST", `${origin}/cron/replay`, "primary", { nonce: "{{SECRET:cron_nonce}}" }), decision("ALLOW")), step("second", "VERIFY", "service", "cron", request("POST", `${origin}/cron/replay`, "primary", { nonce: "{{SECRET:cron_nonce}}" }), decision("DENY"))] },
    { id: "cron-workload", label: "cron workload", category: "CRON_SCOPE_WORKLOAD_LIMIT", authorization: controlled, steps: [step("before", "PRE_STATE", "service", "state", request("GET", `${origin}/state/cron`), [{ kind: "STATUS_IN", values: [200] }], [{ name: "cron_before", source: "JSON", path: "work" }]), step("action", "ACTION", "service", "cron", request("POST", `${origin}/cron/workload`, "primary", { requested: 5 }), decision("ALLOW")), step("after", "VERIFY", "service", "state", request("GET", `${origin}/state/cron`), [{ kind: "NUMERIC_DELTA", before: "cron_before", after: "cron_after", operator: "LTE", expected: 2 }], [{ name: "cron_after", source: "JSON", path: "work" }])] },
    { id: "job-authorization", label: "job authorization", category: "JOB_AUTHORIZATION", authorization: observe, steps: [step("owner", "VERIFY", "owner", "job", request("GET", `${origin}/jobs/{{SECRET:job_id}}`, "account_a"), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "job", request("GET", `${origin}/jobs/{{SECRET:job_id}}`, "account_a"), decision("DENY"))] },
    { id: "incident-access", label: "incident access", category: "INCIDENT_ACCESS_CONTROL", authorization: observe, steps: [step("owner", "VERIFY", "owner", "incident", request("GET", `${origin}/incidents/{{SECRET:incident_id}}`, "account_a"), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "incident", request("GET", `${origin}/incidents/{{SECRET:incident_id}}`, "account_a"), decision("DENY"))] },
    { id: "health-exposure", label: "health exposure", category: "HEALTH_INFORMATION_EXPOSURE", authorization: observe, steps: [step("public", "VERIFY", "public", "health", request("GET", `${origin}/health`), [{ kind: "JSON_FIELD_ABSENT", path: "databaseUrl", classification: "SECRET" }])] },
    { id: "admin-worker-authorization", label: "admin worker authorization", category: "ADMIN_WORKER_AUTHORIZATION", authorization: observe, steps: [step("service", "VERIFY", "service", "admin", request("GET", `${origin}/admin/workers`), decision("ALLOW")), step("foreign", "VERIFY", "foreign", "admin", request("GET", `${origin}/admin/workers`), decision("DENY"))] }
  ];
  return { schemaVersion: 1, maxCases: 20, maxStepsPerCase: 8, maxRequests: 40, maxResponseBytes: 65536, actors, endpoints, cases };
}

function primarySecrets(): Record<string, string> { return { webhook_secret: webhookKey, webhook_timestamp: webhookTimestamp, signature_event: "event-signature-private", replay_event: "event-replay-private", idempotency_event: "event-idempotency-private", new_event: "event-new-private", old_event: "event-old-private", payload_event: "event-payload-private", expected_order_status: "latest-private", old_order_status: "stale-private", expected_amount: "1250", expected_currency: "USD", expected_product: "expected-product-private", baseline_product: "baseline", cron_nonce: "cron-nonce-private" }; }
function profile(principalId: string, tenantId: string, token: string, lifecycleSecrets: Record<string, string>): unknown { return { label: principalId, safeAlias: principalId, principalId, tenantId, headers: { Authorization: `Bearer ${token}` }, cookies: [], lifecycleSecrets, notes: [] }; }
function validSignature(request: IncomingMessage, raw: string): boolean { const supplied = String(request.headers["x-webhook-signature"] ?? ""); const expected = `sha256=${createHmac("sha256", webhookKey).update(`${webhookTimestamp}.${raw}`).digest("hex")}`; const left = Buffer.from(supplied); const right = Buffer.from(expected); return String(request.headers["x-webhook-timestamp"] ?? "") === webhookTimestamp && left.length === right.length && timingSafeEqual(left, right); }
function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); }
async function body(request: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks).toString("utf8"); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, JSON.stringify(value)); return path; }
