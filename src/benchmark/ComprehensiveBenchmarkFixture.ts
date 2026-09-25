import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface ComprehensiveBenchmarkTarget {
  origin: string;
  requestCount(): number;
  reset(): void;
  close(): Promise<void>;
}

/** Process-owned target containing paired vulnerable and secure controls. */
export async function startComprehensiveBenchmarkTarget(): Promise<ComprehensiveBenchmarkTarget> {
  let requests = 0;
  const races = { vulnerable: { used: false, events: 0 }, secure: { used: false, events: 0 } };
  const sessions = new Set<string>();
  const server = createServer((request, response) => { void handle(request, response).catch(() => json(response, 400, { error: "invalid_fixture_request" })); });
  server.on("upgrade", (_request, socket) => socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    requests += 1;
    if (requests > 5000) return json(response, 429, { error: "fixture_request_ceiling" });
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const method = request.method ?? "GET";
    const authorization = String(request.headers.authorization ?? "");
    response.setHeader("cache-control", "no-store");

    if (url.pathname === "/") return html(response, '<a href="/login">Sign in</a><script src="/app.js"></script>');
    if (url.pathname === "/app.js") return javascript(response, 'window.SUPABASE_SERVICE_ROLE_KEY="sb_secret_benchmark_server_only_123456789";');
    if (url.pathname === "/login" && method === "GET") return html(response, '<form action="/api/session" method="post"><input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form>');
    if (url.pathname === "/api/session" && method === "POST") {
      const fields = new URLSearchParams(await body(request));
      if (fields.get("username") !== "browser@benchmark.test" || fields.get("password") !== "browser-password") return json(response, 401, { error: "invalid_credentials" });
      const session = `benchmark-session-${sessions.size + 1}`; sessions.add(session);
      response.writeHead(303, { location: "/app", "set-cookie": `benchmark_session=${session}; HttpOnly; SameSite=Strict; Path=/` }).end(); return;
    }
    if (url.pathname === "/api/logout" && method === "POST") { sessions.clear(); response.writeHead(204).end(); return; }
    if (url.pathname === "/app") {
      const session = cookie(request, "benchmark_session");
      return session && sessions.has(session) ? html(response, '<span id="principal">browser-benchmark-user</span><script src="/app.js"></script>') : json(response, 401, { error: "authentication_required" });
    }
    if (url.pathname === "/me") return json(response, 200, identity(authorization));

    if (url.pathname === "/object/vulnerable") return json(response, 200, { id: "tenant-a-object", tenantId: "tenant-a" });
    if (url.pathname === "/object/secure") return void response.writeHead(403).end();
    if (url.pathname === "/admin/vulnerable") return json(response, 200, { privileged: true });
    if (url.pathname === "/admin/secure") return void response.writeHead(403).end();
    if (url.pathname === "/search/vulnerable") return url.search.includes("%27") || url.search.includes("'") ? json(response, 500, { error: "SQL syntax error near query" }) : json(response, 200, { matches: [] });
    if (url.pathname === "/search/secure") return json(response, 200, { matches: [] });
    if (url.pathname === "/redirect/vulnerable") { response.writeHead(302, { location: url.searchParams.get("next") ?? "/home" }).end(); return; }
    if (url.pathname === "/redirect/secure") { response.writeHead(302, { location: "/home" }).end(); return; }

    const protocol = /^\/protocol\/(?<kind>sse|multipart|graphql)\/(?<control>vulnerable|secure)$/.exec(url.pathname);
    if (protocol?.groups?.kind === "sse") {
      if (protocol.groups.control === "secure") return void response.writeHead(403).end();
      response.writeHead(200, { "content-type": "text/event-stream" }).end("event: ready\ndata: {\"ok\":true}\n\n"); return;
    }
    if (protocol?.groups?.kind === "multipart" && method === "POST") {
      await rawBody(request); return protocol.groups.control === "secure" ? void response.writeHead(403).end() : json(response, 200, { accepted: true });
    }
    if (protocol?.groups?.kind === "graphql" && method === "POST") {
      await body(request); return protocol.groups.control === "secure" ? void response.writeHead(403).end() : json(response, 200, { data: { updateFixture: { ok: true } } });
    }
    if (url.pathname.startsWith("/protocol/graphql/reset/") && method === "POST") { response.writeHead(204).end(); return; }

    const supabase = /^\/(?:rest\/v1\/documents|storage\/v1\/object\/private-files\/document-a|rest\/v1\/rpc\/tenant_stats)\/(?<control>vulnerable|secure)$/.exec(url.pathname);
    if (supabase?.groups?.control) {
      const vulnerable = supabase.groups.control === "vulnerable";
      if (url.pathname.startsWith("/rest/v1/documents")) return json(response, 200, vulnerable ? [{ id: "document-a", tenant_id: "tenant-a" }] : []);
      if (!vulnerable) return void response.writeHead(403).end();
      return json(response, 200, url.pathname.includes("storage") ? { id: "document-a" } : { tenantId: "tenant-a", count: 1 });
    }

    const lifecycle = /^\/auth\/(?<control>vulnerable|secure)\/login$/.exec(url.pathname);
    if (lifecycle?.groups?.control && method === "POST") {
      const fields = parseBody(await body(request), request.headers["content-type"]); const known = fields.username === "known@benchmark.test";
      if (lifecycle.groups.control === "vulnerable" && !known) return json(response, 404, { error: "account_not_found", recovery: true });
      return json(response, 401, { error: "invalid_credentials" });
    }
    if (/^\/auth\/(?:vulnerable|secure)\/cleanup$/.test(url.pathname) && method === "POST") { response.writeHead(204).end(); return; }

    const signed = /^\/signed\/(?<control>vulnerable|secure)\/expired$/.exec(url.pathname);
    if (signed?.groups?.control) return signed.groups.control === "secure" ? void response.writeHead(403).end() : json(response, 200, { document: "expired-but-readable" });

    const premium = /^\/premium\/(?<control>vulnerable|secure)$/.exec(url.pathname);
    if (premium?.groups?.control) {
      const owner = authorization === "Bearer benchmark-a";
      if (!owner && premium.groups.control === "secure") return json(response, 403, { access: false });
      return json(response, 200, { access: true });
    }

    const race = /^\/race\/(?<control>vulnerable|secure)\/(?<operation>state|redeem|reset)$/.exec(url.pathname);
    if (race?.groups?.control && race.groups.operation) {
      const state = races[race.groups.control as "vulnerable" | "secure"];
      if (race.groups.operation === "state" && method === "GET") return json(response, 200, state);
      if (race.groups.operation === "reset" && method === "DELETE") { state.used = false; state.events = 0; response.writeHead(204).end(); return; }
      if (race.groups.operation === "redeem" && method === "POST") {
        await body(request);
        if (state.used) return json(response, 409, { accepted: false });
        if (race.groups.control === "secure") state.used = true;
        await delay(30);
        state.used = true; state.events += 1; return json(response, 200, { accepted: true });
      }
    }
    response.writeHead(404).end();
  }

  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); }); });
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const reset = () => { sessions.clear(); for (const state of Object.values(races)) { state.used = false; state.events = 0; } };
  return { origin, requestCount: () => requests, reset, close: async () => { reset(); server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); } };
}

export function comprehensiveBenchmarkInputs(origin: string) {
  const authorization = { environment: "LOCAL", operator: "benchmark-operator", ticket: "BENCHMARK-PROTOCOL", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES", disposableResources: true };
  const protocolExpectation = (decision: "ALLOW" | "DENY") => ({ decision, allowedStatuses: [200, 201, 202, 204], deniedStatuses: [400, 401, 403, 404], minMessages: 0 });
  const protocolCases: unknown[] = [];
  for (const control of ["vulnerable", "secure"] as const) {
    protocolCases.push({ id: `protocol-sse-${control}`, label: `SSE ${control} denial`, kind: "SSE", actorId: "anonymous", requireVerifiedIdentity: false, url: `${origin}/protocol/sse/${control}`, headers: {}, method: "GET", maxEvents: 1, expectation: { ...protocolExpectation("DENY"), messageType: "ready" } });
    protocolCases.push({ id: `protocol-multipart-${control}`, label: `Multipart ${control} denial`, kind: "MULTIPART_UPLOAD", actorId: "member", requireVerifiedIdentity: false, url: `${origin}/protocol/multipart/${control}`, headers: {}, fields: { purpose: "benchmark" }, files: [{ fieldName: "file", fileName: "fixture.bin", contentType: "application/octet-stream", contentSecretRef: "upload_fixture" }], readOnly: true, expectation: protocolExpectation("DENY") });
    protocolCases.push({ id: `protocol-graphql-${control}`, label: `GraphQL mutation ${control} denial`, kind: "GRAPHQL_MUTATION", actorId: "anonymous", requireVerifiedIdentity: false, url: `${origin}/protocol/graphql/${control}`, headers: {}, operationName: "UpdateFixture", document: "mutation UpdateFixture { updateFixture { ok } }", variables: {}, authorization, cleanup: { url: `${origin}/protocol/graphql/reset/${control}`, method: "POST", headers: {}, statusIn: [204] }, expectation: { ...protocolExpectation("DENY"), jsonPath: "data.updateFixture.ok", equals: true } });
  }
  const supabaseCases = (["TABLE", "STORAGE", "RPC"] as const).flatMap((surface) => (["vulnerable", "secure"] as const).map((control) => {
    const id = `supabase-${surface.toLowerCase()}-${control}`;
    const path = surface === "TABLE" ? `/rest/v1/documents/${control}` : surface === "STORAGE" ? `/storage/v1/object/private-files/document-a/${control}` : `/rest/v1/rpc/tenant_stats/${control}`;
    return { id, surface, resource: surface === "TABLE" ? "public.documents" : surface === "STORAGE" ? "private-files" : "public.tenant_stats", operation: surface === "RPC" ? "INVOKE" : "SELECT", actor: "ACCOUNT_B", expectedDecision: "DENY", boundary: "CROSS_TENANT", method: "GET", url: `${origin}${path}`, responseShape: surface === "TABLE" ? "LIST" : "SINGLE", identityAssertions: surface === "RPC" ? [{ path: "tenantId", equals: "tenant-a" }] : [{ path: "id", equals: "document-a" }], requireVerifiedIdentity: false };
  }));
  const lifecycleAuthorization = { mode: "CONTROLLED_LIFECYCLE", environment: "LOCAL", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "benchmark-operator", changeTicket: "BENCHMARK-AUTH", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), disposableAccounts: true };
  const lifecycleCases = (["vulnerable", "secure"] as const).map((control) => ({ id: `auth-enumeration-${control}`, label: `Login enumeration ${control} control`, category: "LOGIN_ENUMERATION_RESISTANCE", actors: [{ id: "member", safeAlias: "benchmark-member", authSlot: "primary", relationship: "SELF", declaredState: "ACTIVE" }], authorization: lifecycleAuthorization, cleanupRequired: true, steps: [{ id: "known", phase: "ACTION", actorId: "member", request: { method: "POST", url: `${origin}/auth/${control}/login`, stateChanging: true, fields: { username: "{{SECRET:known_username}}", password: "{{SECRET:password}}" } }, assertions: [{ kind: "STATUS_IN", values: [401] }] }, { id: "unknown", phase: "VERIFY", actorId: "member", request: { method: "POST", url: `${origin}/auth/${control}/login`, stateChanging: true, fields: { username: "{{SECRET:unknown_username}}", password: "{{SECRET:password}}" } }, assertions: [{ kind: "RESPONSE_SIMILAR", stepId: "known", compareStatus: true, compareShape: true, compareBodyDigest: false, maxLengthDelta: 8 }] }, { id: "cleanup", phase: "CLEANUP", actorId: "member", request: { method: "POST", url: `${origin}/auth/${control}/cleanup`, stateChanging: true }, assertions: [{ kind: "STATUS_IN", values: [204] }] }] }));
  const linkActors = [{ id: "anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" }];
  const linkResources = (["vulnerable", "secure"] as const).map((control) => ({ id: `signed-${control}`, safeAlias: `signed-${control}`, kind: "SIGNED_LINK", pathTemplate: `/signed/${control}/{object}`, allowedOrigins: [origin] }));
  const linkCases = (["vulnerable", "secure"] as const).map((control) => ({ id: `signed-expiry-${control}`, label: `Signed-link expiry ${control} control`, category: "SIGNED_LINK_EXPIRY", authorization: { mode: "OBSERVE_ONLY", environment: "LOCAL" }, steps: [{ id: "expired", phase: "VERIFY", actorId: "anonymous", resourceId: `signed-${control}`, request: { method: "GET", urlTemplate: `${origin}/signed/${control}/expired`, secretSource: "anonymous" }, assertions: [{ kind: "DECISION", expected: "DENY" }] }] }));
  const billingActors = [{ id: "owner", safeAlias: "owner", authSlot: "account_a", relationship: "OWNER", principalId: "account-a", tenantId: "tenant-a" }, { id: "foreign", safeAlias: "foreign", authSlot: "account_b", relationship: "CROSS_TENANT", principalId: "account-b", tenantId: "tenant-b" }];
  const billingEndpoints = (["vulnerable", "secure"] as const).map((control) => ({ id: `premium-${control}`, safeAlias: `premium-${control}`, kind: "PREMIUM_ACCESS", pathTemplate: `/premium/${control}`, allowedOrigins: [origin] }));
  const billingCases = (["vulnerable", "secure"] as const).map((control) => ({ id: `billing-premium-${control}`, label: `Premium authorization ${control} control`, category: "CROSS_ACCOUNT_PREMIUM_ACCESS", authorization: { mode: "OBSERVE_ONLY", environment: "LOCAL" }, steps: [{ id: "owner", phase: "ACTION", actorId: "owner", endpointId: `premium-${control}`, operation: "PREMIUM_ACCESS_PROBE", request: { method: "GET", urlTemplate: `${origin}/premium/${control}`, secretSource: "anonymous" }, expectation: { authorization: "ALLOW", businessRule: "NOT_EVALUATED" } }, { id: "foreign", phase: "ACTION", actorId: "foreign", endpointId: `premium-${control}`, operation: "PREMIUM_ACCESS_PROBE", request: { method: "GET", urlTemplate: `${origin}/premium/${control}`, secretSource: "anonymous" }, expectation: { authorization: "DENY", businessRule: "NOT_EVALUATED" } }], assertions: [{ id: "foreign-denied", scope: "MAIN", kind: "ACTION_OUTCOME_COUNT", dimension: "ACCESS", stepId: "foreign", outcome: "DENIED", operator: "EQ", expected: 1 }] }));
  return {
    protocol: { schemaVersion: 1, maxRequests: 12, maxDurationMs: 5000, actors: [{ id: "anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" }, { id: "member", safeAlias: "benchmark-member", authSlot: "primary", relationship: "SELF" }], cases: protocolCases },
    supabase: { schemaVersion: 1, projectUrl: origin, anonKeyEnv: "ROUTECAIRN_BENCHMARK_SUPABASE_ANON", cases: supabaseCases, catalog: { exposedSchemas: ["public"], expectedExposedSchemas: ["public"], tables: [{ schema: "public", name: "documents", exposed: true, rlsEnabled: true, rlsForced: true, ownerColumn: "owner_id", tenantColumn: "tenant_id" }], functions: [{ schema: "public", name: "tenant_stats", exposed: true, securityDefiner: false, executableBy: ["authenticated"], searchPath: ["public"], usesDynamicSql: false }], storageBuckets: [{ name: "private-files", public: false, ownershipEnforced: true }] } },
    lifecycle: { schemaVersion: 1, maxRequests: 12, cases: lifecycleCases },
    links: { schemaVersion: 1, maxCases: 4, maxStepsPerCase: 4, maxRequests: 4, actors: linkActors, resources: linkResources, cases: linkCases },
    billing: { schemaVersion: 1, maxCases: 4, maxRequests: 8, maxConcurrency: 2, provider: { kind: "CUSTOM_SYNTHETIC", mode: "TEST", fixturePathPrefix: "/__routecairn__/billing-fixtures", realPaymentExecution: "FORBIDDEN" }, actors: billingActors, endpoints: billingEndpoints, cases: billingCases },
    races: { schemaVersion: 1, maxRequests: 30, maxConcurrency: 5, cases: (["vulnerable", "secure"] as const).map((control, index) => raceCase(origin, control, String(index + 1))) }
  };
}

export function benchmarkAuthProfiles(origin: string) {
  return {
    primary: { label: "benchmark-primary", safeAlias: "benchmark-primary", headers: { Authorization: "Bearer benchmark-primary" }, lifecycleSecrets: { known_username: "known@benchmark.test", unknown_username: "unknown@benchmark.test", password: "benchmark-password", upload_fixture: "base64:AP8B", race_token: "benchmark-one-time-token" } },
    accountA: { label: "benchmark-account-a", safeAlias: "benchmark-a", principalId: "account-a", tenantId: "tenant-a", headers: { Authorization: "Bearer benchmark-a" }, identityVerification: { mode: "disabled" } },
    accountB: { label: "benchmark-account-b", safeAlias: "benchmark-b", principalId: "account-b", tenantId: "tenant-b", headers: { Authorization: "Bearer benchmark-b" }, identityVerification: { mode: "disabled" } },
    browser: { label: "benchmark-browser", safeAlias: "benchmark-browser", principalId: "browser-benchmark-user", headers: {}, cookies: [], identityVerification: { mode: "disabled" }, browserBootstrap: { schemaVersion: 1, loginSecrets: { username: "browser@benchmark.test", password: "browser-password" }, login: { startUrl: `${origin}/login`, allowedWritePaths: ["/api/session"], successUrlPrefix: `${origin}/app`, steps: [{ action: "fill", selector: "input[name=username]", valueRef: "username" }, { action: "fill", selector: "input[name=password]", valueRef: "password" }, { action: "click", selector: "button[type=submit]" }, { action: "waitForUrl", urlPrefix: `${origin}/app` }] }, identitySelectors: { principal: "#principal" }, journeys: [], proofCases: [] } }
  };
}

function raceCase(origin: string, control: "vulnerable" | "secure", fingerprint: string) {
  const authorization = { mode: "CONTROLLED_RACE", environment: "LOCAL", confirmation: "I_AUTHORIZE_CONTROLLED_RACE_TESTING", authorizedBy: "benchmark-operator", changeTicket: "BENCHMARK-RACE", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), disposableEntities: true };
  const actor = { id: "member", safeAlias: "benchmark-member", authSlot: "primary", relationship: "SELF", declaredState: "ACTIVE" };
  const observe = (id: string, name: string) => ({ id, actorId: "member", request: { method: "GET", url: `${origin}/race/${control}/state`, stateChanging: false }, captures: [{ name, source: "JSON", path: "events" }] });
  const redeem = (id: string) => ({ id, actorId: "member", request: { method: "POST", url: `${origin}/race/${control}/redeem`, stateChanging: true, bodyFormat: "JSON", fields: { token: "{{SECRET:race_token}}" } }, expectation: { authorization: "ALLOW", businessRule: "NOT_EVALUATED" } });
  return { id: `race-${control}`, label: `One-time token race ${control} control`, category: "ONE_TIME_TOKEN", target: { type: "one-time-token", safeAlias: `${control}-token`, identityFingerprint: fingerprint.repeat(64), disposable: true }, actors: [actor], authorization, preState: [observe("before", `${control}_before`)], groups: [{ id: "redeem", label: "Two synchronized redemptions", synchronization: "READY_BARRIER", maxDispatchSkewMs: 100, requests: [redeem("redeem-a"), redeem("redeem-b")] }], postState: [observe("after", `${control}_after`)], invariants: [{ id: "one-event", kind: "EVENT_COUNT_DELTA", before: `${control}_before`, after: `${control}_after`, operator: "LTE", expected: 1 }, { id: "one-accepted", kind: "GROUP_OUTCOME_COUNT", groupId: "redeem", outcome: "ACCEPTED", operator: "LTE", expected: 1 }], cleanupRequired: true, cleanup: [{ id: "reset", actorId: "member", request: { method: "DELETE", url: `${origin}/race/${control}/reset`, stateChanging: true }, successStatusCodes: [204] }], cleanupVerification: [observe("restored", `${control}_restored`)], cleanupInvariants: [{ id: "restored", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: `${control}_restored` }, operator: "EQ", right: { source: "CAPTURE", ref: `${control}_before` } }] };
}

function identity(authorization: string): { id: string; tenantId: string } { return authorization === "Bearer benchmark-a" ? { id: "account-a", tenantId: "tenant-a" } : authorization === "Bearer benchmark-b" ? { id: "account-b", tenantId: "tenant-b" } : { id: "benchmark-primary", tenantId: "benchmark" }; }
function cookie(request: IncomingMessage, name: string): string | undefined { return String(request.headers.cookie ?? "").split(";").map((value) => value.trim()).find((value) => value.startsWith(`${name}=`))?.slice(name.length + 1); }
function parseBody(raw: string, contentType: string | string[] | undefined): Record<string, string> { if (String(contentType).includes("json")) { try { return JSON.parse(raw) as Record<string, string>; } catch { return {}; } } return Object.fromEntries(new URLSearchParams(raw)); }
async function body(request: IncomingMessage): Promise<string> { return (await rawBody(request)).toString("utf8"); }
async function rawBody(request: IncomingMessage): Promise<Buffer> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of request) { const value = Buffer.from(chunk); size += value.length; if (size > 256 * 1024) throw new Error("fixture_body_too_large"); chunks.push(value); } return Buffer.concat(chunks); }
function json(response: ServerResponse, status: number, value: unknown): void { if (response.writableEnded) return; response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); }
function html(response: ServerResponse, value: string): void { response.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><html><body>${value}</body></html>`); }
function javascript(response: ServerResponse, value: string): void { response.writeHead(200, { "content-type": "application/javascript" }).end(value); }
function delay(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }
