import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { OidcTestHarness } from "../modules/authenticationLifecycle/AuthenticationFixtures.js";
import { resolveTurnkeyAuthRequest, type TurnkeyAuthAdapterConfig, type TurnkeyAuthOperation, type TurnkeyAuthProvider } from "../modules/authenticationLifecycle/TurnkeyAuthProviderAdapters.js";
import { VirtualWebAuthnManager } from "../modules/browserCrawler/VirtualWebAuthnManager.js";

export interface AuthenticationFixtureAcceptanceSummary {
  schemaVersion: 1;
  status: "PASSED" | "FAILED";
  generatedAt: string;
  providers: Array<{ provider: TurnkeyAuthProvider; status: "PASSED" | "FAILED"; operations: TurnkeyAuthOperation[]; requests: number; reason?: string }>;
  oidc: { status: "PASSED" | "FAILED"; discovery: boolean; callback: boolean; pkce: boolean; idToken: boolean; replay: boolean; reason?: string };
  passkey: { status: "PASSED" | "FAILED"; enrollment: boolean; login: boolean; signatureVerified: boolean; cleanup: boolean; reason?: string };
  totalRequests: number;
  evidenceSha256: string;
  outputDirectory: string;
}

type Json = Record<string, unknown>;

export async function runAuthenticationFixtureAcceptance(parentDirectory = ".routecairn-authentication-acceptance"): Promise<AuthenticationFixtureAcceptanceSummary> {
  const parent = resolve(parentDirectory);
  await mkdir(parent, { recursive: true });
  const outputDirectory = await mkdtemp(resolve(parent, "run-"));
  const emulator = new AuthenticationProviderEmulator();
  const started = await emulator.start();
  const providers: AuthenticationFixtureAcceptanceSummary["providers"] = [];
  let oidc: AuthenticationFixtureAcceptanceSummary["oidc"] = { status: "FAILED", discovery: false, callback: false, pkce: false, idToken: false, replay: false, reason: "NOT_RUN" };
  let passkey: AuthenticationFixtureAcceptanceSummary["passkey"] = { status: "FAILED", enrollment: false, login: false, signatureVerified: false, cleanup: false, reason: "NOT_RUN" };
  try {
    for (const definition of providerDefinitions(started.origin)) {
      const before = emulator.requestCount;
      try {
        const operations = await executeProviderLifecycle(definition.config, definition.operations, definition.secrets);
        providers.push({ provider: definition.config.provider, status: "PASSED", operations, requests: emulator.requestCount - before });
      } catch (error) {
        providers.push({ provider: definition.config.provider, status: "FAILED", operations: [], requests: emulator.requestCount - before, reason: safeReason(error) });
      }
    }
    oidc = await validateOidcLifecycle();
    passkey = await emulator.validatePasskeyBrowserLifecycle();
  } finally {
    await emulator.close();
  }
  const status: AuthenticationFixtureAcceptanceSummary["status"] = providers.every((item) => item.status === "PASSED") && oidc.status === "PASSED" && passkey.status === "PASSED" ? "PASSED" : "FAILED";
  const core = { schemaVersion: 1 as const, status, generatedAt: new Date().toISOString(), providers, oidc, passkey, totalRequests: emulator.requestCount };
  const evidenceSha256 = createHash("sha256").update(JSON.stringify(core)).digest("hex");
  const summary: AuthenticationFixtureAcceptanceSummary = { ...core, evidenceSha256, outputDirectory };
  await writeFile(resolve(outputDirectory, "authentication-fixture-acceptance.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await writeFile(resolve(outputDirectory, "authentication-fixture-acceptance.md"), markdown(summary), "utf8");
  return summary;
}

interface ProviderDefinition { config: TurnkeyAuthAdapterConfig; operations: Array<{ operation: TurnkeyAuthOperation; fields: Json }>; secrets: Record<string, string> }

function providerDefinitions(origin: string): ProviderDefinition[] {
  const common = { email: "fixture-user@example.test", password: "Fixture-password-42!", refresh_token: "{{CAPTURE:refresh_token}}", access_token: "{{CAPTURE:access_token}}" };
  return [
    { config: { id: "auth0", provider: "AUTH0", baseUrl: `${origin}/auth0`, managementTokenSecretRef: "management" }, secrets: { management: "auth0-management-secret" }, operations: [
      { operation: "SIGN_UP", fields: { email: common.email, password: common.password, connection: "Username-Password-Authentication" } },
      { operation: "SIGN_IN_PASSWORD", fields: { grant_type: "password", username: common.email, password: common.password } },
      { operation: "REFRESH_TOKEN", fields: { grant_type: "refresh_token", refresh_token: common.refresh_token } },
      { operation: "SIGN_OUT", fields: {} }, { operation: "DELETE_USER", fields: { userId: "{{CAPTURE:user_id}}" } }
    ] },
    { config: { id: "cognito", provider: "COGNITO", baseUrl: `${origin}/cognito`, cognitoMode: "USER_POOLS_API" }, secrets: {}, operations: [
      { operation: "SIGN_UP", fields: { Username: common.email, Password: common.password } },
      { operation: "SIGN_IN_PASSWORD", fields: { AuthFlow: "USER_PASSWORD_AUTH", AuthParameters: { USERNAME: common.email, PASSWORD: common.password } } },
      { operation: "REFRESH_TOKEN", fields: { AuthFlow: "REFRESH_TOKEN_AUTH", AuthParameters: { REFRESH_TOKEN: common.refresh_token } } },
      { operation: "SIGN_OUT", fields: { AccessToken: common.access_token } }, { operation: "DELETE_USER", fields: { AccessToken: common.access_token } }
    ] },
    { config: { id: "clerk", provider: "CLERK", baseUrl: `${origin}/clerk`, serviceKeySecretRef: "service" }, secrets: { service: "clerk-service-secret" }, operations: [
      { operation: "SIGN_UP", fields: { email_address: [common.email], password: common.password } },
      { operation: "SIGN_IN_PASSWORD", fields: { user_id: "{{CAPTURE:user_id}}" } },
      { operation: "SIGN_OUT", fields: { sessionId: "{{CAPTURE:session_id}}" } }, { operation: "DELETE_USER", fields: { userId: "{{CAPTURE:user_id}}" } }
    ] },
    { config: { id: "firebase", provider: "FIREBASE", baseUrl: `${origin}/firebase`, tokenBaseUrl: `${origin}/firebase-token`, apiKeySecretRef: "api_key" }, secrets: { api_key: "firebase-emulator-key" }, operations: [
      { operation: "SIGN_UP", fields: { email: common.email, password: common.password, returnSecureToken: true } },
      { operation: "SIGN_IN_PASSWORD", fields: { email: common.email, password: common.password, returnSecureToken: true } },
      { operation: "REFRESH_TOKEN", fields: { grant_type: "refresh_token", refresh_token: common.refresh_token } },
      { operation: "DELETE_USER", fields: { idToken: "{{CAPTURE:id_token}}" } }
    ] },
    { config: { id: "supabase", provider: "SUPABASE_AUTH", baseUrl: `${origin}/supabase`, apiKeySecretRef: "anon", serviceKeySecretRef: "service" }, secrets: { anon: "supabase-anon-key", service: "supabase-service-key" }, operations: [
      { operation: "SIGN_UP", fields: { email: common.email, password: common.password } },
      { operation: "SIGN_IN_PASSWORD", fields: { email: common.email, password: common.password } },
      { operation: "REFRESH_TOKEN", fields: { refresh_token: common.refresh_token } },
      { operation: "SIGN_OUT", fields: {} }, { operation: "DELETE_USER", fields: { userId: "{{CAPTURE:user_id}}" } }
    ] }
  ];
}

async function executeProviderLifecycle(config: TurnkeyAuthAdapterConfig, calls: Array<{ operation: TurnkeyAuthOperation; fields: Json }>, secrets: Record<string, string>): Promise<TurnkeyAuthOperation[]> {
  const captures = new Map<string, string>();
  const executed: TurnkeyAuthOperation[] = [];
  for (const call of calls) {
    const template = resolveTurnkeyAuthRequest(config, call.operation, call.fields);
    const url = expandUrl(String(template.url), secrets, captures);
    const headers = Object.fromEntries(Object.entries(template.headers).map(([name, value]) => [name, expand(value, secrets, captures)]));
    const fields = expandValue(template.fields ?? {}, secrets, captures) as Json;
    let body: string | undefined;
    if (template.bodyFormat === "FORM") { body = new URLSearchParams(Object.entries(fields).map(([key, value]) => [key, String(value)] as [string, string])).toString(); headers[headerName(headers, "content-type") ?? "Content-Type"] = "application/x-www-form-urlencoded"; }
    else if (template.bodyFormat === "JSON") { body = JSON.stringify(fields); headers[headerName(headers, "content-type") ?? "Content-Type"] = "application/json"; }
    const response = await fetch(url, { method: template.method, headers, ...(body !== undefined ? { body } : {}), redirect: "manual" });
    const payload = await boundedJson(response);
    if (!response.ok) throw new Error(`${config.provider}_${call.operation}_HTTP_${response.status}`);
    for (const [name, path] of Object.entries(template.suggestedCaptures)) {
      const value = valueAt(payload, path);
      if (typeof value === "string" && value) captures.set(name, value);
    }
    executed.push(call.operation);
  }
  return executed;
}

async function validateOidcLifecycle(): Promise<AuthenticationFixtureAcceptanceSummary["oidc"]> {
  const harness = new OidcTestHarness({ clientId: "routecairn-acceptance-client", clientSecret: "routecairn-acceptance-secret", redirectUris: ["http://127.0.0.1/callback-placeholder"], subject: "fixture-subject", claims: { email_verified: true } });
  try {
    const flow = await harness.completeAuthorizationCodeFlow({ state: randomBytes(24).toString("base64url"), nonce: randomBytes(24).toString("base64url"), codeVerifier: randomBytes(48).toString("base64url") });
    return { status: "PASSED", discovery: flow.discoveryValidated, callback: flow.callbackValidated, pkce: flow.pkceValidated, idToken: flow.idTokenValidated, replay: flow.replayRejected };
  } catch (error) { return { status: "FAILED", discovery: false, callback: false, pkce: false, idToken: false, replay: false, reason: safeReason(error) }; }
  finally { await harness.close(); }
}

export class AuthenticationProviderEmulator {
  private server: Server | undefined;
  private origin = "";
  private readonly passkeyChallenge = randomBytes(32);
  private passkey: { id: Buffer; publicKey: ReturnType<typeof createPublicKey>; signCount: number } | undefined;
  private signatureVerified = false;
  private passkeyError: unknown;
  public requestCount = 0;

  public async start(): Promise<{ origin: string }> {
    this.server = createServer((request, response) => { void this.handle(request, response); });
    await new Promise<void>((resolve, reject) => { this.server!.once("error", reject); this.server!.listen(0, "127.0.0.1", () => { this.server!.off("error", reject); resolve(); }); });
    this.origin = `http://localhost:${(this.server.address() as AddressInfo).port}`;
    return { origin: this.origin };
  }

  public async validatePasskeyBrowserLifecycle(): Promise<AuthenticationFixtureAcceptanceSummary["passkey"]> {
    const manager = new VirtualWebAuthnManager();
    try {
      await manager.create("acceptance", { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true });
      await manager.runBrowserFlow({ startUrl: `${this.origin}/passkey/enroll`, steps: [{ action: "click", selector: "#enroll" }, { action: "assertVisible", selector: "#enrolled" }] });
      const credentials = await manager.credentials("acceptance");
      if (credentials.length !== 1 || !this.passkey) throw new Error("PASSKEY_ENROLLMENT_FAILED");
      await manager.runBrowserFlow({ startUrl: `${this.origin}/passkey/login`, clearCookies: true, steps: [{ action: "click", selector: "#login" }, { action: "waitForUrl", urlPrefix: `${this.origin}/passkey/account` }, { action: "assertVisible", selector: "#authenticated" }] });
      await manager.runBrowserFlow({ startUrl: `${this.origin}/passkey/manage`, steps: [{ action: "click", selector: "#remove" }, { action: "assertVisible", selector: "#removed" }] });
      await manager.clear("acceptance");
      if (this.passkey || (await manager.credentials("acceptance")).length) throw new Error("PASSKEY_CLEANUP_FAILED");
      return { status: "PASSED", enrollment: true, login: true, signatureVerified: this.signatureVerified, cleanup: true };
    } catch (error) { return { status: "FAILED", enrollment: Boolean(this.passkey), login: this.signatureVerified, signatureVerified: this.signatureVerified, cleanup: false, reason: safeReason(this.passkeyError ?? error) }; }
    finally { await manager.close(); }
  }

  public async close(): Promise<void> { const server = this.server; this.server = undefined; if (server) await new Promise<void>((resolve) => server.close(() => resolve())); }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    this.requestCount += 1;
    const url = new URL(request.url ?? "/", this.origin || "http://127.0.0.1");
    try {
      if (url.pathname.startsWith("/passkey/")) return await this.handlePasskey(request, response, url);
      const body = await requestBody(request);
      const jsonBody = request.headers["content-type"]?.includes("json") && body ? JSON.parse(body) as Json : Object.fromEntries(new URLSearchParams(body));
      if (url.pathname.startsWith("/auth0/")) return this.auth0(request, response, url, jsonBody);
      if (url.pathname.startsWith("/cognito")) return this.cognito(request, response, jsonBody);
      if (url.pathname.startsWith("/clerk/")) return this.clerk(request, response, url);
      if (url.pathname.startsWith("/firebase")) return this.firebase(response, url);
      if (url.pathname.startsWith("/supabase/")) return this.supabase(request, response, url);
      return json(response, 404, { error: "not_found" });
    } catch (error) { if (url.pathname.startsWith("/passkey/")) this.passkeyError = error; return json(response, 400, { error: "invalid_request" }); }
  }

  private auth0(request: IncomingMessage, response: ServerResponse, url: URL, body: Json): void {
    if (url.pathname.endsWith("/dbconnections/signup")) return json(response, 200, { _id: "auth0|fixture" });
    if (url.pathname.endsWith("/oauth/token")) return json(response, 200, { access_token: token("a0-access"), refresh_token: token("a0-refresh"), id_token: token("a0-id") });
    if (url.pathname.endsWith("/v2/logout")) return json(response, 200, { ok: true });
    if (request.method === "DELETE" && url.pathname.includes("/api/v2/users/") && request.headers.authorization === "Bearer auth0-management-secret") return json(response, 200, { deleted: true });
    return json(response, 400, { error: "unsupported", body: Object.keys(body).length });
  }

  private cognito(request: IncomingMessage, response: ServerResponse, _body: Json): void {
    const target = String(request.headers["x-amz-target"] ?? "").split(".").pop();
    if (target === "SignUp") return json(response, 200, { UserSub: "cognito-fixture" });
    if (target === "InitiateAuth") return json(response, 200, { AuthenticationResult: { AccessToken: token("cog-access"), RefreshToken: token("cog-refresh"), IdToken: token("cog-id") } });
    if (target === "GlobalSignOut" || target === "DeleteUser") return json(response, 200, {});
    return json(response, 400, { error: "unsupported" });
  }

  private clerk(request: IncomingMessage, response: ServerResponse, url: URL): void {
    if (request.headers.authorization !== "Bearer clerk-service-secret") return json(response, 401, { error: "unauthorized" });
    if (request.method === "POST" && url.pathname.endsWith("/v1/users")) return json(response, 200, { id: "user_clerk_fixture" });
    if (request.method === "POST" && url.pathname.endsWith("/v1/sessions")) return json(response, 200, { id: "sess_clerk_fixture" });
    if (request.method === "POST" && url.pathname.endsWith("/revoke")) return json(response, 200, { status: "revoked" });
    if (request.method === "DELETE" && url.pathname.includes("/v1/users/")) return json(response, 200, { deleted: true });
    return json(response, 400, { error: "unsupported" });
  }

  private firebase(response: ServerResponse, url: URL): void {
    if (url.searchParams.get("key") !== "firebase-emulator-key") return json(response, 401, { error: "invalid_key" });
    if (url.pathname.includes("accounts:signUp") || url.pathname.includes("accounts:signInWithPassword")) return json(response, 200, { localId: "firebase-fixture", idToken: token("fb-id"), refreshToken: token("fb-refresh") });
    if (url.pathname.endsWith("/v1/token")) return json(response, 200, { access_token: token("fb-access"), refresh_token: token("fb-refresh-2"), id_token: token("fb-id-2") });
    if (url.pathname.includes("accounts:delete")) return json(response, 200, {});
    return json(response, 400, { error: "unsupported" });
  }

  private supabase(request: IncomingMessage, response: ServerResponse, url: URL): void {
    if (request.headers.apikey !== "supabase-anon-key") return json(response, 401, { error: "unauthorized" });
    const admin = request.method === "DELETE" && url.pathname.includes("/auth/v1/admin/users/");
    const authorized = admin ? request.headers.authorization === "Bearer supabase-service-key" : ["Bearer supabase-anon-key", "Bearer sb-access-"].some((value) => String(request.headers.authorization ?? "").startsWith(value));
    if (!authorized) return json(response, 401, { error: "unauthorized" });
    if (url.pathname.endsWith("/auth/v1/signup") || url.pathname.endsWith("/auth/v1/token")) return json(response, 200, { user: { id: "supabase-fixture" }, access_token: token("sb-access"), refresh_token: token("sb-refresh") });
    if (url.pathname.endsWith("/auth/v1/logout")) return json(response, 204, undefined);
    if (request.method === "DELETE" && url.pathname.includes("/auth/v1/admin/users/")) return json(response, 200, { deleted: true });
    return json(response, 400, { error: "unsupported" });
  }

  private async handlePasskey(request: IncomingMessage, response: ServerResponse, url: URL): Promise<void> {
    const rpId = "localhost";
    if (request.method === "GET" && url.pathname === "/passkey/enroll") return html(response, passkeyEnrollmentHtml(this.origin, rpId, this.passkeyChallenge));
    if (request.method === "POST" && url.pathname === "/passkey/register") {
      const body = JSON.parse(await requestBody(request)) as Record<string, string>;
      const rawId = Buffer.from(body.rawId!, "base64url");
      const client = validateClientData(body.clientDataJSON!, "webauthn.create", this.passkeyChallenge, this.origin);
      void client;
      const attestation = decodeCbor(Buffer.from(body.attestationObject!, "base64url"));
      if (!(attestation instanceof Map) || !Buffer.isBuffer(attestation.get("authData"))) throw new Error("PASSKEY_ATTESTATION_INVALID");
      const parsed = parseRegistrationAuthData(attestation.get("authData") as Buffer, rpId);
      if (!safeBufferEqual(rawId, parsed.credentialId)) throw new Error("PASSKEY_CREDENTIAL_MISMATCH");
      this.passkey = { id: rawId, publicKey: parsed.publicKey, signCount: parsed.signCount };
      return json(response, 201, { registered: true });
    }
    if (request.method === "GET" && url.pathname === "/passkey/login") {
      if (!this.passkey) return json(response, 409, { error: "not_enrolled" });
      return html(response, passkeyLoginHtml(this.origin, rpId, this.passkeyChallenge, this.passkey.id));
    }
    if (request.method === "POST" && url.pathname === "/passkey/verify") {
      if (!this.passkey) return json(response, 409, { error: "not_enrolled" });
      const body = JSON.parse(await requestBody(request)) as Record<string, string>;
      const rawId = Buffer.from(body.rawId!, "base64url");
      if (!safeBufferEqual(rawId, this.passkey.id)) throw new Error("PASSKEY_CREDENTIAL_MISMATCH");
      const clientData = Buffer.from(body.clientDataJSON!, "base64url");
      validateClientData(body.clientDataJSON!, "webauthn.get", this.passkeyChallenge, this.origin);
      const authenticatorData = Buffer.from(body.authenticatorData!, "base64url");
      const parsed = parseAssertionAuthData(authenticatorData, rpId);
      const signed = Buffer.concat([authenticatorData, createHash("sha256").update(clientData).digest()]);
      if (!verify("sha256", signed, this.passkey.publicKey, Buffer.from(body.signature!, "base64url"))) throw new Error("PASSKEY_SIGNATURE_INVALID");
      if (parsed.signCount !== 0 && parsed.signCount <= this.passkey.signCount) throw new Error("PASSKEY_COUNTER_INVALID");
      this.passkey.signCount = parsed.signCount;
      this.signatureVerified = true;
      response.setHeader("set-cookie", "routecairn_passkey=authenticated; HttpOnly; SameSite=Strict");
      return json(response, 200, { authenticated: true });
    }
    if (request.method === "GET" && url.pathname === "/passkey/account") {
      if (!String(request.headers.cookie ?? "").includes("routecairn_passkey=authenticated")) return json(response, 401, { error: "unauthorized" });
      return html(response, '<!doctype html><div id="authenticated">Authenticated with passkey</div>');
    }
    if (request.method === "GET" && url.pathname === "/passkey/manage") {
      if (!String(request.headers.cookie ?? "").includes("routecairn_passkey=authenticated")) return json(response, 401, { error: "unauthorized" });
      return html(response, passkeyCleanupHtml(this.origin));
    }
    if (request.method === "DELETE" && url.pathname === "/passkey/credential") { this.passkey = undefined; return void response.writeHead(204).end(); }
    return json(response, 404, { error: "not_found" });
  }
}

function passkeyEnrollmentHtml(origin: string, rpId: string, challenge: Buffer): string { return `<!doctype html><button id="enroll">Enroll</button><div id="enrolled" hidden>Enrolled</div><script>${browserHelpers()}document.querySelector('#enroll').onclick=async()=>{const c=await navigator.credentials.create({publicKey:{challenge:dec('${challenge.toString("base64url")}'),rp:{name:'RouteCairn',id:'${rpId}'},user:{id:dec('Zml4dHVyZS11c2Vy'),name:'fixture@example.test',displayName:'Fixture'},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'},timeout:30000,attestation:'none'}});const r=await fetch('${origin}/passkey/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({rawId:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),attestationObject:enc(c.response.attestationObject)})});if(!r.ok)throw new Error('register');document.querySelector('#enrolled').hidden=false;};</script>`; }
function passkeyLoginHtml(origin: string, rpId: string, challenge: Buffer, credentialId: Buffer): string { return `<!doctype html><button id="login">Login</button><script>${browserHelpers()}document.querySelector('#login').onclick=async()=>{const c=await navigator.credentials.get({publicKey:{challenge:dec('${challenge.toString("base64url")}'),rpId:'${rpId}',allowCredentials:[{type:'public-key',id:dec('${credentialId.toString("base64url")}')}],userVerification:'required',timeout:30000}});const r=await fetch('${origin}/passkey/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({rawId:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),authenticatorData:enc(c.response.authenticatorData),signature:enc(c.response.signature),userHandle:c.response.userHandle?enc(c.response.userHandle):null})});if(!r.ok)throw new Error('verify');location.href='${origin}/passkey/account';};</script>`; }
function passkeyCleanupHtml(origin: string): string { return `<!doctype html><button id="remove">Remove passkey</button><div id="removed" hidden>Removed</div><script>document.querySelector('#remove').onclick=async()=>{const r=await fetch('${origin}/passkey/credential',{method:'DELETE'});if(!r.ok)throw new Error('remove');document.querySelector('#removed').hidden=false;};</script>`; }
function browserHelpers(): string { return String.raw`const dec=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0));const enc=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');`; }

function validateClientData(encoded: string, type: string, challenge: Buffer, origin: string): Json { const value = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Json; if (value.type !== type || value.challenge !== challenge.toString("base64url") || value.origin !== origin) throw new Error("PASSKEY_CLIENT_DATA_INVALID"); return value; }
function parseRegistrationAuthData(data: Buffer, rpId: string): { credentialId: Buffer; publicKey: ReturnType<typeof createPublicKey>; signCount: number } { if (data.length < 55 || !safeBufferEqual(data.subarray(0, 32), createHash("sha256").update(rpId).digest()) || (data[32]! & 0x45) !== 0x45) throw new Error("PASSKEY_AUTH_DATA_INVALID"); const signCount = data.readUInt32BE(33); const length = data.readUInt16BE(53); const credentialId = data.subarray(55, 55 + length); const cose = decodeCbor(data.subarray(55 + length)); if (!(cose instanceof Map) || cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1 || !Buffer.isBuffer(cose.get(-2)) || !Buffer.isBuffer(cose.get(-3))) throw new Error("PASSKEY_COSE_KEY_INVALID"); const publicKey = createPublicKey({ key: { kty: "EC", crv: "P-256", x: (cose.get(-2) as Buffer).toString("base64url"), y: (cose.get(-3) as Buffer).toString("base64url") }, format: "jwk" }); return { credentialId, publicKey, signCount }; }
function parseAssertionAuthData(data: Buffer, rpId: string): { signCount: number } { if (data.length < 37 || !safeBufferEqual(data.subarray(0, 32), createHash("sha256").update(rpId).digest()) || (data[32]! & 0x05) !== 0x05) throw new Error("PASSKEY_ASSERTION_DATA_INVALID"); return { signCount: data.readUInt32BE(33) }; }

function decodeCbor(data: Buffer): unknown { const state = { offset: 0 }; return readCbor(data, state); }
function readCbor(data: Buffer, state: { offset: number }): unknown { const first = data[state.offset++]; if (first === undefined) throw new Error("CBOR_TRUNCATED"); const major = first >> 5; const info = first & 31; const length = cborLength(data, state, info); if (major === 0) return length; if (major === 1) return -1 - length; if (major === 2) { const value = data.subarray(state.offset, state.offset + length); state.offset += length; return value; } if (major === 3) { const value = data.subarray(state.offset, state.offset + length).toString("utf8"); state.offset += length; return value; } if (major === 4) return Array.from({ length }, () => readCbor(data, state)); if (major === 5) { const map = new Map<unknown, unknown>(); for (let index = 0; index < length; index += 1) map.set(readCbor(data, state), readCbor(data, state)); return map; } if (major === 7 && info === 20) return false; if (major === 7 && info === 21) return true; if (major === 7 && info === 22) return null; throw new Error("CBOR_UNSUPPORTED"); }
function cborLength(data: Buffer, state: { offset: number }, info: number): number { if (info < 24) return info; if (info === 24) return data[state.offset++]!; if (info === 25) { const value = data.readUInt16BE(state.offset); state.offset += 2; return value; } if (info === 26) { const value = data.readUInt32BE(state.offset); state.offset += 4; return value; } throw new Error("CBOR_LENGTH_UNSUPPORTED"); }

async function boundedJson(response: Response): Promise<Json> { const text = await response.text(); if (Buffer.byteLength(text) > 64 * 1024) throw new Error("PROVIDER_RESPONSE_LIMIT"); if (!text) return {}; try { return JSON.parse(text) as Json; } catch { throw new Error("PROVIDER_RESPONSE_JSON_INVALID"); } }
function expand(value: string, secrets: Record<string, string>, captures: Map<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_token, source: string, name: string) => { const resolved = source === "SECRET" ? secrets[name] : captures.get(name); if (resolved === undefined) throw new Error(`REFERENCE_UNAVAILABLE:${source}:${name}`); return resolved; }); }
function expandUrl(value: string, secrets: Record<string, string>, captures: Map<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_token, source: string, name: string) => { const resolved = source === "SECRET" ? secrets[name] : captures.get(name); if (resolved === undefined) throw new Error(`REFERENCE_UNAVAILABLE:${source}:${name}`); return encodeURIComponent(resolved); }); }
function expandValue(value: unknown, secrets: Record<string, string>, captures: Map<string, string>): unknown { if (typeof value === "string") return expand(value, secrets, captures); if (Array.isArray(value)) return value.map((item) => expandValue(item, secrets, captures)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, expandValue(item, secrets, captures)])); return value; }
function valueAt(value: unknown, path: string): unknown { let current = value; for (const part of path.split(".")) { if (!current || typeof current !== "object") return undefined; current = (current as Json)[part]; } return current; }
function headerName(headers: Record<string, string>, wanted: string): string | undefined { return Object.keys(headers).find((name) => name.toLowerCase() === wanted); }
function token(prefix: string): string { return `${prefix}-${randomBytes(18).toString("base64url")}`; }
function requestBody(request: IncomingMessage): Promise<string> { return new Promise((resolveBody, reject) => { const chunks: Buffer[] = []; let size = 0; request.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 64 * 1024) { reject(new Error("BODY_LIMIT")); request.destroy(); } else chunks.push(chunk); }); request.on("end", () => resolveBody(Buffer.concat(chunks).toString("utf8"))); request.on("error", reject); }); }
function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(value === undefined ? "" : JSON.stringify(value)); }
function html(response: ServerResponse, value: string): void { response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(value); }
function safeBufferEqual(left: Buffer, right: Buffer): boolean { return left.length === right.length && timingSafeEqual(left, right); }
function safeReason(error: unknown): string { const value = error instanceof Error ? error.message : "UNKNOWN"; const normalized = value.toUpperCase().replace(/HTTPS?:\/\/[^\s]+/g, "URL").replace(/[^A-Z0-9_:-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 160); return normalized || "ACCEPTANCE_CHECK_FAILED"; }
function markdown(summary: AuthenticationFixtureAcceptanceSummary): string { return `# Authentication fixture acceptance\n\nStatus: **${summary.status}**\n\n## Provider emulators\n\n${summary.providers.map((item) => `- ${item.provider}: ${item.status} (${item.operations.join(", ") || "none"}; ${item.requests} requests)`).join("\n")}\n\n## OIDC callback lifecycle\n\n- Status: ${summary.oidc.status}\n- Discovery: ${summary.oidc.discovery}\n- Callback/state: ${summary.oidc.callback}\n- PKCE: ${summary.oidc.pkce}\n- ID token: ${summary.oidc.idToken}\n- Replay rejected: ${summary.oidc.replay}\n\n## Browser passkey lifecycle\n\n- Status: ${summary.passkey.status}\n- Enrollment: ${summary.passkey.enrollment}\n- Login: ${summary.passkey.login}\n- Signature verified: ${summary.passkey.signatureVerified}\n- Cleanup: ${summary.passkey.cleanup}\n\nEvidence SHA-256: \`${summary.evidenceSha256}\`\n`; }
