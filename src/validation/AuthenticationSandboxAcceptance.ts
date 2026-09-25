import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify, type JsonWebKey } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { z } from "zod";
import { resolveTurnkeyAuthRequest, turnkeyAuthOperations, turnkeyAuthProviders, type TurnkeyAuthAdapterConfig, type TurnkeyAuthOperation, type TurnkeyAuthProvider } from "../modules/authenticationLifecycle/TurnkeyAuthProviderAdapters.js";
import { VirtualWebAuthnManager, type VirtualWebAuthnBrowserStep } from "../modules/browserCrawler/VirtualWebAuthnManager.js";

const id = z.string().regex(/^[A-Za-z0-9._-]{1,100}$/);
const envName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);
const url = z.string().url().max(2048);
const jsonPath = z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){0,7}$/);
const headerNameSchema = z.string().regex(/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/);
const browserSelector = z.string().min(1).max(500).refine((value) => !/[\r\n\0]/.test(value));
const browserStep = z.discriminatedUnion("action", [
  z.object({ action: z.literal("fill"), selector: browserSelector, valueSecretRef: id }).strict(),
  z.object({ action: z.literal("click"), selector: browserSelector }).strict(),
  z.object({ action: z.literal("check"), selector: browserSelector }).strict(),
  z.object({ action: z.literal("uncheck"), selector: browserSelector }).strict(),
  z.object({ action: z.literal("press"), selector: browserSelector, key: z.string().min(1).max(50).refine((value) => !/[\r\n\0]/.test(value)) }).strict(),
  z.object({ action: z.literal("selectOption"), selector: browserSelector, value: z.string().max(500) }).strict(),
  z.object({ action: z.literal("waitForTimeout"), milliseconds: z.number().int().min(0).max(5000) }).strict(),
  z.object({ action: z.literal("assertVisible"), selector: browserSelector }).strict(),
  z.object({ action: z.literal("assertHidden"), selector: browserSelector }).strict(),
  z.object({ action: z.literal("assertText"), selector: browserSelector, text: z.string().min(1).max(500).refine((value) => !/[\r\n\0]/.test(value)) }).strict(),
  z.object({ action: z.literal("waitForUrl"), urlPrefix: url }).strict()
]);
const adapter = z.object({
  id,
  provider: z.enum(turnkeyAuthProviders),
  baseUrl: url,
  tokenBaseUrl: url.optional(),
  cognitoMode: z.enum(["HOSTED_UI", "USER_POOLS_API"]).optional(),
  clientIdSecretRef: id.optional(),
  clientSecretRef: id.optional(),
  apiKeySecretRef: id.optional(),
  serviceKeySecretRef: id.optional(),
  managementTokenSecretRef: id.optional()
}).strict();
const providerAssertions = z.object({
  jsonEquals: z.record(jsonPath, z.unknown()).default({}),
  jsonPresent: z.array(jsonPath).max(40).default([]),
  jsonAbsent: z.array(jsonPath).max(40).default([]),
  headerPresent: z.array(headerNameSchema).max(20).default([]),
  headerAbsent: z.array(headerNameSchema).max(20).default([])
}).strict().default({});
const providerOperation = z.object({
  id,
  phase: z.enum(["SETUP", "ACTION", "VERIFY", "CLEANUP"]),
  operation: z.enum(turnkeyAuthOperations),
  fields: z.record(z.unknown()).default({}),
  expectedStatuses: z.array(z.number().int().min(200).max(499)).min(1).max(12).default([200, 201, 204]),
  captureSuggested: z.boolean().default(true),
  captures: z.record(jsonPath).default({}),
  assertions: providerAssertions
}).strict();
const providerAcceptance = z.object({
  id,
  environment: z.enum(["EMULATOR", "DEVELOPMENT", "SANDBOX"]),
  authorizationConfirmed: z.literal(true),
  disposableAccount: z.literal(true),
  adapter,
  secretEnvironment: z.record(id, envName).default({}),
  maxRequests: z.number().int().min(1).max(40).default(12),
  requestTimeoutMs: z.number().int().min(1000).max(120000).default(30000),
  operations: z.array(providerOperation).min(1).max(40)
}).strict().superRefine((value, ctx) => {
  const ids = new Set<string>();
  for (const [index, operation] of value.operations.entries()) {
    if (ids.has(operation.id)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["operations", index, "id"], message: "Operation IDs must be unique." });
    ids.add(operation.id);
  }
  if (!value.operations.some((item) => item.phase === "CLEANUP")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["operations"], message: "Every provider acceptance lane requires an explicit cleanup operation." });
  if (value.operations.some((item) => item.operation === "SIGN_UP") && !value.operations.some((item) => item.phase === "CLEANUP" && item.operation === "DELETE_USER")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["operations"], message: "A disposable signup lifecycle requires DELETE_USER cleanup." });
});
const oidcAcceptance = z.object({
  id,
  environment: z.enum(["EMULATOR", "DEVELOPMENT", "SANDBOX"]),
  authorizationConfirmed: z.literal(true),
  issuer: url,
  discoveryUrl: url.optional(),
  clientIdEnvironment: envName,
  clientSecretEnvironment: envName.optional(),
  expectedSubjectEnvironment: envName.optional(),
  secretEnvironment: z.record(id, envName).default({}),
  callbackPort: z.number().int().min(0).max(65535).default(43119),
  callbackPath: z.string().regex(/^\/[A-Za-z0-9._~!$&'()*+,;=:@%\/-]{1,200}$/).default("/callback"),
  scopes: z.array(z.string().regex(/^[A-Za-z0-9._:-]{1,80}$/)).min(1).max(20).default(["openid", "profile"]),
  extraAuthorizeParameters: z.record(z.string().max(1000)).default({}),
  tokenAuthMethod: z.enum(["NONE", "CLIENT_SECRET_POST", "CLIENT_SECRET_BASIC"]).default("NONE"),
  allowedEndpointOrigins: z.array(url).max(20).default([]),
  browserAllowedOrigins: z.array(url).max(20).default([]),
  browserSteps: z.array(browserStep).max(40).default([]),
  timeoutMs: z.number().int().min(1000).max(120000).default(30000)
}).strict().superRefine((value, ctx) => {
  const reserved = new Set(["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"]);
  for (const key of Object.keys(value.extraAuthorizeParameters)) if (reserved.has(key)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["extraAuthorizeParameters", key], message: "Security-critical authorization parameters cannot be overridden." });
  if (value.tokenAuthMethod !== "NONE" && !value.clientSecretEnvironment) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["clientSecretEnvironment"], message: "The selected token authentication method requires a client secret environment variable." });
});
const passkeyJourney = z.object({ startUrl: url, steps: z.array(browserStep).min(1).max(40), clearCookies: z.boolean().default(false) }).strict();
const passkeyAcceptance = z.object({
  id,
  environment: z.enum(["EMULATOR", "DEVELOPMENT", "SANDBOX"]),
  authorizationConfirmed: z.literal(true),
  disposableAccount: z.literal(true),
  expectedRpId: z.string().min(1).max(253).refine(validRpId, "Expected RP ID must be a lowercase host name without a port or path."),
  secretEnvironment: z.record(id, envName).default({}),
  allowedOrigins: z.array(url).max(20).default([]),
  authenticator: z.object({ protocol: z.enum(["ctap2", "u2f"]).default("ctap2"), transport: z.enum(["usb", "nfc", "ble", "internal"]).default("internal"), hasResidentKey: z.boolean().default(true), hasUserVerification: z.boolean().default(true), isUserVerified: z.boolean().default(true), automaticPresenceSimulation: z.boolean().default(true) }).strict().default({}),
  enrollment: passkeyJourney,
  login: passkeyJourney,
  cleanup: passkeyJourney,
  timeoutMs: z.number().int().min(1000).max(120000).default(30000)
}).strict().superRefine((value, ctx) => {
  if (!value.cleanup.steps.some((step) => step.action === "assertVisible" || step.action === "assertHidden" || step.action === "assertText")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["cleanup", "steps"], message: "Passkey application cleanup requires a browser assertion." });
});

export const authenticationSandboxAcceptanceSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  name: z.string().min(1).max(160),
  providers: z.array(providerAcceptance).max(20).default([]),
  oidc: z.array(oidcAcceptance).max(10).default([]),
  passkeys: z.array(passkeyAcceptance).max(10).default([])
}).strict().superRefine((value, ctx) => {
  if (!value.providers.length && !value.oidc.length && !value.passkeys.length) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "At least one provider, OIDC, or passkey acceptance lane is required." });
  const ids = new Set<string>();
  for (const [kind, items] of [["providers", value.providers], ["oidc", value.oidc], ["passkeys", value.passkeys]] as const) for (const [index, item] of items.entries()) {
    if (ids.has(item.id)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [kind, index, "id"], message: "Acceptance lane IDs must be globally unique." });
    ids.add(item.id);
  }
});

export type AuthenticationSandboxAcceptanceInput = z.infer<typeof authenticationSandboxAcceptanceSchema>;
type ProviderDefinition = AuthenticationSandboxAcceptanceInput["providers"][number];
type ProviderOperation = ProviderDefinition["operations"][number];
type OidcDefinition = AuthenticationSandboxAcceptanceInput["oidc"][number];
type PasskeyDefinition = AuthenticationSandboxAcceptanceInput["passkeys"][number];

export interface AuthenticationSandboxAcceptanceSummary {
  schemaVersion: 1;
  name: string;
  status: "PASSED" | "FAILED";
  generatedAt: string;
  providers: Array<{ id: string; provider: TurnkeyAuthProvider; environment: string; status: "PASSED" | "FAILED"; operations: TurnkeyAuthOperation[]; cleanup: "PASSED" | "FAILED" | "NOT_REQUIRED"; requests: number; reason?: string }>;
  oidc: Array<{ id: string; status: "PASSED" | "FAILED"; discovery: boolean; browserCallback: boolean; state: boolean; pkce: boolean; idToken: boolean; callbackReplayRejected: boolean; codeReplayRejected: boolean; requests: number; reason?: string }>;
  passkeys: Array<{ id: string; status: "PASSED" | "FAILED"; enrollment: boolean; rpBound: boolean; login: boolean; counterAdvanced: boolean; applicationCleanup: boolean; authenticatorCleanup: boolean; reason?: string }>;
  totalRequests: number;
  evidenceSha256: string;
  outputDirectory: string;
}

export async function loadAuthenticationSandboxAcceptance(path: string): Promise<AuthenticationSandboxAcceptanceInput> {
  const raw = await readFile(path);
  if (raw.byteLength > 1024 * 1024) throw new Error("AUTH_SANDBOX_MANIFEST_TOO_LARGE");
  let value: unknown;
  try { value = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, "")); } catch { throw new Error("AUTH_SANDBOX_MANIFEST_JSON_INVALID"); }
  return authenticationSandboxAcceptanceSchema.parse(value);
}

export async function runAuthenticationSandboxAcceptance(raw: AuthenticationSandboxAcceptanceInput, parentDirectory = ".routecairn-authentication-sandbox-acceptance", environment: NodeJS.ProcessEnv = process.env): Promise<AuthenticationSandboxAcceptanceSummary> {
  const input = authenticationSandboxAcceptanceSchema.parse(raw);
  const parent = resolve(parentDirectory);
  await mkdir(parent, { recursive: true });
  const outputDirectory = await mkdtemp(resolve(parent, "run-"));
  const providers: AuthenticationSandboxAcceptanceSummary["providers"] = [];
  const oidc: AuthenticationSandboxAcceptanceSummary["oidc"] = [];
  const passkeys: AuthenticationSandboxAcceptanceSummary["passkeys"] = [];
  for (const definition of input.providers) providers.push(await runProvider(definition, environment));
  for (const definition of input.oidc) oidc.push(await runOidc(definition, environment));
  for (const definition of input.passkeys) passkeys.push(await runPasskey(definition, environment));
  const status: AuthenticationSandboxAcceptanceSummary["status"] = [...providers, ...oidc, ...passkeys].every((item) => item.status === "PASSED") ? "PASSED" : "FAILED";
  const totalRequests = providers.reduce((sum, item) => sum + item.requests, 0) + oidc.reduce((sum, item) => sum + item.requests, 0);
  const core = { schemaVersion: 1 as const, name: input.name, status, generatedAt: new Date().toISOString(), providers, oidc, passkeys, totalRequests };
  const evidenceSha256 = createHash("sha256").update(JSON.stringify(core)).digest("hex");
  const summary: AuthenticationSandboxAcceptanceSummary = { ...core, evidenceSha256, outputDirectory };
  await writeFile(resolve(outputDirectory, "authentication-sandbox-acceptance.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await writeFile(resolve(outputDirectory, "authentication-sandbox-acceptance.md"), markdown(summary), "utf8");
  return summary;
}

async function runProvider(definition: ProviderDefinition, environment: NodeJS.ProcessEnv): Promise<AuthenticationSandboxAcceptanceSummary["providers"][number]> {
  const secrets = resolveEnvironmentMap(definition.secretEnvironment, environment);
  const captures = new Map<string, string>();
  const completed: TurnkeyAuthOperation[] = [];
  const cleanup = definition.operations.filter((item) => item.phase === "CLEANUP");
  let requests = 0;
  let failure: unknown;
  let cleanupFailed = false;
  try {
    for (const operation of definition.operations.filter((item) => item.phase !== "CLEANUP")) {
      if (++requests > definition.maxRequests) throw new Error("AUTH_SANDBOX_REQUEST_BUDGET_EXCEEDED");
      await executeProviderOperation(definition.adapter, operation, secrets, captures, definition.requestTimeoutMs);
      completed.push(operation.operation);
    }
  } catch (error) { failure = error; }
  for (const operation of cleanup) {
    try {
      if (++requests > definition.maxRequests) throw new Error("AUTH_SANDBOX_REQUEST_BUDGET_EXCEEDED");
      await executeProviderOperation(definition.adapter, operation, secrets, captures, definition.requestTimeoutMs);
      completed.push(operation.operation);
    } catch (error) { cleanupFailed = true; failure ??= error; }
  }
  return { id: definition.id, provider: definition.adapter.provider, environment: definition.environment, status: failure || cleanupFailed ? "FAILED" : "PASSED", operations: completed, cleanup: cleanupFailed ? "FAILED" : "PASSED", requests, ...(failure ? { reason: safeReason(failure, Object.values(secrets)) } : {}) };
}

async function executeProviderOperation(adapterConfig: TurnkeyAuthAdapterConfig, operation: ProviderOperation, secrets: Record<string, string>, captures: Map<string, string>, timeoutMs: number): Promise<void> {
  const template = resolveTurnkeyAuthRequest(adapterConfig, operation.operation, operation.fields);
  const endpoint = expandUrl(template.url, secrets, captures);
  enforceProviderDestination(endpoint, adapterConfig);
  const headers = Object.fromEntries(Object.entries(template.headers).map(([name, value]) => [name, expand(value, secrets, captures)]));
  const fields = expandValue(template.fields ?? {}, secrets, captures) as Record<string, unknown>;
  let body: string | undefined;
  if (template.bodyFormat === "FORM") { body = new URLSearchParams(Object.entries(fields).map(([key, value]) => [key, String(value)] as [string, string])).toString(); headers[findHeaderName(headers, "content-type") ?? "Content-Type"] = "application/x-www-form-urlencoded"; }
  if (template.bodyFormat === "JSON") { body = JSON.stringify(fields); headers[findHeaderName(headers, "content-type") ?? "Content-Type"] = "application/json"; }
  const response = await fetchWithTimeout(endpoint, { method: template.method, headers, ...(body !== undefined ? { body } : {}), redirect: "manual" }, timeoutMs);
  const responseCaptures = { ...(operation.captureSuggested ? template.suggestedCaptures : {}), ...operation.captures };
  const requiresJson = Object.keys(responseCaptures).length > 0 || Object.keys(operation.assertions.jsonEquals).length > 0 || operation.assertions.jsonPresent.length > 0 || operation.assertions.jsonAbsent.length > 0;
  const payload = await boundedJson(response, requiresJson && operation.expectedStatuses.includes(response.status));
  if (!operation.expectedStatuses.includes(response.status)) throw new Error(`AUTH_SANDBOX_${adapterConfig.provider}_${operation.operation}_HTTP_${response.status}`);
  for (const [path, expected] of Object.entries(operation.assertions.jsonEquals)) if (!deepEqual(valueAt(payload, path), expandValue(expected, secrets, captures))) throw new Error(`AUTH_SANDBOX_JSON_ASSERTION_FAILED:${path}`);
  for (const path of operation.assertions.jsonPresent) if (valueAt(payload, path) === undefined) throw new Error(`AUTH_SANDBOX_JSON_ASSERTION_FAILED:${path}`);
  for (const path of operation.assertions.jsonAbsent) if (valueAt(payload, path) !== undefined) throw new Error(`AUTH_SANDBOX_JSON_ASSERTION_FAILED:${path}`);
  for (const name of operation.assertions.headerPresent) if (!response.headers.has(name)) throw new Error(`AUTH_SANDBOX_HEADER_ASSERTION_FAILED:${name}`);
  for (const name of operation.assertions.headerAbsent) if (response.headers.has(name)) throw new Error(`AUTH_SANDBOX_HEADER_ASSERTION_FAILED:${name}`);
  for (const [name, path] of Object.entries(responseCaptures)) {
    const value = valueAt(payload, path);
    if (typeof value !== "string" || !value) throw new Error(`AUTH_SANDBOX_CAPTURE_MISSING:${name}`);
    captures.set(name, value);
  }
}

async function runOidc(definition: OidcDefinition, environment: NodeJS.ProcessEnv): Promise<AuthenticationSandboxAcceptanceSummary["oidc"][number]> {
  let requests = 0;
  const secretValues = oidcSecretValues(definition, environment);
  const failed = (reason: unknown): AuthenticationSandboxAcceptanceSummary["oidc"][number] => ({ id: definition.id, status: "FAILED", discovery: false, browserCallback: false, state: false, pkce: false, idToken: false, callbackReplayRejected: false, codeReplayRejected: false, requests, reason: safeReason(reason, secretValues) });
  let callback: OidcCallbackReceiver | undefined;
  const browser = new VirtualWebAuthnManager();
  try {
    const issuer = canonicalIssuer(definition.issuer);
    const endpointOrigins = new Set([new URL(issuer).origin, ...definition.allowedEndpointOrigins.map((value) => { requireHttpsOrLoopback(value); return new URL(value).origin; })]);
    const discoveryUrl = definition.discoveryUrl ?? `${issuer}/.well-known/openid-configuration`;
    enforceAllowedOrigin(discoveryUrl, endpointOrigins, "OIDC_DISCOVERY_ORIGIN_BLOCKED");
    requests += 1;
    const discovery = await fetchBoundedJson(discoveryUrl, definition.timeoutMs);
    const authorizationEndpoint = requiredUrl(discovery.authorization_endpoint, "OIDC_AUTHORIZATION_ENDPOINT_MISSING");
    const tokenEndpoint = requiredUrl(discovery.token_endpoint, "OIDC_TOKEN_ENDPOINT_MISSING");
    const jwksUri = requiredUrl(discovery.jwks_uri, "OIDC_JWKS_URI_MISSING");
    if (canonicalIssuer(String(discovery.issuer ?? "")) !== issuer) throw new Error("OIDC_DISCOVERY_ISSUER_MISMATCH");
    if (!stringArray(discovery.response_types_supported).includes("code") || !stringArray(discovery.code_challenge_methods_supported).includes("S256")) throw new Error("OIDC_DISCOVERY_CODE_PKCE_UNSUPPORTED");
    const advertisedMethods = stringArray(discovery.token_endpoint_auth_methods_supported);
    const expectedMethod = { NONE: "none", CLIENT_SECRET_POST: "client_secret_post", CLIENT_SECRET_BASIC: "client_secret_basic" }[definition.tokenAuthMethod];
    if (advertisedMethods.length && !advertisedMethods.includes(expectedMethod)) throw new Error("OIDC_TOKEN_AUTH_METHOD_UNSUPPORTED");
    for (const [endpoint, code] of [[authorizationEndpoint, "OIDC_AUTHORIZATION_ORIGIN_BLOCKED"], [tokenEndpoint, "OIDC_TOKEN_ORIGIN_BLOCKED"], [jwksUri, "OIDC_JWKS_ORIGIN_BLOCKED"]] as const) enforceAllowedOrigin(endpoint, endpointOrigins, code);
    const state = randomBytes(32).toString("base64url");
    const nonce = randomBytes(32).toString("base64url");
    const verifier = randomBytes(48).toString("base64url");
    callback = new OidcCallbackReceiver(definition.callbackPort, definition.callbackPath, state);
    const callbackUrl = await callback.start();
    const clientId = requiredEnvironment(environment, definition.clientIdEnvironment);
    const authorize = new URL(authorizationEndpoint);
    authorize.search = new URLSearchParams({ ...definition.extraAuthorizeParameters, response_type: "code", client_id: clientId, redirect_uri: callbackUrl, scope: definition.scopes.join(" "), state, nonce, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" }).toString();
    const secrets = resolveEnvironmentMap(definition.secretEnvironment, environment);
    const steps = browserSteps(definition.browserSteps, secrets);
    steps.push({ action: "waitForUrl", urlPrefix: callbackUrl });
    await browser.runBrowserFlow({ startUrl: authorize.toString(), steps, timeoutMs: definition.timeoutMs, allowedOrigins: [...definition.browserAllowedOrigins, callbackUrl] });
    const result = await callback.wait(definition.timeoutMs);
    if (!safeEqual(result.state, state) || !result.code) throw new Error("OIDC_CALLBACK_STATE_INVALID");
    const tokenFields: Record<string, string> = { grant_type: "authorization_code", code: result.code, redirect_uri: callbackUrl, client_id: clientId, code_verifier: verifier };
    const tokenHeaders: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
    if (definition.tokenAuthMethod === "CLIENT_SECRET_POST") tokenFields.client_secret = requiredEnvironment(environment, definition.clientSecretEnvironment ?? "");
    if (definition.tokenAuthMethod === "CLIENT_SECRET_BASIC") tokenHeaders.Authorization = `Basic ${Buffer.from(`${formComponent(clientId)}:${formComponent(requiredEnvironment(environment, definition.clientSecretEnvironment ?? ""))}`).toString("base64")}`;
    const tokenBody = new URLSearchParams(tokenFields).toString();
    requests += 1;
    const tokenResponse = await fetchWithTimeout(tokenEndpoint, { method: "POST", redirect: "manual", headers: tokenHeaders, body: tokenBody }, definition.timeoutMs);
    const tokens = await boundedJson(tokenResponse);
    if (!tokenResponse.ok || typeof tokens.id_token !== "string") throw new Error(`OIDC_TOKEN_EXCHANGE_HTTP_${tokenResponse.status}`);
    requests += 1;
    const jwks = await fetchBoundedJson(jwksUri, definition.timeoutMs);
    const claims = verifyIdToken(tokens.id_token, jwks, { issuer, audience: clientId, nonce });
    const expectedSubject = definition.expectedSubjectEnvironment ? requiredEnvironment(environment, definition.expectedSubjectEnvironment) : undefined;
    if (expectedSubject && !safeEqual(String(claims.sub ?? ""), expectedSubject)) throw new Error("OIDC_SUBJECT_MISMATCH");
    requests += 1;
    const callbackReplay = await fetchWithTimeout(`${callbackUrl}?code=${encodeURIComponent(result.code)}&state=${encodeURIComponent(state)}`, { redirect: "manual" }, definition.timeoutMs);
    requests += 1;
    const codeReplay = await fetchWithTimeout(tokenEndpoint, { method: "POST", redirect: "manual", headers: tokenHeaders, body: tokenBody }, definition.timeoutMs);
    if (callbackReplay.status < 400) throw new Error("OIDC_CALLBACK_REPLAY_ACCEPTED");
    if (codeReplay.status < 400) throw new Error("OIDC_CODE_REPLAY_ACCEPTED");
    return { id: definition.id, status: "PASSED", discovery: true, browserCallback: true, state: true, pkce: true, idToken: true, callbackReplayRejected: true, codeReplayRejected: true, requests };
  } catch (error) { return failed(error); }
  finally { await browser.close().catch(() => undefined); await callback?.close().catch(() => undefined); }
}

async function runPasskey(definition: PasskeyDefinition, environment: NodeJS.ProcessEnv): Promise<AuthenticationSandboxAcceptanceSummary["passkeys"][number]> {
  const manager = new VirtualWebAuthnManager();
  let enrollment = false; let rpBound = false; let login = false; let counterAdvanced = false; let applicationCleanup = false; let authenticatorCleanup = false;
  try {
    const secrets = resolveEnvironmentMap(definition.secretEnvironment, environment);
    await manager.create(definition.id, definition.authenticator);
    await manager.runBrowserFlow({ startUrl: definition.enrollment.startUrl, steps: browserSteps(definition.enrollment.steps, secrets), clearCookies: definition.enrollment.clearCookies, timeoutMs: definition.timeoutMs, allowedOrigins: definition.allowedOrigins });
    const created = await manager.credentials(definition.id);
    enrollment = created.length === 1;
    rpBound = enrollment && created[0]!.rpId === definition.expectedRpId;
    if (!enrollment || !rpBound) throw new Error("PASSKEY_ENROLLMENT_EVIDENCE_INVALID");
    const before = created[0]!.signCount;
    await manager.runBrowserFlow({ startUrl: definition.login.startUrl, steps: browserSteps(definition.login.steps, secrets), clearCookies: definition.login.clearCookies, timeoutMs: definition.timeoutMs, allowedOrigins: definition.allowedOrigins });
    const authenticated = await manager.credentials(definition.id);
    login = authenticated.length === 1;
    counterAdvanced = login && authenticated[0]!.signCount > before;
    if (!login || !counterAdvanced) throw new Error("PASSKEY_LOGIN_EVIDENCE_INVALID");
    await manager.runBrowserFlow({ startUrl: definition.cleanup.startUrl, steps: browserSteps(definition.cleanup.steps, secrets), clearCookies: definition.cleanup.clearCookies, timeoutMs: definition.timeoutMs, allowedOrigins: definition.allowedOrigins });
    applicationCleanup = true;
    await manager.clear(definition.id);
    authenticatorCleanup = (await manager.credentials(definition.id)).length === 0;
    if (!authenticatorCleanup) throw new Error("PASSKEY_AUTHENTICATOR_CLEANUP_FAILED");
    return { id: definition.id, status: "PASSED", enrollment, rpBound, login, counterAdvanced, applicationCleanup, authenticatorCleanup };
  } catch (error) { return { id: definition.id, status: "FAILED", enrollment, rpBound, login, counterAdvanced, applicationCleanup, authenticatorCleanup, reason: safeReason(error, Object.values(resolveEnvironmentMapLenient(definition.secretEnvironment, environment))) }; }
  finally { await manager.remove(definition.id).catch(() => undefined); await manager.close().catch(() => undefined); }
}

class OidcCallbackReceiver {
  private server: Server | undefined;
  private accepted = false;
  private result: Record<string, string> | undefined;
  public constructor(private readonly port: number, private readonly path: string, private readonly state: string) {}
  public async start(): Promise<string> {
    this.server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", `http://127.0.0.1:${this.port}`);
      response.setHeader("cache-control", "no-store");
      if (request.method !== "GET" || url.pathname !== this.path) return response.writeHead(404).end();
      const values = Object.fromEntries(url.searchParams.entries());
      if (this.accepted || !safeEqual(values.state, this.state) || !values.code) return response.writeHead(this.accepted ? 409 : 400).end();
      this.accepted = true; this.result = values;
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end("<!doctype html><title>OIDC callback complete</title><p id=complete>Complete</p>");
    });
    await new Promise<void>((resolveStart, reject) => { this.server!.once("error", reject); this.server!.listen(this.port, "127.0.0.1", () => { this.server!.off("error", reject); resolveStart(); }); });
    return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}${this.path}`;
  }
  public async wait(timeoutMs: number): Promise<Record<string, string>> { const deadline = Date.now() + timeoutMs; while (Date.now() < deadline) { if (this.result) return this.result; await new Promise((resolveWait) => setTimeout(resolveWait, 50)); } throw new Error("OIDC_CALLBACK_TIMEOUT"); }
  public async close(): Promise<void> { const server = this.server; this.server = undefined; if (server) await new Promise<void>((resolveClose) => server.close(() => resolveClose())); }
}

function verifyIdToken(token: string, jwks: Record<string, unknown>, expected: { issuer: string; audience: string; nonce: string }): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("OIDC_ID_TOKEN_FORMAT_INVALID");
  const header = parseJwtPart(parts[0]!); const claims = parseJwtPart(parts[1]!);
  const keys = Array.isArray(jwks.keys) ? jwks.keys.filter(record) : [];
  const key = keys.find((item) => (!header.kid || item.kid === header.kid) && (!item.alg || item.alg === header.alg) && (!item.use || item.use === "sig"));
  if (!key || !["RS256", "RS384", "RS512", "ES256"].includes(String(header.alg))) throw new Error("OIDC_ID_TOKEN_KEY_INVALID");
  let publicKey: ReturnType<typeof createPublicKey>;
  try { publicKey = createPublicKey({ key: key as JsonWebKey, format: "jwk" }); } catch { throw new Error("OIDC_ID_TOKEN_KEY_INVALID"); }
  const algorithms: Record<string, string> = { RS256: "RSA-SHA256", RS384: "RSA-SHA384", RS512: "RSA-SHA512", ES256: "sha256" };
  const verificationKey = header.alg === "ES256" ? { key: publicKey, dsaEncoding: "ieee-p1363" as const } : publicKey;
  if (!verify(algorithms[String(header.alg)]!, Buffer.from(`${parts[0]}.${parts[1]}`), verificationKey, Buffer.from(parts[2]!, "base64url"))) throw new Error("OIDC_ID_TOKEN_SIGNATURE_INVALID");
  const now = Math.floor(Date.now() / 1000); const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const authorizedPartyValid = audience.length <= 1 || claims.azp === expected.audience;
  if (canonicalIssuer(String(claims.iss ?? "")) !== expected.issuer || !audience.includes(expected.audience) || !authorizedPartyValid || !safeEqual(String(claims.nonce ?? ""), expected.nonce) || typeof claims.exp !== "number" || claims.exp <= now - 30 || typeof claims.iat !== "number" || claims.iat < now - 300 || claims.iat > now + 60 || (typeof claims.nbf === "number" && claims.nbf > now + 60) || typeof claims.sub !== "string" || !claims.sub) throw new Error("OIDC_ID_TOKEN_CLAIMS_INVALID");
  return claims;
}

function validRpId(value: string): boolean { try { const parsed = new URL(`https://${value}`); return !value.includes(":") && parsed.hostname === value.toLowerCase() && !parsed.username && !parsed.password && parsed.pathname === "/"; } catch { return false; } }
function browserSteps(input: readonly z.infer<typeof browserStep>[], secrets: Record<string, string>): VirtualWebAuthnBrowserStep[] { return input.map((step) => step.action === "fill" ? { action: "fill", selector: step.selector, value: requiredValue(secrets, step.valueSecretRef) } : step); }
function resolveEnvironmentMap(mapping: Record<string, string>, environment: NodeJS.ProcessEnv): Record<string, string> { return Object.fromEntries(Object.entries(mapping).map(([name, variable]) => [name, requiredEnvironment(environment, variable)])); }
function resolveEnvironmentMapLenient(mapping: Record<string, string>, environment: NodeJS.ProcessEnv): Record<string, string> { const values: Record<string, string> = {}; for (const [name, variable] of Object.entries(mapping)) if (environment[variable]) values[name] = environment[variable]!; return values; }
function oidcSecretValues(definition: OidcDefinition, environment: NodeJS.ProcessEnv): string[] { return [environment[definition.clientIdEnvironment], definition.clientSecretEnvironment ? environment[definition.clientSecretEnvironment] : undefined, definition.expectedSubjectEnvironment ? environment[definition.expectedSubjectEnvironment] : undefined, ...Object.values(resolveEnvironmentMapLenient(definition.secretEnvironment, environment))].filter((value): value is string => Boolean(value)); }
function requiredEnvironment(environment: NodeJS.ProcessEnv, name: string): string { const value = environment[name]; if (!name || !value || /[\r\n\0]/.test(value)) throw new Error(`AUTH_SANDBOX_ENVIRONMENT_MISSING:${name || "UNCONFIGURED"}`); return value; }
function requiredValue(values: Record<string, string>, name: string): string { const value = values[name]; if (value === undefined) throw new Error(`AUTH_SANDBOX_SECRET_MISSING:${name}`); return value; }
function expand(value: string, secrets: Record<string, string>, captures: Map<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}|\{\{RUN_ID\}\}/g, (token, source?: string, name?: string) => token === "{{RUN_ID}}" ? runId(captures) : source === "SECRET" ? requiredValue(secrets, name!) : requiredCapture(captures, name!)); }
function expandUrl(value: string, secrets: Record<string, string>, captures: Map<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}|\{\{RUN_ID\}\}/g, (token, source?: string, name?: string) => encodeURIComponent(token === "{{RUN_ID}}" ? runId(captures) : source === "SECRET" ? requiredValue(secrets, name!) : requiredCapture(captures, name!))); }
function expandValue(value: unknown, secrets: Record<string, string>, captures: Map<string, string>): unknown { if (typeof value === "string") return expand(value, secrets, captures); if (Array.isArray(value)) return value.map((item) => expandValue(item, secrets, captures)); if (record(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, expandValue(item, secrets, captures)])); return value; }
function runId(captures: Map<string, string>): string { let value = captures.get("__run_id"); if (!value) { value = randomBytes(12).toString("hex"); captures.set("__run_id", value); } return value; }
function requiredCapture(captures: Map<string, string>, name: string): string { const value = captures.get(name); if (!value) throw new Error(`AUTH_SANDBOX_CAPTURE_UNAVAILABLE:${name}`); return value; }
function enforceProviderDestination(endpoint: string, config: TurnkeyAuthAdapterConfig): void { const actual = new URL(endpoint); requireHttpsOrLoopback(actual.toString()); const allowed = new Set([new URL(config.baseUrl).origin, ...(config.tokenBaseUrl ? [new URL(config.tokenBaseUrl).origin] : []), ...(config.provider === "FIREBASE" && new URL(config.baseUrl).hostname === "identitytoolkit.googleapis.com" ? ["https://securetoken.googleapis.com"] : [])]); if (!allowed.has(actual.origin) || actual.username || actual.password || actual.hash) throw new Error("AUTH_SANDBOX_DESTINATION_BLOCKED"); }
function enforceAllowedOrigin(endpoint: string, allowed: ReadonlySet<string>, code: string): void { const parsed = new URL(endpoint); requireHttpsOrLoopback(parsed.toString()); if (!allowed.has(parsed.origin) || parsed.username || parsed.password || parsed.hash) throw new Error(code); }
async function fetchWithTimeout(endpoint: string, init: RequestInit, timeoutMs: number): Promise<Response> { requireHttpsOrLoopback(endpoint); const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs); try { return await fetch(endpoint, { ...init, signal: controller.signal }); } finally { clearTimeout(timer); } }
async function boundedJson(response: Response, required = true): Promise<Record<string, unknown>> { const length = Number(response.headers.get("content-length") ?? 0); if (length > 256 * 1024) throw new Error("AUTH_SANDBOX_RESPONSE_TOO_LARGE"); const text = await response.text(); if (Buffer.byteLength(text) > 256 * 1024) throw new Error("AUTH_SANDBOX_RESPONSE_TOO_LARGE"); if (!text) return {}; try { const value = JSON.parse(text); if (!record(value) && required) throw new Error(); return record(value) ? value : {}; } catch { if (!required) return {}; throw new Error("AUTH_SANDBOX_RESPONSE_JSON_INVALID"); } }
async function fetchBoundedJson(endpoint: string, timeoutMs: number): Promise<Record<string, unknown>> { const response = await fetchWithTimeout(endpoint, { headers: { accept: "application/json" }, redirect: "error" }, timeoutMs); if (!response.ok) throw new Error(`OIDC_METADATA_HTTP_${response.status}`); return boundedJson(response); }
function requiredUrl(value: unknown, code: string): string { if (typeof value !== "string") throw new Error(code); new URL(value); return value; }
function requireHttpsOrLoopback(value: string): void { const parsed = new URL(value); if (parsed.username || parsed.password || parsed.hash || (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && ["127.0.0.1", "localhost", "::1", "[::1]"].includes(parsed.hostname)))) throw new Error("AUTH_SANDBOX_HTTPS_REQUIRED"); }
function canonicalIssuer(value: string): string { const parsed = new URL(value); requireHttpsOrLoopback(parsed.toString()); if (parsed.search || parsed.hash) throw new Error("OIDC_ISSUER_INVALID"); return parsed.toString().replace(/\/$/, ""); }
function parseJwtPart(value: string): Record<string, unknown> { try { const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")); if (!record(parsed)) throw new Error(); return parsed; } catch { throw new Error("OIDC_ID_TOKEN_FORMAT_INVALID"); } }
function stringArray(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []; }
function formComponent(value: string): string { return new URLSearchParams({ value }).toString().slice("value=".length); }
function valueAt(value: unknown, path: string): unknown { return path.split(".").reduce<unknown>((current, part) => record(current) ? current[part] : undefined, value); }
function deepEqual(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function findHeaderName(headers: Record<string, string>, wanted: string): string | undefined { return Object.keys(headers).find((name) => name.toLowerCase() === wanted); }
function safeEqual(left: string | undefined, right: string): boolean { if (left === undefined) return false; const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function safeReason(error: unknown, secrets: readonly string[] = []): string { let value = error instanceof Error ? error.message : "UNKNOWN"; for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) value = value.split(secret).join("[REDACTED]"); return value.toUpperCase().replace(/HTTPS?:\/\/[^\s]+/g, "URL").replace(/[^A-Z0-9_:-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 180) || "ACCEPTANCE_FAILED"; }
function markdown(summary: AuthenticationSandboxAcceptanceSummary): string { return `# Authentication sandbox acceptance\n\nStatus: **${summary.status}**\n\n## Provider lifecycles\n\n${summary.providers.map((item) => `- ${item.id} (${item.provider}/${item.environment}): ${item.status}; cleanup ${item.cleanup}; ${item.requests} requests${item.reason ? `; ${item.reason}` : ""}`).join("\n") || "- Not configured"}\n\n## OIDC callback lifecycles\n\n${summary.oidc.map((item) => `- ${item.id}: ${item.status}; discovery ${item.discovery}; browser callback ${item.browserCallback}; state ${item.state}; PKCE ${item.pkce}; ID token ${item.idToken}; callback replay ${item.callbackReplayRejected}; code replay ${item.codeReplayRejected}; ${item.requests} direct requests${item.reason ? `; ${item.reason}` : ""}`).join("\n") || "- Not configured"}\n\n## Browser passkey lifecycles\n\n${summary.passkeys.map((item) => `- ${item.id}: ${item.status}; enrollment ${item.enrollment}; RP binding ${item.rpBound}; login ${item.login}; counter ${item.counterAdvanced}; application cleanup ${item.applicationCleanup}; authenticator cleanup ${item.authenticatorCleanup}${item.reason ? `; ${item.reason}` : ""}`).join("\n") || "- Not configured"}\n\nEvidence SHA-256: \`${summary.evidenceSha256}\`\n`; }
