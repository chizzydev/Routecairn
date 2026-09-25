import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { verifyTotp } from "../modules/authenticationLifecycle/AuthenticationFixtures.js";

type Actor = { id: "user-a" | "user-b"; tenantId: "tenant-a" | "tenant-b" };
type StoredPasskey = { publicKeyDer: string; signCount: number };

export interface BroaderAcceptanceTargetSnapshot {
  vulnerableTenantRead: boolean;
  pendingOidcAuthorizations: number;
  totpEnrollments: number;
  passkeys: number;
  pendingChallenges: number;
  activeCheckouts: number;
  activeEntitlements: number;
  consumedWebhookEvents: number;
  cronRuns: number;
}

export interface BroaderAcceptanceTarget {
  origin: string;
  actorAuthorization(actor: "a" | "b"): string;
  signCapability(kind: "portal" | "export", tenantId: string, resourceId: string, expiresAt: number): string;
  signWebhook(body: string): string;
  cronAuthorization(): string;
  setVulnerableTenantRead(value: boolean): void;
  snapshot(): BroaderAcceptanceTargetSnapshot;
  reset(): void;
  close(): Promise<void>;
}

export async function startBroaderAcceptanceTarget(): Promise<BroaderAcceptanceTarget> {
  const actorTokens = new Map<string, Actor>([
    [randomBytes(24).toString("base64url"), { id: "user-a", tenantId: "tenant-a" }],
    [randomBytes(24).toString("base64url"), { id: "user-b", tenantId: "tenant-b" }]
  ]);
  const tokens = [...actorTokens.keys()];
  const capabilityKey = randomBytes(32);
  const webhookKey = randomBytes(32);
  const cronToken = randomBytes(24).toString("base64url");
  const oidcSigningKeys = generateKeyPairSync("ed25519");
  const oidcKid = randomBytes(12).toString("base64url");
  const oidcAuthorizations = new Map<string, { actorId: string; code: string; codeChallenge: string; nonce: string; clientId: string }>();
  const totp = new Map<string, string>();
  const passkeys = new Map<string, Map<string, StoredPasskey>>();
  const challenges = new Map<string, { actorId: string; credentialId: string }>();
  const checkouts = new Map<string, { tenantId: string; refunded: boolean }>();
  const entitlements = new Set<string>();
  const webhookEvents = new Set<string>();
  let vulnerableTenantRead = false;
  let cronRuns = 0;
  let origin = "";

  const documents = new Map([
    ["document-a", { id: "document-a", tenantId: "tenant-a", title: "Alpha operating report" }],
    ["document-b", { id: "document-b", tenantId: "tenant-b", title: "Beta operating report" }]
  ]);

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", origin || "http://127.0.0.1");
    const actor = authenticate(request, actorTokens);
    try {
      const tenantDocument = /^\/tenant\/documents\/(?<id>[A-Za-z0-9-]+)$/.exec(url.pathname);
      if (request.method === "GET" && tenantDocument?.groups?.id) {
        const document = documents.get(tenantDocument.groups.id);
        if (!actor) return json(response, 401, { error: "unauthorized" });
        if (!document || (!vulnerableTenantRead && document.tenantId !== actor.tenantId)) return json(response, 404, { error: "not_found" });
        return json(response, 200, { id: document.id, tenantId: document.tenantId, title: document.title });
      }

      if (request.method === "GET" && url.pathname === "/rest/v1/documents") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const id = (url.searchParams.get("id") ?? "").replace(/^eq\./, "");
        const document = documents.get(id);
        return json(response, 200, document?.tenantId === actor.tenantId ? [{ id: document.id, tenant_id: document.tenantId }] : []);
      }

      const storage = /^\/storage\/v1\/object\/private\/(?<tenant>tenant-[ab])\/(?<key>[A-Za-z0-9._-]+)$/.exec(url.pathname);
      if (request.method === "GET" && storage?.groups?.tenant && storage.groups.key) {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        if (storage.groups.tenant !== actor.tenantId) return json(response, 404, { error: "not_found" });
        return binary(response, 200, Buffer.from(`report:${storage.groups.tenant}:${storage.groups.key}`), "application/pdf");
      }

      if (request.method === "POST" && url.pathname === "/rest/v1/rpc/tenant_stats") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const body = await readJson(request);
        if (body.tenantId !== actor.tenantId) return json(response, 403, { error: "forbidden" });
        return json(response, 200, { tenantId: actor.tenantId, documentCount: 1 });
      }

      if (request.method === "GET" && url.pathname === "/oidc/.well-known/openid-configuration") {
        return json(response, 200, { issuer: `${origin}/oidc`, authorization_endpoint: `${origin}/auth/oauth/start`, token_endpoint: `${origin}/auth/oauth/callback`, jwks_uri: `${origin}/oidc/jwks`, response_types_supported: ["code"], code_challenge_methods_supported: ["S256"], id_token_signing_alg_values_supported: ["EdDSA"] });
      }
      if (request.method === "GET" && url.pathname === "/oidc/jwks") {
        return json(response, 200, { keys: [{ ...(oidcSigningKeys.publicKey.export({ format: "jwk" }) as Record<string, unknown>), kid: oidcKid, use: "sig", alg: "EdDSA" }] });
      }
      if (request.method === "POST" && url.pathname === "/auth/oauth/start") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const body = await readJson(request); const codeChallenge = bounded(string(body.codeChallenge), 128); const clientId = bounded(string(body.clientId), 120);
        if (!/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) return json(response, 400, { error: "invalid_code_challenge" });
        const state = randomBytes(18).toString("base64url"); const nonce = randomBytes(18).toString("base64url"); const code = randomBytes(24).toString("base64url");
        oidcAuthorizations.set(state, { actorId: actor.id, code, codeChallenge, nonce, clientId });
        return json(response, 201, { state, nonce, code, issuer: `${origin}/oidc` });
      }
      if (request.method === "POST" && url.pathname === "/auth/oauth/callback") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const body = await readJson(request); const state = string(body.state); const authorization = oidcAuthorizations.get(state);
        if (!authorization) return json(response, 409, { error: "state_invalid_or_replayed" });
        if (authorization.actorId !== actor.id) return json(response, 403, { error: "actor_binding_failed" });
        if (authorization.code !== string(body.code) || authorization.codeChallenge !== pkceChallenge(string(body.codeVerifier))) return json(response, 403, { error: "code_or_pkce_invalid" });
        oidcAuthorizations.delete(state);
        return json(response, 200, { tokenType: "Bearer", idToken: issueIdToken(oidcSigningKeys.privateKey, oidcKid, `${origin}/oidc`, authorization.clientId, actor, authorization.nonce) });
      }

      if (request.method === "POST" && url.pathname === "/auth/totp/enroll") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const secret = randomBytes(20).toString("hex"); totp.set(actor.id, secret);
        return json(response, 201, { secret, encoding: "HEX" });
      }
      if (request.method === "POST" && url.pathname === "/auth/totp/verify") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const body = await readJson(request); const secret = totp.get(actor.id);
        if (!secret || !verifyTotp(string(body.code), { secret, encoding: "HEX" }).valid) return json(response, 403, { verified: false });
        return json(response, 200, { verified: true });
      }
      if (request.method === "DELETE" && url.pathname === "/auth/totp") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        totp.delete(actor.id); return json(response, 204);
      }

      if (request.method === "POST" && url.pathname === "/auth/passkeys") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const body = await readJson(request); const credentialId = bounded(string(body.credentialId), 200); const publicKeyDer = bounded(string(body.publicKeyDer), 4096);
        try { createPublicKey({ key: Buffer.from(publicKeyDer, "base64url"), format: "der", type: "spki" }); } catch { return json(response, 400, { error: "invalid_public_key" }); }
        const actorPasskeys = passkeys.get(actor.id) ?? new Map<string, StoredPasskey>(); actorPasskeys.set(credentialId, { publicKeyDer, signCount: 0 }); passkeys.set(actor.id, actorPasskeys);
        return json(response, 201, { credentialId });
      }
      if (request.method === "POST" && url.pathname === "/auth/passkeys/challenge") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const body = await readJson(request); const credentialId = string(body.credentialId);
        if (!passkeys.get(actor.id)?.has(credentialId)) return json(response, 404, { error: "credential_not_found" });
        const challenge = randomBytes(32).toString("base64url"); challenges.set(challenge, { actorId: actor.id, credentialId });
        return json(response, 201, { challenge });
      }
      if (request.method === "POST" && url.pathname === "/auth/passkeys/verify") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const body = await readJson(request); const challenge = string(body.challenge); const binding = challenges.get(challenge);
        if (!binding || binding.actorId !== actor.id || binding.credentialId !== string(body.credentialId)) return json(response, 409, { error: "challenge_invalid_or_replayed" });
        const credential = passkeys.get(actor.id)?.get(binding.credentialId); let valid = false;
        try { valid = Boolean(credential && verify(null, Buffer.from(challenge), createPublicKey({ key: Buffer.from(credential.publicKeyDer, "base64url"), format: "der", type: "spki" }), Buffer.from(string(body.signature), "base64url"))); } catch { valid = false; }
        if (!valid) return json(response, 403, { verified: false });
        challenges.delete(challenge); credential!.signCount += 1; return json(response, 200, { verified: true, signCount: credential!.signCount });
      }
      const passkeyDelete = /^\/auth\/passkeys\/(?<id>[A-Za-z0-9_-]+)$/.exec(url.pathname);
      if (request.method === "DELETE" && passkeyDelete?.groups?.id) {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        passkeys.get(actor.id)?.delete(passkeyDelete.groups.id); return json(response, 204);
      }

      if (request.method === "POST" && url.pathname === "/graphql") {
        if (!actor) return json(response, 401, { errors: [{ message: "Unauthorized" }] });
        const body = await readJson(request); const variables = record(body.variables); const document = documents.get(string(variables.id));
        if (!document || document.tenantId !== actor.tenantId) return json(response, 200, { data: { document: null }, errors: [{ message: "Forbidden", extensions: { code: "FORBIDDEN" } }] });
        return json(response, 200, { data: { document: { id: document.id, tenantId: document.tenantId } } });
      }

      if (request.method === "GET" && (url.pathname === "/portal" || url.pathname.startsWith("/exports/"))) {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const kind = url.pathname === "/portal" ? "portal" : "export"; const tenantId = string(url.searchParams.get("tenant")); const resourceId = kind === "portal" ? string(url.searchParams.get("portal")) : url.pathname.slice("/exports/".length); const expiresAt = Number(url.searchParams.get("exp")); const signature = string(url.searchParams.get("sig"));
        if (tenantId !== actor.tenantId || !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || !safeEqual(signature, capabilitySignature(capabilityKey, kind, tenantId, resourceId, expiresAt))) return json(response, 403, { error: "capability_rejected" });
        return kind === "portal" ? json(response, 200, { portal: resourceId, tenantId }) : binary(response, 200, Buffer.from(`protected-export:${tenantId}:${resourceId}`), "text/csv");
      }

      if (request.method === "POST" && url.pathname === "/billing/checkouts") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        const id = randomBytes(12).toString("hex"); checkouts.set(id, { tenantId: actor.tenantId, refunded: false }); return json(response, 201, { id, provider: "synthetic" });
      }
      if (request.method === "POST" && url.pathname === "/billing/webhook") {
        const raw = await readBody(request); if (!verifiedWebhook(request, raw, webhookKey)) return json(response, 401, { error: "signature_invalid" });
        const body = parseJson(raw); const eventId = bounded(string(body.eventId), 160); if (webhookEvents.has(eventId)) return json(response, 409, { error: "event_replayed" }); webhookEvents.add(eventId);
        const checkout = checkouts.get(string(body.checkoutId)); if (!checkout) return json(response, 404, { error: "checkout_not_found" });
        if (body.type === "checkout.completed") entitlements.add(checkout.tenantId); else if (body.type === "checkout.refunded") { entitlements.delete(checkout.tenantId); checkout.refunded = true; }
        return json(response, 202, { accepted: true });
      }
      if (request.method === "GET" && url.pathname === "/billing/entitlement") {
        if (!actor) return json(response, 401, { error: "unauthorized" });
        return json(response, 200, { tenantId: actor.tenantId, active: entitlements.has(actor.tenantId) });
      }

      if (request.method === "POST" && url.pathname === "/webhooks/events") {
        const raw = await readBody(request); if (!verifiedWebhook(request, raw, webhookKey)) return json(response, 401, { error: "signature_invalid" });
        const body = parseJson(raw); const eventId = `generic:${bounded(string(body.eventId), 160)}`; if (webhookEvents.has(eventId)) return json(response, 409, { error: "event_replayed" }); webhookEvents.add(eventId); return json(response, 202, { accepted: true });
      }
      if (request.method === "POST" && url.pathname === "/cron/reconcile") {
        if (request.headers.authorization !== `Bearer ${cronToken}`) return json(response, 401, { error: "unauthorized" });
        cronRuns += 1; return json(response, 202, { accepted: true, run: cronRuns });
      }

      return json(response, 404, { error: "not_found" });
    } catch (error) {
      return json(response, 400, { error: error instanceof Error ? error.message : "invalid_request" });
    }
  });

  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); }); });
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const reset = () => { oidcAuthorizations.clear(); totp.clear(); passkeys.clear(); challenges.clear(); checkouts.clear(); entitlements.clear(); webhookEvents.clear(); vulnerableTenantRead = false; cronRuns = 0; };
  return {
    origin,
    actorAuthorization: (actor) => `Bearer ${tokens[actor === "a" ? 0 : 1]}`,
    signCapability: (kind, tenantId, resourceId, expiresAt) => capabilitySignature(capabilityKey, kind, tenantId, resourceId, expiresAt),
    signWebhook: (body) => createHmac("sha256", webhookKey).update(body).digest("hex"),
    cronAuthorization: () => `Bearer ${cronToken}`,
    setVulnerableTenantRead: (value) => { vulnerableTenantRead = value; },
    snapshot: () => ({ vulnerableTenantRead, pendingOidcAuthorizations: oidcAuthorizations.size, totpEnrollments: totp.size, passkeys: [...passkeys.values()].reduce((total, value) => total + value.size, 0), pendingChallenges: challenges.size, activeCheckouts: [...checkouts.values()].filter((item) => !item.refunded).length, activeEntitlements: entitlements.size, consumedWebhookEvents: webhookEvents.size, cronRuns }),
    reset,
    close: async () => { reset(); await closeServer(server); }
  };
}

function authenticate(request: IncomingMessage, tokens: Map<string, Actor>): Actor | undefined { const match = /^Bearer (.+)$/.exec(request.headers.authorization ?? ""); return match?.[1] ? tokens.get(match[1]) : undefined; }
function pkceChallenge(verifier: string): string { return createHash("sha256").update(verifier).digest("base64url"); }
function issueIdToken(privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], kid: string, issuer: string, audience: string, actor: Actor, nonce: string): string {
  const now = Math.floor(Date.now() / 1000); const header = base64urlJson({ alg: "EdDSA", typ: "JWT", kid }); const payload = base64urlJson({ iss: issuer, aud: audience, sub: actor.id, tenant_id: actor.tenantId, nonce, iat: now, exp: now + 300 }); const input = `${header}.${payload}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString("base64url")}`;
}
function base64urlJson(value: unknown): string { return Buffer.from(JSON.stringify(value)).toString("base64url"); }
function capabilitySignature(key: Buffer, kind: string, tenantId: string, resourceId: string, expiresAt: number): string { return createHmac("sha256", key).update(`${kind}\0${tenantId}\0${resourceId}\0${expiresAt}`).digest("base64url"); }
function verifiedWebhook(request: IncomingMessage, body: string, key: Buffer): boolean { const supplied = string(request.headers["x-fixture-signature"]); const expected = createHmac("sha256", key).update(body).digest("hex"); return safeEqual(supplied, expected); }
function safeEqual(left: string, right: string): boolean { const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
function record(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function string(value: unknown): string { return typeof value === "string" ? value : ""; }
function bounded(value: string, max: number): string { if (!value || value.length > max || /[\r\n\0]/.test(value)) throw new Error("invalid_value"); return value; }
function parseJson(value: string): Record<string, unknown> { try { return record(JSON.parse(value)); } catch { throw new Error("invalid_json"); } }
async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> { return parseJson(await readBody(request)); }
async function readBody(request: IncomingMessage): Promise<string> { let body = ""; for await (const chunk of request) { body += String(chunk); if (Buffer.byteLength(body) > 64 * 1024) throw new Error("body_too_large"); } return body; }
function json(response: ServerResponse, status: number, value?: unknown): void { response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); response.end(value === undefined ? "" : JSON.stringify(value)); }
function binary(response: ServerResponse, status: number, value: Buffer, contentType: string): void { response.writeHead(status, { "content-type": contentType, "cache-control": "no-store", "content-length": value.length }); response.end(value); }
async function closeServer(server: Server): Promise<void> { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
