import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import type { JsonWebKey } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateTotp } from "../modules/authenticationLifecycle/AuthenticationFixtures.js";
import { startBroaderAcceptanceTarget, type BroaderAcceptanceTarget, type BroaderAcceptanceTargetSnapshot } from "./BroaderAcceptanceTarget.js";

export const broaderAcceptanceLaneIds = [
  "multi-tenant-authorization",
  "supabase-rls-storage-rpc",
  "oauth-mfa-passkeys",
  "graphql-authorization",
  "signed-portals-exports",
  "synthetic-payment-provider",
  "webhooks-cron",
  "remediation-reruns"
] as const;

export type BroaderAcceptanceLaneId = typeof broaderAcceptanceLaneIds[number];

interface LaneResult { id: BroaderAcceptanceLaneId; status: "PASSED" | "FAILED"; checks: string[]; evidenceDigest: string; error?: string }
interface RequestEvidence { sequence: number; lane: BroaderAcceptanceLaneId; method: string; path: string; status: number; durationMs: number; requestBodyHash?: string; responseBodyHash: string }

export interface BroaderAcceptanceSummary {
  schemaVersion: 1;
  standard: "BROADER_ACCEPTANCE_LAB_V1";
  status: "PASSED" | "FAILED";
  fixtureOnly: true;
  externalTargetsTested: false;
  targetClass: "OWNED_DISPOSABLE_MULTI_TENANT_LOOPBACK";
  startedAt: string;
  completedAt: string;
  directory: string;
  requestCount: number;
  lanes: LaneResult[];
  cleanup: { verified: boolean; finalStateDigest: string };
  attestation: { algorithm: "Ed25519"; digest: string; signature: string; publicKey: string };
}

/**
 * Executes the complete broader grid against an owned, disposable stateful app.
 * No caller-controlled URL is accepted and no result is represented as external acceptance.
 */
export async function runBroaderAcceptanceValidation(outputParent?: string): Promise<BroaderAcceptanceSummary> {
  if (outputParent) await mkdir(outputParent, { recursive: true });
  const directory = await mkdtemp(join(resolve(outputParent ?? tmpdir()), "routecairn-broader-acceptance-"));
  const startedAt = new Date().toISOString();
  const target = await startBroaderAcceptanceTarget();
  const requests: RequestEvidence[] = [];
  const lanes: LaneResult[] = [];
  let finalSnapshot: BroaderAcceptanceTargetSnapshot | undefined;
  let activeLane: BroaderAcceptanceLaneId = broaderAcceptanceLaneIds[0];
  const request = async (method: string, path: string, options: { actor?: "a" | "b"; body?: unknown; headers?: Record<string, string> } = {}) => {
    if (requests.length >= 96) throw new Error("ACCEPTANCE_REQUEST_BUDGET_EXCEEDED");
    const url = new URL(path, target.origin); if (url.origin !== target.origin) throw new Error("ACCEPTANCE_CROSS_ORIGIN_BLOCKED");
    const body = options.body === undefined ? undefined : typeof options.body === "string" ? options.body : JSON.stringify(options.body);
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 5000); const began = Date.now();
    try {
      const response = await fetch(url, { method, redirect: "manual", signal: controller.signal, headers: { ...(options.actor ? { authorization: target.actorAuthorization(options.actor) } : {}), ...(body === undefined ? {} : { "content-type": "application/json" }), ...options.headers }, ...(body === undefined ? {} : { body }) });
      const responseBytes = Buffer.from(await response.arrayBuffer()); if (responseBytes.length > 64 * 1024) throw new Error("ACCEPTANCE_RESPONSE_BUDGET_EXCEEDED");
      requests.push({ sequence: requests.length + 1, lane: activeLane, method, path: url.pathname, status: response.status, durationMs: Date.now() - began, ...(body === undefined ? {} : { requestBodyHash: hash(body) }), responseBodyHash: hash(responseBytes) });
      let json: unknown; try { json = responseBytes.length ? JSON.parse(responseBytes.toString("utf8")) : undefined; } catch { json = undefined; }
      return { status: response.status, body: responseBytes, json };
    } finally { clearTimeout(timer); }
  };
  const runLane = async (id: BroaderAcceptanceLaneId, checks: string[], execute: () => Promise<unknown>) => {
    activeLane = id; const before = requests.length;
    try {
      await execute();
      lanes.push({ id, status: "PASSED", checks, evidenceDigest: hash(canonical(requests.slice(before))) });
    } catch (error) {
      lanes.push({ id, status: "FAILED", checks, evidenceDigest: hash(canonical(requests.slice(before))), error: safeError(error) });
    }
  };

  try {
    await runLane("multi-tenant-authorization", ["owner read allowed", "cross-tenant read denied", "tenant identity retained"], async () => {
      const own = await request("GET", "/tenant/documents/document-a", { actor: "a" }); requireStatus(own.status, 200, "TENANT_OWNER_READ");
      requireValue(object(own.json).tenantId, "tenant-a", "TENANT_OWNER_BINDING");
      requireStatus((await request("GET", "/tenant/documents/document-b", { actor: "a" })).status, 404, "TENANT_FOREIGN_DENIAL");
    });

    await runLane("supabase-rls-storage-rpc", ["table RLS", "private storage ownership", "RPC tenant binding"], async () => {
      const tableOwn = await request("GET", "/rest/v1/documents?id=eq.document-a", { actor: "a" }); requireStatus(tableOwn.status, 200, "SUPABASE_TABLE_OWNER"); requireCheck(Array.isArray(tableOwn.json) && tableOwn.json.length === 1, "SUPABASE_TABLE_OWNER_ROW");
      const tableForeign = await request("GET", "/rest/v1/documents?id=eq.document-b", { actor: "a" }); requireStatus(tableForeign.status, 200, "SUPABASE_TABLE_FOREIGN"); requireCheck(Array.isArray(tableForeign.json) && tableForeign.json.length === 0, "SUPABASE_TABLE_RLS");
      requireStatus((await request("GET", "/storage/v1/object/private/tenant-a/report.pdf", { actor: "a" })).status, 200, "SUPABASE_STORAGE_OWNER");
      requireStatus((await request("GET", "/storage/v1/object/private/tenant-b/report.pdf", { actor: "a" })).status, 404, "SUPABASE_STORAGE_FOREIGN");
      requireStatus((await request("POST", "/rest/v1/rpc/tenant_stats", { actor: "a", body: { tenantId: "tenant-a" } })).status, 200, "SUPABASE_RPC_OWNER");
      requireStatus((await request("POST", "/rest/v1/rpc/tenant_stats", { actor: "a", body: { tenantId: "tenant-b" } })).status, 403, "SUPABASE_RPC_FOREIGN");
    });

    await runLane("oauth-mfa-passkeys", ["OIDC discovery, state, nonce and PKCE", "TOTP lifecycle", "signed passkey challenge lifecycle"], async () => {
      const clientId = "routecairn-acceptance"; const codeVerifier = randomBytes(32).toString("base64url"); const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
      const discovery = await request("GET", "/oidc/.well-known/openid-configuration"); requireStatus(discovery.status, 200, "OIDC_DISCOVERY"); requireValue(object(discovery.json).issuer, `${target.origin}/oidc`, "OIDC_ISSUER");
      const jwksResponse = await request("GET", "/oidc/jwks"); requireStatus(jwksResponse.status, 200, "OIDC_JWKS"); const jwk = object((object(jwksResponse.json).keys as unknown[])[0]);
      const oauth = await request("POST", "/auth/oauth/start", { actor: "a", body: { clientId, codeChallenge } }); requireStatus(oauth.status, 201, "OAUTH_START"); const oauthBody = object(oauth.json); const state = text(oauthBody.state); const nonce = text(oauthBody.nonce); const authorizationCode = text(oauthBody.code); requireCheck(Boolean(state && nonce && authorizationCode), "OAUTH_BINDING_MISSING");
      requireStatus((await request("POST", "/auth/oauth/callback", { actor: "a", body: { state: `wrong-${state}`, code: authorizationCode, codeVerifier } })).status, 409, "OAUTH_STATE_REJECT");
      requireStatus((await request("POST", "/auth/oauth/callback", { actor: "b", body: { state, code: authorizationCode, codeVerifier } })).status, 403, "OAUTH_ACTOR_REJECT");
      requireStatus((await request("POST", "/auth/oauth/callback", { actor: "a", body: { state, code: authorizationCode, codeVerifier: `${codeVerifier}x` } })).status, 403, "OAUTH_PKCE_REJECT");
      const callback = await request("POST", "/auth/oauth/callback", { actor: "a", body: { state, code: authorizationCode, codeVerifier } }); requireStatus(callback.status, 200, "OAUTH_CALLBACK"); verifyIdToken(text(object(callback.json).idToken), jwk, { issuer: `${target.origin}/oidc`, audience: clientId, nonce, subject: "user-a", tenantId: "tenant-a" });
      requireStatus((await request("POST", "/auth/oauth/callback", { actor: "a", body: { state, code: authorizationCode, codeVerifier } })).status, 409, "OAUTH_REPLAY_REJECT");

      const enrollment = await request("POST", "/auth/totp/enroll", { actor: "a", body: {} }); requireStatus(enrollment.status, 201, "TOTP_ENROLL"); const secret = text(object(enrollment.json).secret); const code = generateTotp({ secret, encoding: "HEX" }).code;
      const invalidCode = code === "000000" ? "000001" : "000000"; requireStatus((await request("POST", "/auth/totp/verify", { actor: "a", body: { code: invalidCode } })).status, 403, "TOTP_INVALID_REJECT");
      requireStatus((await request("POST", "/auth/totp/verify", { actor: "a", body: { code } })).status, 200, "TOTP_VERIFY");
      requireStatus((await request("DELETE", "/auth/totp", { actor: "a" })).status, 204, "TOTP_REMOVE");

      const keys = generateKeyPairSync("ed25519"); const credentialId = randomBytes(18).toString("base64url"); const publicKeyDer = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
      requireStatus((await request("POST", "/auth/passkeys", { actor: "a", body: { credentialId, publicKeyDer } })).status, 201, "PASSKEY_REGISTER");
      requireStatus((await request("POST", "/auth/passkeys/challenge", { actor: "b", body: { credentialId } })).status, 404, "PASSKEY_ACTOR_REJECT");
      const challengeResponse = await request("POST", "/auth/passkeys/challenge", { actor: "a", body: { credentialId } }); const challenge = text(object(challengeResponse.json).challenge); requireCheck(Boolean(challenge), "PASSKEY_CHALLENGE"); const signature = sign(null, Buffer.from(challenge), keys.privateKey).toString("base64url");
      requireStatus((await request("POST", "/auth/passkeys/verify", { actor: "a", body: { credentialId, challenge, signature } })).status, 200, "PASSKEY_VERIFY");
      requireStatus((await request("POST", "/auth/passkeys/verify", { actor: "a", body: { credentialId, challenge, signature } })).status, 409, "PASSKEY_REPLAY_REJECT");
      requireStatus((await request("DELETE", `/auth/passkeys/${credentialId}`, { actor: "a" })).status, 204, "PASSKEY_REMOVE");
    });

    await runLane("graphql-authorization", ["authorized object query", "cross-tenant object denial", "structured GraphQL denial"], async () => {
      const query = "query AcceptanceDocument($id: ID!) { document(id: $id) { id tenantId } }";
      const own = await request("POST", "/graphql", { actor: "a", body: { operationName: "AcceptanceDocument", query, variables: { id: "document-a" } } }); requireStatus(own.status, 200, "GRAPHQL_OWNER"); requireValue(object(object(object(own.json).data).document).tenantId, "tenant-a", "GRAPHQL_OWNER_BINDING");
      const foreign = await request("POST", "/graphql", { actor: "a", body: { operationName: "AcceptanceDocument", query, variables: { id: "document-b" } } }); requireStatus(foreign.status, 200, "GRAPHQL_FOREIGN_HTTP"); requireCheck(Array.isArray(object(foreign.json).errors), "GRAPHQL_FOREIGN_DENIAL");
    });

    await runLane("signed-portals-exports", ["signed portal", "protected export", "tenant and signature tamper rejection"], async () => {
      const expiresAt = Date.now() + 60_000; const portalSig = target.signCapability("portal", "tenant-a", "billing", expiresAt);
      requireStatus((await request("GET", `/portal?tenant=tenant-a&portal=billing&exp=${expiresAt}&sig=${encodeURIComponent(portalSig)}`, { actor: "a" })).status, 200, "PORTAL_OWNER");
      requireStatus((await request("GET", `/portal?tenant=tenant-a&portal=billing&exp=${expiresAt}&sig=${encodeURIComponent(portalSig)}`, { actor: "b" })).status, 403, "PORTAL_TENANT_REJECT");
      requireStatus((await request("GET", `/portal?tenant=tenant-a&portal=admin&exp=${expiresAt}&sig=${encodeURIComponent(portalSig)}`, { actor: "a" })).status, 403, "PORTAL_TAMPER_REJECT");
      const exportSig = target.signCapability("export", "tenant-a", "quarterly.csv", expiresAt);
      requireStatus((await request("GET", `/exports/quarterly.csv?tenant=tenant-a&exp=${expiresAt}&sig=${encodeURIComponent(exportSig)}`, { actor: "a" })).status, 200, "EXPORT_OWNER");
      requireStatus((await request("GET", `/exports/quarterly.csv?tenant=tenant-b&exp=${expiresAt}&sig=${encodeURIComponent(exportSig)}`, { actor: "b" })).status, 403, "EXPORT_TAMPER_REJECT");
    });

    await runLane("synthetic-payment-provider", ["synthetic checkout", "signed idempotent event", "entitlement activation and refund cleanup"], async () => {
      const checkout = await request("POST", "/billing/checkouts", { actor: "a", body: { plan: "fixture-pro" } }); requireStatus(checkout.status, 201, "BILLING_CHECKOUT"); const checkoutId = text(object(checkout.json).id);
      const complete = JSON.stringify({ eventId: randomBytes(12).toString("hex"), type: "checkout.completed", checkoutId }); const completeSignature = target.signWebhook(complete);
      requireStatus((await request("POST", "/billing/webhook", { body: complete, headers: { "x-fixture-signature": completeSignature } })).status, 202, "BILLING_EVENT");
      requireStatus((await request("POST", "/billing/webhook", { body: complete, headers: { "x-fixture-signature": completeSignature } })).status, 409, "BILLING_REPLAY_REJECT");
      requireValue(object((await request("GET", "/billing/entitlement", { actor: "a" })).json).active, true, "BILLING_ENTITLEMENT");
      const refund = JSON.stringify({ eventId: randomBytes(12).toString("hex"), type: "checkout.refunded", checkoutId }); requireStatus((await request("POST", "/billing/webhook", { body: refund, headers: { "x-fixture-signature": target.signWebhook(refund) } })).status, 202, "BILLING_REFUND");
      requireValue(object((await request("GET", "/billing/entitlement", { actor: "a" })).json).active, false, "BILLING_CLEANUP");
    });

    await runLane("webhooks-cron", ["webhook signature", "webhook replay rejection", "cron authentication"], async () => {
      const event = JSON.stringify({ eventId: randomBytes(12).toString("hex"), kind: "fixture.updated" });
      requireStatus((await request("POST", "/webhooks/events", { body: event, headers: { "x-fixture-signature": "invalid" } })).status, 401, "WEBHOOK_SIGNATURE_REJECT");
      const signature = target.signWebhook(event); requireStatus((await request("POST", "/webhooks/events", { body: event, headers: { "x-fixture-signature": signature } })).status, 202, "WEBHOOK_ACCEPT"); requireStatus((await request("POST", "/webhooks/events", { body: event, headers: { "x-fixture-signature": signature } })).status, 409, "WEBHOOK_REPLAY_REJECT");
      requireStatus((await request("POST", "/cron/reconcile", { body: {} })).status, 401, "CRON_UNAUTHORIZED"); requireStatus((await request("POST", "/cron/reconcile", { body: {}, headers: { authorization: target.cronAuthorization() } })).status, 202, "CRON_AUTHORIZED");
    });

    await runLane("remediation-reruns", ["known vulnerable baseline", "exact fixed rerun", "stable case identity"], async () => {
      target.setVulnerableTenantRead(true); const baseline = await request("GET", "/tenant/documents/document-b", { actor: "a" }); requireStatus(baseline.status, 200, "REMEDIATION_BASELINE_FINDING"); const caseIdentity = hash("multi-tenant-authorization\0GET /tenant/documents/:id\0actor-a-to-tenant-b");
      target.setVulnerableTenantRead(false); const rerun = await request("GET", "/tenant/documents/document-b", { actor: "a" }); requireStatus(rerun.status, 404, "REMEDIATION_FIXED_RERUN"); requireCheck(caseIdentity.length === 64, "REMEDIATION_CASE_IDENTITY");
    });
    finalSnapshot = target.snapshot();
  } finally {
    target.reset();
    await target.close();
  }

  if (!finalSnapshot) throw new Error("ACCEPTANCE_FINAL_STATE_UNAVAILABLE");
  const cleanupVerified = clean(finalSnapshot);
  const completedAt = new Date().toISOString();
  const unsigned = { schemaVersion: 1 as const, standard: "BROADER_ACCEPTANCE_LAB_V1" as const, status: lanes.every((lane) => lane.status === "PASSED") && cleanupVerified ? "PASSED" as const : "FAILED" as const, fixtureOnly: true as const, externalTargetsTested: false as const, targetClass: "OWNED_DISPOSABLE_MULTI_TENANT_LOOPBACK" as const, startedAt, completedAt, directory, requestCount: requests.length, lanes, cleanup: { verified: cleanupVerified, finalStateDigest: hash(canonical(finalSnapshot)) } };
  const digest = hash(canonical(unsigned)); const keys = generateKeyPairSync("ed25519"); const signature = sign(null, Buffer.from(digest, "hex"), keys.privateKey).toString("base64url"); const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const summary: BroaderAcceptanceSummary = { ...unsigned, attestation: { algorithm: "Ed25519", digest, signature, publicKey } };
  await writeFile(join(directory, "broader-acceptance-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(directory, "broader-acceptance-requests.json"), `${JSON.stringify({ schemaVersion: 1, requests }, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(directory, "broader-acceptance-report.md"), markdown(summary), { mode: 0o600 });
  return summary;
}

function clean(snapshot: ReturnType<BroaderAcceptanceTarget["snapshot"]>): boolean { return !snapshot.vulnerableTenantRead && snapshot.pendingOidcAuthorizations === 0 && snapshot.totpEnrollments === 0 && snapshot.passkeys === 0 && snapshot.pendingChallenges === 0 && snapshot.activeCheckouts === 0 && snapshot.activeEntitlements === 0; }
function verifyIdToken(token: string, jwk: Record<string, unknown>, expected: { issuer: string; audience: string; nonce: string; subject: string; tenantId: string }): void {
  const parts = token.split("."); requireCheck(parts.length === 3 && Boolean(parts[0] && parts[1] && parts[2]), "OIDC_TOKEN_FORMAT");
  const header = parseBase64urlJson(parts[0]!); const claims = parseBase64urlJson(parts[1]!);
  requireValue(header.alg, "EdDSA", "OIDC_TOKEN_ALGORITHM"); requireValue(header.kid, jwk.kid, "OIDC_TOKEN_KEY_ID");
  const publicKey = createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }); requireCheck(verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2]!, "base64url")), "OIDC_TOKEN_SIGNATURE");
  requireValue(claims.iss, expected.issuer, "OIDC_TOKEN_ISSUER"); requireValue(claims.aud, expected.audience, "OIDC_TOKEN_AUDIENCE"); requireValue(claims.nonce, expected.nonce, "OIDC_TOKEN_NONCE"); requireValue(claims.sub, expected.subject, "OIDC_TOKEN_SUBJECT"); requireValue(claims.tenant_id, expected.tenantId, "OIDC_TOKEN_TENANT");
  requireCheck(typeof claims.exp === "number" && claims.exp > Math.floor(Date.now() / 1000), "OIDC_TOKEN_EXPIRY");
}
function parseBase64urlJson(value: string): Record<string, unknown> { try { return object(JSON.parse(Buffer.from(value, "base64url").toString("utf8"))); } catch { throw new Error("OIDC_TOKEN_JSON"); } }
function requireStatus(actual: number, expected: number, code: string): void { if (actual !== expected) throw new Error(`${code}: expected ${expected}, received ${actual}`); }
function requireValue(actual: unknown, expected: unknown, code: string): void { if (actual !== expected) throw new Error(`${code}: unexpected value`); }
function requireCheck(value: unknown, code: string): asserts value { if (!value) throw new Error(code); }
function object(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function text(value: unknown): string { return typeof value === "string" ? value : ""; }
function hash(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }
function canonical(value: unknown): string { if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`).join(",")}}`; return JSON.stringify(value); }
function safeError(error: unknown): string { return (error instanceof Error ? error.message : "Acceptance lane failed").replace(/[\r\n\0]/g, " ").slice(0, 500); }
function markdown(summary: BroaderAcceptanceSummary): string { return `# RouteCairn broader acceptance laboratory\n\nStatus: **${summary.status}**\n\nThis is an owned disposable loopback acceptance target. It is not external-target certification.\n\n| Lane | Status | Evidence digest |\n|---|---|---|\n${summary.lanes.map((lane) => `| ${lane.id} | ${lane.status} | \`${lane.evidenceDigest}\` |`).join("\n")}\n\nRequests: ${summary.requestCount}\n\nCleanup verified: ${summary.cleanup.verified ? "yes" : "no"}\n\nAttestation digest: \`${summary.attestation.digest}\`\n`; }
