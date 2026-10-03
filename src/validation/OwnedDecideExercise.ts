import { randomBytes, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import { runBoundedHttp } from "../modules/protocolSecurity/ProtocolTransports.js";
import { acceptanceDigest, assertAcceptanceExternalOrigin } from "./ExternalAcceptanceReadiness.js";

export const ownedDecideAuthorizationSchema = z.object({
  schemaVersion: z.literal(1), product: z.literal("Decide"), apiOrigin: z.string().url(),
  authorizedBy: z.string().min(2).max(160), authorizationReference: z.string().min(3).max(500),
  startsAt: z.string().datetime(), expiresAt: z.string().datetime(),
  maxRequests: z.number().int().min(24).max(60), rateLimitPerSecond: z.number().min(0.1).max(2),
  disposableAccounts: z.literal(2), administrativeProvisioning: z.literal(true),
  sessionLifecycle: z.literal(true), ownAccountProfileChanges: z.literal(true),
  crossAccountSessionDenial: z.literal(true), deleteCreatedAccounts: z.literal(true),
  cleanupGraceMs: z.number().int().min(60000).max(3600000).default(300000)
}).strict().refine((value) => Date.parse(value.expiresAt) > Date.parse(value.startsAt), "Authorization window is invalid");
export type OwnedDecideAuthorization = z.infer<typeof ownedDecideAuthorizationSchema>;
export interface DisposableDecideAccount { id: string; email: string; password: string; displayName: string; }
export interface OwnedDecideAccountStore {
  provision(accounts: readonly DisposableDecideAccount[]): Promise<void>;
  remove(accounts: readonly Pick<DisposableDecideAccount, "id" | "email">[]): Promise<void>;
  remaining(accounts: readonly Pick<DisposableDecideAccount, "id" | "email">[]): Promise<{ users: number; sessions: number }>;
}
interface Receipt { case: string; status: "PASSED" | "FAILED"; method: string; pathTemplate: string; statusCode?: number; bodySha256?: string; responseBytes?: number; proof: string; }

/** Uses two newly provisioned accounts only. This is owner-operated evidence, never independent acceptance. */
export async function exerciseOwnedDecide(input: OwnedDecideAuthorization, store: OwnedDecideAccountStore, outputParent: string) {
  const authorization = ownedDecideAuthorizationSchema.parse(input);
  assertAcceptanceExternalOrigin(authorization.apiOrigin);
  const started = Date.now();
  const startWindow = Date.parse(authorization.startsAt); const expiry = Date.parse(authorization.expiresAt);
  if (started < startWindow || started >= expiry) throw new Error("OWNED_DECIDE_AUTHORIZATION_INACTIVE");
  const runId = randomUUID(); const marker = `rca-${runId}`;
  const accounts: DisposableDecideAccount[] = ["a", "b"].map((suffix) => ({ id: randomUUID(), email: `${marker}-${suffix}@acceptance.decide.invalid`, password: `Rca!${randomBytes(32).toString("base64url")}`, displayName: `${marker}-${suffix}` }));
  const parent = resolve(outputParent); await mkdir(parent, { recursive: true });
  const directory = await mkdtemp(resolve(parent, "decide-owned-"));
  const recoveryPath = resolve(directory, "private-recovery.json");
  const identities = accounts.map(({ id, email }) => ({ id, email }));
  // Persist exact generated identities before any insertion. No password or bearer token is saved.
  await writeFile(recoveryPath, `${JSON.stringify({ schemaVersion: 1, runId, apiOrigin: authorization.apiOrigin, stage: "PROVISION_PREPARED", accounts: identities }, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  const receipts: Receipt[] = []; let requestCount = 0; let lastAt = 0;
  const sessions = new Map<string, { access: string; refresh: string }>();
  let primaryError: string | undefined; let cleanup = "REQUIRED";
  const request = async (caseName: string, method: string, path: string, body: unknown, access: string | undefined, proof: string, check: (status: number, data: unknown) => boolean, cleanupRequest = false): Promise<{ status: number; data: unknown }> => {
    const deadline = Math.min(expiry + (cleanupRequest ? authorization.cleanupGraceMs : 0), started + 600000 + (cleanupRequest ? authorization.cleanupGraceMs : 0));
    if (Date.now() >= deadline || requestCount >= authorization.maxRequests) throw new Error("OWNED_DECIDE_BUDGET_OR_WINDOW_EXHAUSTED");
    const wait = Math.max(0, lastAt + Math.ceil(1000 / authorization.rateLimitPerSecond) - Date.now());
    if (wait) await new Promise((done) => setTimeout(done, wait));
    const remaining = deadline - Date.now(); if (remaining <= 0) throw new Error("OWNED_DECIDE_AUTHORIZATION_EXPIRED");
    const timeoutMs = Math.min(10000, remaining); lastAt = Date.now(); requestCount += 1;
    const pathTemplate = path.replace(/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/gi, "{disposable-id}");
    try {
      const response = await runBoundedHttp(new URL(path, `${authorization.apiOrigin}/`).toString(), method, { accept: "application/json", "user-agent": "RouteCairn-owned-Decide-exercise/0.1", ...(body === undefined ? {} : { "content-type": "application/json" }), ...(access ? { authorization: `Bearer ${access}` } : {}) }, body === undefined ? undefined : Buffer.from(JSON.stringify(body)), { allowedPrivateOrigins: [], timeoutMs, abortSignal: AbortSignal.timeout(timeoutMs), maxBytes: 32768 });
      let json: unknown; try { json = JSON.parse(response.body.toString("utf8")); } catch { json = undefined; }
      const data = field(json, "data"); const passed = check(response.statusCode, data);
      receipts.push({ case: caseName, status: passed ? "PASSED" : "FAILED", method, pathTemplate, statusCode: response.statusCode, bodySha256: acceptanceDigest(response.body), responseBytes: response.body.length, proof });
      return { status: response.statusCode, data };
    } catch {
      receipts.push({ case: caseName, status: "FAILED", method, pathTemplate, proof: "TRANSPORT_FAILED_NO_RAW_ERROR_RETAINED" });
      throw new Error("OWNED_DECIDE_TRANSPORT_FAILED");
    }
  };
  const login = async (account: DisposableDecideAccount, caseName: string) => {
    const response = await request(caseName, "POST", "/api/v1/mobile-auth/login", { email: account.email, password: account.password }, undefined, "New disposable account authenticates with its generated password and exact user identity", (status, data) => status === 200 && field(field(data, "user"), "id") === account.id && token(field(data, "access_token")) && token(field(data, "refresh_token")));
    if (response.status !== 200 || field(field(response.data, "user"), "id") !== account.id || !token(field(response.data, "access_token")) || !token(field(response.data, "refresh_token"))) throw new Error("OWNED_DECIDE_LOGIN_FAILED");
    const value = { access: field(response.data, "access_token") as string, refresh: field(response.data, "refresh_token") as string }; sessions.set(account.id, value); return value;
  };
  try {
    await store.provision(accounts);
    await writeFile(recoveryPath, `${JSON.stringify({ schemaVersion: 1, runId, apiOrigin: authorization.apiOrigin, stage: "PROVISIONED", accounts: identities }, null, 2)}\n`, { mode: 0o600 });
    const [a, b] = accounts as [DisposableDecideAccount, DisposableDecideAccount];
    const sessionA = await login(a, "ACCOUNT_A_LOGIN"); const sessionB = await login(b, "ACCOUNT_B_LOGIN");
    await request("UNAUTHENTICATED_ME_DENIED", "GET", "/api/v1/mobile-auth/me", undefined, undefined, "Missing bearer token is denied", (status) => status === 401);
    for (const [index, account] of accounts.entries()) await request(`ACCOUNT_${index ? "B" : "A"}_IDENTITY`, "GET", "/api/v1/mobile-auth/me", undefined, sessions.get(account.id)!.access, "Bearer token returns only its own generated account identity", (status, data) => status === 200 && field(data, "id") === account.id);
    const ownedSessions = await request("ACCOUNT_B_SESSION_LIST", "GET", "/api/v1/mobile-auth/sessions", undefined, sessionB.access, "Own session list supplies a disposable session to test", (status, data) => status === 200 && Array.isArray(data) && data.length > 0 && data.every((item) => uuid(field(item, "id"))));
    const foreignId = Array.isArray(ownedSessions.data) ? field(ownedSessions.data[0], "id") : undefined;
    if (!uuid(foreignId)) throw new Error("OWNED_DECIDE_SESSION_BINDING_UNAVAILABLE");
    await request("FOREIGN_SESSION_REVOCATION_DENIED", "DELETE", `/api/v1/mobile-auth/sessions/${foreignId}`, undefined, sessionA.access, "Account A cannot revoke account B's exact session", (status) => status === 403 || status === 404);
    await request("FOREIGN_SESSION_UNCHANGED", "GET", "/api/v1/mobile-auth/me", undefined, sessionB.access, "Account B remains authenticated after the foreign revocation attempt", (status, data) => status === 200 && field(data, "id") === b.id);
    await request("PROFILE_IDENTITY_BOUND_TO_BEARER", "PATCH", "/api/v1/auth/me/profile", { user_id: b.id, display_name: `${marker}-changed` }, sessionA.access, "Body-supplied account B ID cannot redirect account A's profile update", (status, data) => status === 200 && field(data, "id") === a.id);
    await request("FOREIGN_PROFILE_UNCHANGED", "GET", "/api/v1/mobile-auth/me", undefined, sessionB.access, "Account B's display name remains at the provisioned baseline", (status, data) => status === 200 && field(data, "id") === b.id && field(data, "display_name") === b.displayName);
    await request("PROFILE_RESTORE", "PATCH", "/api/v1/auth/me/profile", { display_name: a.displayName }, sessionA.access, "Own disposable profile returns to baseline", (status, data) => status === 200 && field(data, "id") === a.id && field(data, "display_name") === a.displayName);
    const refreshed = await request("REFRESH_TOKEN_ROTATES", "POST", "/api/v1/mobile-auth/refresh", { refresh_token: sessionA.refresh }, undefined, "Successful refresh replaces the old refresh credential", (status, data) => status === 200 && token(field(data, "refresh_token")) && field(data, "refresh_token") !== sessionA.refresh && field(field(data, "user"), "id") === a.id);
    if (refreshed.status !== 200 || !token(field(refreshed.data, "access_token")) || !token(field(refreshed.data, "refresh_token"))) throw new Error("OWNED_DECIDE_REFRESH_FAILED");
    const latest = { access: field(refreshed.data, "access_token") as string, refresh: field(refreshed.data, "refresh_token") as string }; sessions.set(a.id, latest);
    await request("OLD_REFRESH_REPLAY_DENIED", "POST", "/api/v1/mobile-auth/refresh", { refresh_token: sessionA.refresh }, undefined, "The consumed refresh credential is denied on replay", (status) => status === 401 || status === 403);
    await request("LOGOUT", "POST", "/api/v1/mobile-auth/logout", { refresh_token: latest.refresh }, undefined, "Logout revokes the disposable session", (status) => status === 200);
    await request("LOGGED_OUT_ACCESS_DENIED", "GET", "/api/v1/mobile-auth/me", undefined, latest.access, "Access token from a logged-out session is denied", (status) => status === 401 || status === 403);
    await login(a, "ACCOUNT_A_CLEANUP_LOGIN");
  } catch (error) { primaryError = error instanceof Error && /^OWNED_DECIDE_[A-Z_]+$/.test(error.message) ? error.message : "OWNED_DECIDE_PROVISION_OR_EXECUTION_FAILED"; }
  finally {
    for (const [index, account] of accounts.entries()) {
      const session = sessions.get(account.id);
      if (!session) continue;
      try {
        await request(`ACCOUNT_${index ? "B" : "A"}_DELETE`, "DELETE", "/api/v1/auth/me/account", { confirmation_text: "DELETE", current_password: account.password }, session.access, "Delete only this run's disposable account using its own bearer and password", (status) => status === 200, true);
        await request(`DELETED_ACCOUNT_${index ? "B" : "A"}_ACCESS_DENIED`, "GET", "/api/v1/mobile-auth/me", undefined, session.access, "Deleted account bearer no longer authenticates", (status) => status === 401 || status === 403, true);
      } catch { /* Exact-identity administrative cleanup remains mandatory below. */ }
    }
    try {
      await store.remove(identities);
      const remaining = await store.remaining(identities);
      cleanup = remaining.users === 0 && remaining.sessions === 0 ? "VERIFIED" : "FAILED";
    } catch { cleanup = "FAILED"; }
    for (const account of accounts) account.password = ""; sessions.clear();
  }
  const evidence = { schemaVersion: 1, standard: "ROUTECAIRN_OWNED_DECIDE_EXERCISE_V1", runId, status: !primaryError && cleanup === "VERIFIED" && receipts.length > 0 && receipts.every((receipt) => receipt.status === "PASSED") ? "PASSED" : "FAILED", startedAt: new Date(started).toISOString(), completedAt: new Date().toISOString(), apiOrigin: authorization.apiOrigin, authorizationSha256: acceptanceDigest(JSON.stringify(authorization)), authorization, provisionedAccountIdentitySha256: identities.map(({ id }) => acceptanceDigest(id)), provisioningMode: "ADMINISTRATIVELY_PROVISIONED_EMAIL_VERIFIED", requestCount, cleanup, ...(primaryError ? { primaryError } : {}), receipts, independentlyOperated: false, independentAcceptanceVerified: false, fullEightLaneAcceptance: false, limitations: ["Owned accounts were provisioned administratively; email delivery and email ownership verification were not exercised.", "These cases assess account ownership and the custom Decide session lifecycle; they do not establish a tenant model or Auth0/Cognito MFA/passkey acceptance.", "Supabase database hosting does not by itself prove Data API RLS, storage or RPC behavior.", "This owner-operated run cannot supply an independent operator's execution or signature."] };
  const bytes = `${JSON.stringify(evidence, null, 2)}\n`;
  await writeFile(resolve(directory, "owned-decide-exercise.json"), bytes, { mode: 0o600 });
  await writeFile(resolve(directory, "SHA256SUMS"), `${acceptanceDigest(bytes)}  owned-decide-exercise.json\n`, { mode: 0o600 });
  await writeFile(recoveryPath, `${JSON.stringify({ schemaVersion: 1, runId, apiOrigin: authorization.apiOrigin, stage: cleanup === "VERIFIED" ? "CLEANUP_VERIFIED" : "CLEANUP_REQUIRED", accounts: identities }, null, 2)}\n`, { mode: 0o600 });
  return { directory, evidence };
}

function field(value: unknown, name: string): unknown { return value && typeof value === "object" && Object.hasOwn(value, name) ? (value as Record<string, unknown>)[name] : undefined; }
function token(value: unknown): value is string { return typeof value === "string" && value.length >= 20 && value.length <= 8192 && !/[\0\r\n]/.test(value); }
function uuid(value: unknown): value is string { return typeof value === "string" && z.string().uuid().safeParse(value).success; }
