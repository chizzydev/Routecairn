import { randomBytes, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import { runBoundedHttp } from "../modules/protocolSecurity/ProtocolTransports.js";
import { acceptanceDigest } from "./ExternalAcceptanceReadiness.js";
import { supabaseRecoverySchema, supabaseResources, type SupabaseAcceptanceStore, type SupabaseRecovery } from "./SupabaseAcceptanceStore.js";

export const ownedSupabaseAuthorizationSchema = z.object({
  schemaVersion: z.literal(1), projectRef: z.string().regex(/^[a-z]{20}$/),
  authorizedBy: z.string().min(2).max(160), authorizationReference: z.string().min(3).max(500),
  startsAt: z.string().datetime(), expiresAt: z.string().datetime(), maxRequests: z.number().int().min(40).max(60),
  rateLimitPerSecond: z.number().min(0.1).max(2), disposableAccounts: z.literal(2),
  isolatedTableRpcAndStorage: z.literal(true), deleteCreatedResources: z.literal(true),
  cleanupGraceMs: z.number().int().min(60000).max(3600000).default(300000)
}).strict().refine((value) => Date.parse(value.expiresAt) > Date.parse(value.startsAt), "Authorization window is invalid");
export type OwnedSupabaseAuthorization = z.infer<typeof ownedSupabaseAuthorizationSchema>;
export const supabasePrivateCredentialsSchema = z.object({ projectRef: z.string().regex(/^[a-z]{20}$/), publishableKey: z.string().regex(/^sb_publishable_[A-Za-z0-9_-]+$/), secretKey: z.string().regex(/^sb_secret_[A-Za-z0-9_-]+$/) }).strict();
export type SupabasePrivateCredentials = z.infer<typeof supabasePrivateCredentialsSchema>;
type Receipt = { case: string; status: "PASSED" | "FAILED" | "PENDING"; statusCode?: number; bodySha256?: string; responseBytes?: number; observation?: string };
type Response = { status: number; data: unknown; body: Buffer };
const field = (value: unknown, key: string): unknown => value !== null && typeof value === "object" ? (value as Record<string, unknown>)[key] : undefined;
const success = (value: Response) => value.status >= 200 && value.status < 300;
const denied = (value: Response) => [400, 401, 403, 404].includes(value.status);

function createTransport(authorization: OwnedSupabaseAuthorization, credentials: SupabasePrivateCredentials, started: number, receipts: Receipt[]) {
  let count = 0; let lastAt = 0;
  const deadline = Math.min(Date.parse(authorization.expiresAt), started + 600000);
  const request = async (caseName: string, method: string, path: string, body: unknown, token: string | "ADMIN" | undefined, check: (value: Response) => boolean, cleanup = false, raw = false) => {
    const limit = deadline + (cleanup ? authorization.cleanupGraceMs : 0);
    // Reserve eight requests for cleanup before any further primary action.
    if (Date.now() >= limit || count >= authorization.maxRequests - (cleanup ? 0 : 8)) throw new Error("SUPABASE_BUDGET_OR_WINDOW_EXHAUSTED");
    const wait = Math.max(0, lastAt + Math.ceil(1000 / authorization.rateLimitPerSecond) - Date.now());
    if (wait) await new Promise((done) => setTimeout(done, wait));
    const timeoutMs = Math.min(10000, limit - Date.now()); if (timeoutMs <= 0) throw new Error("SUPABASE_AUTHORIZATION_EXPIRED");
    lastAt = Date.now(); count += 1;
    const admin = token === "ADMIN"; const key = admin ? credentials.secretKey : credentials.publishableKey;
    let response: Awaited<ReturnType<typeof runBoundedHttp>>;
    try { response = await runBoundedHttp(`https://${authorization.projectRef}.supabase.co${path}`, method,
      { apikey: key, ...(token ? { authorization: `Bearer ${admin ? key : token}` } : {}), ...(body === undefined ? {} : { "content-type": raw ? "text/plain" : "application/json" }), accept: "application/json", "user-agent": "RouteCairn-owned-Supabase-acceptance/0.1" },
      body === undefined ? undefined : Buffer.from(raw ? String(body) : JSON.stringify(body)),
      { allowedPrivateOrigins: [], timeoutMs, abortSignal: AbortSignal.timeout(timeoutMs), maxBytes: 65536 }); }
    catch { receipts.push({ case: caseName, status: "FAILED", observation: "TRANSPORT_FAILED" }); throw new Error("SUPABASE_TRANSPORT_FAILED"); }
    let data: unknown; try { data = JSON.parse(response.body.toString("utf8")); } catch { data = undefined; }
    const value = { status: response.statusCode, data, body: response.body };
    receipts.push({ case: caseName, status: check(value) ? "PASSED" : "FAILED", statusCode: value.status, bodySha256: acceptanceDigest(value.body), responseBytes: value.body.length });
    return value;
  };
  return { request, count: () => count };
}

async function cleanupSupabase(recovery: SupabaseRecovery, store: SupabaseAcceptanceStore, request: ReturnType<typeof createTransport>["request"], deadline: number) {
  const resources = supabaseResources(recovery); const failures: string[] = [];
  if (Date.now() >= deadline) return { status: "REQUIRED", remaining: undefined, failures: ["CLEANUP_AUTHORIZATION_EXPIRED"] };
  // Recover ambiguous provisioning responses by looking up only this run's exact generated emails.
  let accounts: { id: string; email: string }[] = [];
  try { accounts = await store.accounts(recovery); } catch { failures.push("ACCOUNT_LOOKUP_FAILED"); }
  try {
    const paths = await store.objects(recovery);
    if (paths.length) {
      const removed = await request("STORAGE_OBJECTS_DELETE", "DELETE", `/storage/v1/object/${resources.bucket}`, { prefixes: paths }, "ADMIN", success, true);
      if (!success(removed)) failures.push("STORAGE_OBJECTS_DELETE");
    }
  } catch { failures.push("STORAGE_OBJECTS_DELETE"); }
  try {
    const value = await request("STORAGE_BUCKET_DELETE", "DELETE", `/storage/v1/bucket/${resources.bucket}`, {}, "ADMIN", (result) => success(result) || result.status === 404 || field(result.data, "message") === "Bucket not found", true);
    if (!success(value) && value.status !== 404 && field(value.data, "message") !== "Bucket not found") failures.push("STORAGE_BUCKET_DELETE");
  } catch { failures.push("STORAGE_BUCKET_DELETE"); }
  // Drop the acceptance table first so its FK cannot prevent deletion of disposable auth users.
  try { if (Date.now() >= deadline) throw new Error(); await store.removeDatabase(recovery); } catch { failures.push("DATABASE_CLEANUP_FAILED"); }
  for (const account of accounts) {
    try { const value = await request(`AUTH_ACCOUNT_DELETE_${account.email.includes("-a@") ? "A" : "B"}`, "DELETE", `/auth/v1/admin/users/${z.string().uuid().parse(account.id)}`, {}, "ADMIN", (result) => success(result) || result.status === 404, true); if (!success(value) && value.status !== 404) failures.push("AUTH_ACCOUNT_DELETE"); } catch { failures.push("AUTH_ACCOUNT_DELETE"); }
  }
  let remaining: number | undefined;
  try { remaining = await store.remaining(recovery); } catch { failures.push("ABSENCE_CHECK_FAILED"); }
  return { status: remaining === 0 && !failures.length ? "VERIFIED" : "REQUIRED", remaining, failures };
}

export async function recoverOwnedSupabase(input: SupabaseRecovery, authorizationInput: OwnedSupabaseAuthorization, credentialInput: SupabasePrivateCredentials, store: SupabaseAcceptanceStore) {
  const recovery = supabaseRecoverySchema.parse(input); const authorization = ownedSupabaseAuthorizationSchema.parse(authorizationInput); const credentials = supabasePrivateCredentialsSchema.parse(credentialInput);
  if (recovery.projectRef !== authorization.projectRef || credentials.projectRef !== authorization.projectRef || Date.now() < Date.parse(authorization.startsAt) || Date.now() >= Date.parse(authorization.expiresAt) + authorization.cleanupGraceMs) throw new Error("SUPABASE_RECOVERY_AUTHORIZATION_INACTIVE_OR_MISMATCH");
  const receipts: Receipt[] = []; const transport = createTransport(authorization, credentials, Date.now(), receipts);
  return { ...await cleanupSupabase(recovery, store, transport.request, Date.parse(authorization.expiresAt) + authorization.cleanupGraceMs), requestCount: transport.count(), receipts };
}

/** Real hosted provider behavior on isolated owner-created fixtures, not independently maintained acceptance. */
export async function exerciseOwnedSupabase(input: OwnedSupabaseAuthorization, credentialInput: SupabasePrivateCredentials, store: SupabaseAcceptanceStore, outputParent: string) {
  const authorization = ownedSupabaseAuthorizationSchema.parse(input); const credentials = supabasePrivateCredentialsSchema.parse(credentialInput); const started = Date.now();
  if (credentials.projectRef !== authorization.projectRef || started < Date.parse(authorization.startsAt) || started >= Date.parse(authorization.expiresAt)) throw new Error("SUPABASE_AUTHORIZATION_INACTIVE_OR_MISMATCH");
  const runId = randomUUID(); const recovery: SupabaseRecovery = { schemaVersion: 1, projectRef: authorization.projectRef, runId, stage: "PREPARED" }; const resources = supabaseResources(recovery);
  await mkdir(resolve(outputParent), { recursive: true }); const directory = await mkdtemp(resolve(outputParent, "supabase-owned-")); const recoveryPath = resolve(directory, "private-recovery.json");
  const journal = () => writeFile(recoveryPath, `${JSON.stringify(recovery, null, 2)}\n`, { mode: 0o600 }); await journal();
  const receipts: Receipt[] = []; const transport = createTransport(authorization, credentials, started, receipts); const request = transport.request;
  const accounts: { id: string; email: string; password: string; token: string }[] = []; let primaryError: string | undefined;
  let cleanup: Awaited<ReturnType<typeof cleanupSupabase>> = { status: "REQUIRED", remaining: undefined, failures: [] };
  try {
    for (const email of resources.emails) {
      const password = `Rca!${randomBytes(32).toString("base64url")}`;
      const created = await request(`AUTH_ADMIN_CREATE_${email.includes("-a@") ? "A" : "B"}`, "POST", "/auth/v1/admin/users", { email, password, email_confirm: true, app_metadata: { routecairn_run: runId } }, "ADMIN", (value) => success(value) && field(value.data, "email") === email && z.string().uuid().safeParse(field(value.data, "id")).success);
      const id = z.string().uuid().parse(field(created.data, "id"));
      if (!success(created) || field(created.data, "email") !== email) throw new Error("SUPABASE_AUTH_PROVISION_FAILED");
      const login = await request(`AUTH_PASSWORD_LOGIN_${email.includes("-a@") ? "A" : "B"}`, "POST", "/auth/v1/token?grant_type=password", { email, password }, undefined, (value) => success(value) && field(field(value.data, "user"), "id") === id && typeof field(value.data, "access_token") === "string");
      if (!success(login) || field(field(login.data, "user"), "id") !== id || typeof field(login.data, "access_token") !== "string") throw new Error("SUPABASE_LOGIN_FAILED");
      accounts.push({ id, email, password, token: field(login.data, "access_token") as string });
    }
    if (Date.now() >= Math.min(Date.parse(authorization.expiresAt), started + 600000)) throw new Error("SUPABASE_AUTHORIZATION_EXPIRED");
    await store.provision(recovery, accounts.map((account) => account.id)); recovery.stage = "PROVISIONED"; await journal();
    let ready = false;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const value = await request(`SCHEMA_CACHE_READINESS_${attempt}`, "GET", `/rest/v1/${resources.table}?select=id&limit=0`, undefined, accounts[0]!.token, (response) => response.status === 200 && Array.isArray(response.data));
      if (value.status === 200 && Array.isArray(value.data)) { ready = true; break; }
      if (value.status === 404 && field(value.data, "code") === "PGRST205") { receipts[receipts.length - 1]!.status = "PENDING"; receipts[receipts.length - 1]!.observation = "POSTGREST_SCHEMA_CACHE_NOT_YET_PROPAGATED"; }
      else break;
    }
    if (!ready) throw new Error("SUPABASE_SCHEMA_CACHE_NOT_READY");
    const bucket = await request("PRIVATE_BUCKET_CREATE", "POST", "/storage/v1/bucket", { id: resources.bucket, name: resources.bucket, public: false, file_size_limit: 4096, allowed_mime_types: ["text/plain"] }, "ADMIN", success);
    if (!success(bucket)) throw new Error("SUPABASE_BUCKET_PROVISION_FAILED");
    const [a, b] = accounts as [typeof accounts[number], typeof accounts[number]]; const proof = `proof-${runId}`;
    const row = (value: Response, id: string) => value.status === 200 && Array.isArray(value.data) && value.data.length === 1 && field(value.data[0], "id") === id && field(value.data[0], "payload") === proof;
    const invisible = (value: Response) => value.status === 200 && Array.isArray(value.data) && value.data.length === 0;
    const path = `/rest/v1/${resources.table}?id=eq.${a.id}&select=id,owner_id,payload`;
    await request("SUPABASE_TABLE_OWNER_ALLOWED", "GET", path, undefined, a.token, (value) => row(value, a.id));
    await request("SUPABASE_TABLE_FOREIGN_DENIED", "GET", path, undefined, b.token, invisible);
    await request("SUPABASE_TABLE_ANONYMOUS_DENIED", "GET", path, undefined, undefined, denied);
    await request("SUPABASE_TABLE_FOREIGN_UPDATE_DENIED", "PATCH", path, { payload: "foreign-change" }, b.token, (value) => value.status === 204 || invisible(value) || denied(value));
    await request("SUPABASE_TABLE_OWNER_UNCHANGED", "GET", path, undefined, a.token, (value) => row(value, a.id));
    await request("SUPABASE_TABLE_OWNER_ALLOWED_B", "GET", `/rest/v1/${resources.table}?id=eq.${b.id}&select=id,owner_id,payload`, undefined, b.token, (value) => row(value, b.id));
    await request("SUPABASE_RPC_OWNER_ALLOWED", "POST", `/rest/v1/rpc/${resources.rpc}`, { target: a.id }, a.token, (value) => row(value, a.id));
    await request("SUPABASE_RPC_FOREIGN_DENIED", "POST", `/rest/v1/rpc/${resources.rpc}`, { target: a.id }, b.token, invisible);
    await request("SUPABASE_RPC_ANONYMOUS_DENIED", "POST", `/rest/v1/rpc/${resources.rpc}`, { target: a.id }, undefined, denied);
    const object = `${resources.bucket}/${a.id}/proof.txt`; const objectPath = `/storage/v1/object/${object}`;
    const upload = await request("SUPABASE_STORAGE_OWNER_UPLOAD", "POST", objectPath, proof, a.token, success, false, true);
    if (!success(upload)) throw new Error("SUPABASE_STORAGE_UPLOAD_FAILED");
    await request("SUPABASE_STORAGE_OWNER_ALLOWED", "GET", `/storage/v1/object/authenticated/${object}`, undefined, a.token, (value) => value.status === 200 && value.body.toString() === proof);
    await request("SUPABASE_STORAGE_FOREIGN_DENIED", "GET", `/storage/v1/object/authenticated/${object}`, undefined, b.token, denied);
    await request("SUPABASE_STORAGE_ANONYMOUS_DENIED", "GET", `/storage/v1/object/authenticated/${object}`, undefined, undefined, denied);
    await request("SUPABASE_STORAGE_PUBLIC_DENIED", "GET", `/storage/v1/object/public/${object}`, undefined, undefined, denied);
    await request("SUPABASE_STORAGE_FOREIGN_OVERWRITE_DENIED", "PUT", objectPath, "foreign-change", b.token, denied, false, true);
    await request("SUPABASE_STORAGE_OWNER_UNCHANGED", "GET", `/storage/v1/object/authenticated/${object}`, undefined, a.token, (value) => value.status === 200 && value.body.toString() === proof);
  } catch (error) { primaryError = error instanceof Error && /^SUPABASE_[A-Z_]+$/.test(error.message) ? error.message : "SUPABASE_PROVISION_OR_EXECUTION_FAILED"; }
  finally {
    recovery.stage = "CLEANUP_REQUIRED";
    try { await journal(); } catch { primaryError ??= "SUPABASE_RECOVERY_JOURNAL_FAILED"; }
    cleanup = await cleanupSupabase(recovery, store, request, Math.min(Date.parse(authorization.expiresAt), started + 600000) + authorization.cleanupGraceMs);
    for (const account of accounts) { account.password = ""; account.token = ""; }
    recovery.stage = cleanup.status === "VERIFIED" ? "CLEANUP_VERIFIED" : "CLEANUP_REQUIRED"; await journal();
  }
  const evidence = { schemaVersion: 1, standard: "OWNED_HOSTED_SUPABASE_EXERCISE_V1", runId, projectOrigin: `https://${authorization.projectRef}.supabase.co`, startedAt: new Date(started).toISOString(), completedAt: new Date().toISOString(), authorizationSha256: acceptanceDigest(Buffer.from(JSON.stringify(authorization))), status: !primaryError && cleanup.status === "VERIFIED" && receipts.every((receipt) => receipt.status !== "FAILED") ? "PASSED" : "FAILED", requestCount: transport.count(), disposableAccounts: 2, receipts, cleanup, ...(primaryError ? { primaryError } : {}), externalTargetsTested: true, independentlyOperated: false, independentAcceptanceVerified: false, fullEightLaneAcceptance: false, limitations: ["Owner-created isolated fixtures on the real hosted Supabase service; this does not establish existing Decide application RLS correctness.", "Email is administratively confirmed. This does not establish independent operator, OIDC/MFA/passkey or payment acceptance."] };
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`); await writeFile(resolve(directory, "owned-supabase-exercise.json"), bytes); await writeFile(resolve(directory, "SHA256SUMS"), `${acceptanceDigest(bytes)}  owned-supabase-exercise.json\n`);
  return { directory, evidence };
}
