import { readBoundedFile } from "../core/files/BoundedFile.js";
import { createRequire } from "node:module";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { z } from "zod";
import type { DisposableDecideAccount, OwnedDecideAccountStore } from "./OwnedDecideExercise.js";

const identity = z.object({ id: z.string().uuid(), email: z.string().regex(/^rca-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}-[ab]@acceptance\.decide\.invalid$/) }).strict();
export const decideRecoverySchema = z.object({ schemaVersion: z.literal(1), runId: z.string().uuid(), apiOrigin: z.string().url(), stage: z.enum(["PROVISION_PREPARED", "PROVISIONED", "CLEANUP_REQUIRED", "CLEANUP_VERIFIED"]), accounts: z.array(identity).length(2) }).strict().refine((value) => new Set(value.accounts.map((account) => account.id)).size === 2 && new Set(value.accounts.map((account) => account.email)).size === 2 && value.accounts.every((account) => account.email.startsWith(`rca-${value.runId}-`)), "Recovery identities must belong to the exact generated run");

/** Explicit owner backend adapter. It never provisions provider administration credentials or mailboxes. */
export async function openDecideAcceptanceAccounts(options: { apiDirectory: string; environmentFile?: string; databaseCaFile: string }) {
  const root = resolve(options.apiDirectory); const metadata = JSON.parse(await readFile(resolve(root, "package.json"), "utf8")) as { name?: string; dependencies?: Record<string, string> };
  if (metadata.name !== "decide-api" || !metadata.dependencies?.bcrypt || !metadata.dependencies?.dotenv) throw new Error("OWNED_DECIDE_BACKEND_DEPENDENCIES_REQUIRED");
  const require = createRequire(resolve(root, "package.json"));
  const environmentPath = resolve(options.environmentFile ?? resolve(root, ".env"));
  if ((await stat(environmentPath)).size > 65536) throw new Error("OWNED_DECIDE_ENVIRONMENT_TOO_LARGE");
  const environment = (require("dotenv") as { parse(bytes: Buffer): Record<string, string> }).parse(await readBoundedFile(environmentPath, 65536));
  if (!environment.DATABASE_URL) throw new Error("OWNED_DECIDE_DATABASE_CREDENTIAL_REQUIRED");
  const url = new URL(environment.DATABASE_URL);
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname || !url.username || !url.password) throw new Error("OWNED_DECIDE_DATABASE_CONFIG_INVALID");
  // pg connection-string SSL options override the explicit SSL object. Reject conflicting options.
  if ([...url.searchParams.keys()].some((key) => key.toLowerCase().startsWith("ssl"))) throw new Error("OWNED_DECIDE_DATABASE_SSL_OPTIONS_MUST_USE_CA_FILE");
  const client = new pg.Client({ connectionString: url.toString(), ssl: { rejectUnauthorized: true, ca: (await readBoundedFile(options.databaseCaFile, 32768)).toString("utf8") }, connectionTimeoutMillis: 10000, query_timeout: 10000, statement_timeout: 10000, application_name: "RouteCairn-owned-disposable-acceptance" });
  try {
    await client.connect();
    const stream = (client as unknown as { connection: { stream: { encrypted?: boolean; authorized?: boolean } } }).connection.stream;
    if (!stream.encrypted || !stream.authorized) throw new Error("OWNED_DECIDE_VERIFIED_DATABASE_TLS_REQUIRED");
    const columns = await client.query<{ table_name: string; column_name: string }>("SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('users', 'mobile_auth_sessions')");
    for (const [table, names] of Object.entries({ users: ["id", "email", "password_hash", "display_name", "provider", "role", "email_verified_at"], mobile_auth_sessions: ["id", "user_id"] })) for (const name of names) if (!columns.rows.some((column) => column.table_name === table && column.column_name === name)) throw new Error("OWNED_DECIDE_DATABASE_SCHEMA_MISMATCH");
  } catch { await client.end().catch(() => undefined); throw new Error("OWNED_DECIDE_DATABASE_PREFLIGHT_FAILED"); }
  const bcrypt = require("bcrypt") as { hash(password: string, rounds: number): Promise<string> };
  const validate = (accounts: readonly Pick<DisposableDecideAccount, "id" | "email">[]) => {
    const parsed = z.array(identity).length(2).parse(accounts.map(({ id, email }) => ({ id, email })));
    const prefix = parsed[0]!.email.slice(0, 40);
    if (new Set(parsed.map((account) => account.id)).size !== 2 || new Set(parsed.map((account) => account.email)).size !== 2 || parsed.some((account) => account.email.slice(0, 40) !== prefix)) throw new Error("OWNED_DECIDE_DISPOSABLE_IDENTITY_MISMATCH");
    return parsed;
  };
  const store: OwnedDecideAccountStore = {
    async provision(accounts) {
      validate(accounts);
      const hashes = await Promise.all(accounts.map((account) => bcrypt.hash(account.password, 12)));
      await client.query("BEGIN");
      try {
        for (const [index, account] of accounts.entries()) {
          const result = await client.query("INSERT INTO public.users (id, email, password_hash, display_name, provider, role, email_verified_at) VALUES ($1,$2,$3,$4,'credentials','user',NOW()) RETURNING id", [account.id, account.email, hashes[index], account.displayName]);
          if (result.rows[0]?.id !== account.id) throw new Error("OWNED_DECIDE_PROVISION_IDENTITY_MISMATCH");
        }
        await client.query("COMMIT");
      } catch { await client.query("ROLLBACK").catch(() => undefined); throw new Error("OWNED_DECIDE_PROVISION_FAILED"); }
    },
    async remove(accounts) {
      const parsed = validate(accounts);
      await client.query("BEGIN");
      try {
        for (const account of parsed) await client.query("DELETE FROM public.users WHERE id=$1 AND email=$2 AND provider='credentials' AND role='user'", [account.id, account.email]);
        await client.query("COMMIT");
      } catch { await client.query("ROLLBACK").catch(() => undefined); throw new Error("OWNED_DECIDE_CLEANUP_FAILED"); }
    },
    async remaining(accounts) {
      const parsed = validate(accounts); const ids = parsed.map((account) => account.id);
      const users = await client.query<{ count: number }>("SELECT COUNT(*)::int AS count FROM public.users WHERE id=ANY($1::uuid[])", [ids]);
      const sessions = await client.query<{ count: number }>("SELECT COUNT(*)::int AS count FROM public.mobile_auth_sessions WHERE user_id=ANY($1::uuid[])", [ids]);
      return { users: users.rows[0]!.count, sessions: sessions.rows[0]!.count };
    }
  };
  return { store, close: () => client.end(), verifiedDatabaseTls: true as const };
}
