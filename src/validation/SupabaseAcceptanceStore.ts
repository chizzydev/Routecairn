import { readBoundedFile } from "../core/files/BoundedFile.js";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { z } from "zod";

export const supabaseRecoverySchema = z.object({
  schemaVersion: z.literal(1), projectRef: z.string().regex(/^[a-z]{20}$/), runId: z.string().uuid(),
  stage: z.enum(["PREPARED", "PROVISIONED", "CLEANUP_REQUIRED", "CLEANUP_VERIFIED"])
}).strict();
export type SupabaseRecovery = z.infer<typeof supabaseRecoverySchema>;
export function supabaseResources(input: SupabaseRecovery) {
  const recovery = supabaseRecoverySchema.parse(input); const suffix = recovery.runId.replaceAll("-", "");
  return { table: `rca_${suffix}`, rpc: `rca_rpc_${suffix}`, policy: `rca_storage_${suffix}`, bucket: `rca-${recovery.runId}`, emails: ["a", "b"].map((part) => `rca-${recovery.runId}-${part}@acceptance.decide.invalid`) };
}
export interface SupabaseAcceptanceStore {
  provision(recovery: SupabaseRecovery, accounts: readonly string[]): Promise<void>;
  accounts(recovery: SupabaseRecovery): Promise<{ id: string; email: string }[]>;
  objects(recovery: SupabaseRecovery): Promise<string[]>;
  removeDatabase(recovery: SupabaseRecovery): Promise<void>;
  remaining(recovery: SupabaseRecovery): Promise<number>;
}

/** Only generated acceptance resources are writable. Existing application policies and tables are untouched. */
export async function openSupabaseAcceptanceStore(options: { apiDirectory: string; databaseCaFile: string; projectRef: string; environmentFile?: string }) {
  const root = resolve(options.apiDirectory); const require = createRequire(resolve(root, "package.json"));
  const metadata = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
  if (metadata.name !== "decide-api" || !metadata.dependencies?.dotenv) throw new Error("SUPABASE_OWNER_BACKEND_REQUIRED");
  const envPath = resolve(options.environmentFile ?? resolve(root, ".env"));
  const environment = (require("dotenv") as { parse(input: Buffer): Record<string, string> }).parse(await readBoundedFile(envPath, 65536));
  const url = new URL(environment.DATABASE_URL ?? "");
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.password || [...url.searchParams.keys()].some((key) => key.toLowerCase().startsWith("ssl"))) throw new Error("SUPABASE_DATABASE_CONFIG_INVALID");
  if (!(url.hostname === `db.${options.projectRef}.supabase.co` || url.hostname.endsWith(".pooler.supabase.com") && decodeURIComponent(url.username) === `postgres.${options.projectRef}`)) throw new Error("SUPABASE_DATABASE_PROJECT_MISMATCH");
  const client = new pg.Client({ connectionString: url.toString(), ssl: { rejectUnauthorized: true, ca: (await readBoundedFile(options.databaseCaFile, 32768)).toString("utf8") }, connectionTimeoutMillis: 10000, query_timeout: 10000, statement_timeout: 10000, application_name: "RouteCairn-owned-Supabase-acceptance" });
  try {
    await client.connect();
    const stream = (client as unknown as { connection: { stream: { encrypted?: boolean; authorized?: boolean } } }).connection.stream;
    if (!stream.encrypted || !stream.authorized) throw new Error();
    await client.query("SELECT id FROM auth.users LIMIT 0"); await client.query("SELECT owner_id FROM storage.objects LIMIT 0");
  } catch { await client.end().catch(() => undefined); throw new Error("SUPABASE_VERIFIED_DATABASE_PREFLIGHT_FAILED"); }
  const bind = (recovery: SupabaseRecovery) => {
    if (recovery.projectRef !== options.projectRef) throw new Error("SUPABASE_RECOVERY_PROJECT_MISMATCH");
    return supabaseResources(recovery);
  };
  const store: SupabaseAcceptanceStore = {
    async accounts(recovery) {
      const { emails } = bind(recovery);
      return (await client.query<{ id: string; email: string }>("SELECT id,email FROM auth.users WHERE email=ANY($1::text[])", [emails])).rows;
    },
    async objects(recovery) {
      const { bucket } = bind(recovery);
      const rows = (await client.query<{ name: string }>("SELECT name FROM storage.objects WHERE bucket_id=$1 ORDER BY name LIMIT 11", [bucket])).rows;
      if (rows.length > 10 || rows.some((row) => !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\/proof\.txt$/.test(row.name))) throw new Error("SUPABASE_RECOVERY_UNEXPECTED_OBJECTS");
      return rows.map((row) => row.name);
    },
    async provision(recovery, accounts) {
      const resources = bind(recovery); const actual = await store.accounts(recovery);
      if (accounts.length !== 2 || new Set(accounts).size !== 2 || actual.length !== 2 || !actual.every((account) => accounts.includes(account.id))) throw new Error("SUPABASE_PROVISION_IDENTITY_MISMATCH");
      await client.query("BEGIN");
      try {
        // All interpolated identifiers are derived solely from the validated, generated UUID.
        await client.query(`CREATE TABLE public.${resources.table} (id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES auth.users(id), payload text NOT NULL); ALTER TABLE public.${resources.table} ENABLE ROW LEVEL SECURITY; ALTER TABLE public.${resources.table} FORCE ROW LEVEL SECURITY; CREATE POLICY owner_only ON public.${resources.table} TO authenticated USING (owner_id=(SELECT auth.uid())) WITH CHECK (owner_id=(SELECT auth.uid())); GRANT SELECT,INSERT,UPDATE,DELETE ON public.${resources.table} TO authenticated; REVOKE ALL ON public.${resources.table} FROM PUBLIC,anon; CREATE FUNCTION public.${resources.rpc}(target uuid) RETURNS SETOF public.${resources.table} LANGUAGE sql STABLE SECURITY INVOKER SET search_path='' AS 'SELECT * FROM public.${resources.table} WHERE id=target'; REVOKE ALL ON FUNCTION public.${resources.rpc}(uuid) FROM PUBLIC,anon; GRANT EXECUTE ON FUNCTION public.${resources.rpc}(uuid) TO authenticated; CREATE POLICY ${resources.policy} ON storage.objects FOR ALL TO authenticated USING (bucket_id='${resources.bucket}' AND owner_id=(SELECT auth.uid()::text)) WITH CHECK (bucket_id='${resources.bucket}' AND owner_id=(SELECT auth.uid()::text));`);
        for (const id of accounts) await client.query(`INSERT INTO public.${resources.table} (id,owner_id,payload) VALUES ($1,$1,$2)`, [id, `proof-${recovery.runId}`]);
        await client.query("NOTIFY pgrst, 'reload schema'"); await client.query("COMMIT");
      } catch { await client.query("ROLLBACK").catch(() => undefined); throw new Error("SUPABASE_ISOLATED_DATABASE_PROVISION_FAILED"); }
    },
    async removeDatabase(recovery) {
      const resources = bind(recovery); await client.query("BEGIN");
      try {
        await client.query(`DROP POLICY IF EXISTS ${resources.policy} ON storage.objects; DROP FUNCTION IF EXISTS public.${resources.rpc}(uuid); DROP TABLE IF EXISTS public.${resources.table}; NOTIFY pgrst, 'reload schema';`);
        await client.query("COMMIT");
      } catch { await client.query("ROLLBACK").catch(() => undefined); throw new Error("SUPABASE_DATABASE_CLEANUP_FAILED"); }
    },
    async remaining(recovery) {
      const resources = bind(recovery);
      const result = await client.query<{ count: number }>(`SELECT ((SELECT count(*) FROM auth.users WHERE email=ANY($1::text[]))+(SELECT count(*) FROM storage.buckets WHERE id=$2)+(SELECT count(*) FROM storage.objects WHERE bucket_id=$2)+(SELECT count(*) FROM pg_policies WHERE schemaname='storage' AND tablename='objects' AND policyname=$3)+(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$4)+(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=$5))::int AS count`, [resources.emails, resources.bucket, resources.policy, resources.table, resources.rpc]);
      return result.rows[0]!.count;
    }
  };
  return { store, close: () => client.end() };
}
