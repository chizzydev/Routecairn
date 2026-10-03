import { readFileSync } from "node:fs";
import { z } from "zod";

const nonEmpty = z.string().trim().min(1);

export const controlPlaneConfigSchema = z.object({
  mode: z.enum(["local", "distributed"]),
  instanceId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/),
  postgres: z.object({
    url: nonEmpty,
    maxConnections: z.number().int().min(2).max(100),
    statementTimeoutMs: z.number().int().min(1_000).max(120_000),
    ssl: z.object({ ca: z.string().optional(), cert: z.string().optional(), key: z.string().optional(), rejectUnauthorized: z.boolean() }).strict().optional()
  }).strict().optional(),
  objectStorage: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("local") }).strict(),
    z.object({
      kind: z.literal("s3"), bucket: nonEmpty, region: nonEmpty, endpoint: z.string().url().optional(),
      forcePathStyle: z.boolean(), prefix: z.string().regex(/^[a-zA-Z0-9/_.-]{0,200}$/), kmsKeyId: nonEmpty.optional(), accessKeyId: nonEmpty.optional(), secretAccessKey: nonEmpty.optional(),
      encryption: z.enum(["AES256", "aws:kms", "provider"]).default("AES256")
    }).strict()
  ]),
  leader: z.object({ leaseMs: z.number().int().min(5_000).max(300_000) }).strict(),
  queue: z.object({ leaseMs: z.number().int().min(15_000).max(3_600_000), claimWaitMs: z.number().int().min(0).max(30_000) }).strict(),
  telemetry: z.object({ serviceName: nonEmpty, otlpEndpoint: z.string().url().optional(), logLevel: z.enum(["debug", "info", "warn", "error"]) }).strict(),
  workloadIdentity: z.object({
    required: z.boolean(),
    trustedIssuers: z.array(z.string().url().refine((value)=>{const url=new URL(value);return url.protocol==="https:"&&!url.username&&!url.password&&!url.search&&!url.hash;},"Workload issuers require exact HTTPS identities.")).max(20),
    audience: nonEmpty.optional(),
    directMtls: z.boolean().default(false),
    mtlsProxySecret: z.string().min(32).optional()
  }).strict()
}).strict().superRefine((value, context) => {
  if (value.mode === "distributed" && !value.postgres) context.addIssue({ code: z.ZodIssueCode.custom, path: ["postgres"], message: "Distributed mode requires PostgreSQL." });
  if (value.workloadIdentity.required && value.workloadIdentity.trustedIssuers.length === 0 && !value.workloadIdentity.mtlsProxySecret && !value.workloadIdentity.directMtls) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["workloadIdentity"], message: "Required workload identity needs a trusted issuer or authenticated mTLS proxy." });
  }
  if (value.objectStorage.kind === "s3" && Boolean(value.objectStorage.accessKeyId) !== Boolean(value.objectStorage.secretAccessKey)) context.addIssue({ code: z.ZodIssueCode.custom, path: ["objectStorage"], message: "S3 access key and secret key must be supplied together." });
  if (value.objectStorage.kind === "s3" && value.objectStorage.encryption === "aws:kms" && !value.objectStorage.kmsKeyId) context.addIssue({ code: z.ZodIssueCode.custom, path: ["objectStorage"], message: "KMS encryption requires a key identity." });
  if(value.workloadIdentity.trustedIssuers.length&&!value.workloadIdentity.audience)context.addIssue({code:z.ZodIssueCode.custom,path:["workloadIdentity","audience"],message:"Workload OIDC requires an audience."});
  if(value.postgres?.ssl&&Boolean(value.postgres.ssl.cert)!==Boolean(value.postgres.ssl.key))context.addIssue({code:z.ZodIssueCode.custom,path:["postgres","ssl"],message:"PostgreSQL client certificates require their matching key."});
});

export type ControlPlaneConfig = z.infer<typeof controlPlaneConfigSchema>;

export function controlPlaneConfigFromEnv(environment: NodeJS.ProcessEnv = process.env): ControlPlaneConfig {
  const databaseUrl = secretFile(environment, "ROUTECAIRN_DATABASE_URL");
  const mode = (value(environment.ROUTECAIRN_CONTROL_PLANE_MODE) ?? (databaseUrl ? "distributed" : "local")) as "local" | "distributed";
  const s3Bucket = value(environment.ROUTECAIRN_EVIDENCE_S3_BUCKET);
  const ca = secretFile(environment, "ROUTECAIRN_POSTGRES_CA");
  const cert = secretFile(environment, "ROUTECAIRN_POSTGRES_CERT");
  const key = secretFile(environment, "ROUTECAIRN_POSTGRES_KEY");
  return controlPlaneConfigSchema.parse({
    mode,
    instanceId: value(environment.ROUTECAIRN_INSTANCE_ID) ?? `routecairn-${process.pid}`,
    ...(databaseUrl ? { postgres: {
      url: databaseUrl,
      maxConnections: integer(environment.ROUTECAIRN_POSTGRES_POOL_SIZE, 12),
      statementTimeoutMs: integer(environment.ROUTECAIRN_POSTGRES_STATEMENT_TIMEOUT_MS, 30_000),
      ...(ca || cert || key ? { ssl: { ...(ca ? { ca } : {}), ...(cert ? { cert } : {}), ...(key ? { key } : {}), rejectUnauthorized: environment.ROUTECAIRN_POSTGRES_TLS_INSECURE !== "true" } } : {})
    } } : {}),
    objectStorage: s3Bucket ? {
      kind: "s3", bucket: s3Bucket, region: value(environment.AWS_REGION) ?? "us-east-1",
      ...(value(environment.ROUTECAIRN_EVIDENCE_S3_ENDPOINT) ? { endpoint: value(environment.ROUTECAIRN_EVIDENCE_S3_ENDPOINT) } : {}),
      forcePathStyle: environment.ROUTECAIRN_EVIDENCE_S3_PATH_STYLE === "true",
      prefix: value(environment.ROUTECAIRN_EVIDENCE_S3_PREFIX) ?? "routecairn",
      encryption: value(environment.ROUTECAIRN_EVIDENCE_S3_ENCRYPTION) ?? (value(environment.ROUTECAIRN_EVIDENCE_KMS_KEY_ID) ? "aws:kms" : "AES256"),
      ...(value(environment.ROUTECAIRN_EVIDENCE_KMS_KEY_ID) ? { kmsKeyId: value(environment.ROUTECAIRN_EVIDENCE_KMS_KEY_ID) } : {}),
      ...(secretFile(environment, "AWS_ACCESS_KEY_ID") ? { accessKeyId: secretFile(environment, "AWS_ACCESS_KEY_ID") } : {}),
      ...(secretFile(environment, "AWS_SECRET_ACCESS_KEY") ? { secretAccessKey: secretFile(environment, "AWS_SECRET_ACCESS_KEY") } : {})
    } : { kind: "local" },
    leader: { leaseMs: integer(environment.ROUTECAIRN_LEADER_LEASE_MS, 30_000) },
    queue: { leaseMs: integer(environment.ROUTECAIRN_JOB_LEASE_MS, 60_000), claimWaitMs: integer(environment.ROUTECAIRN_JOB_CLAIM_WAIT_MS, 20_000) },
    telemetry: {
      serviceName: value(environment.OTEL_SERVICE_NAME) ?? "routecairn-control-plane",
      ...(value(environment.OTEL_EXPORTER_OTLP_ENDPOINT) ? { otlpEndpoint: value(environment.OTEL_EXPORTER_OTLP_ENDPOINT) } : {}),
      logLevel: (value(environment.ROUTECAIRN_LOG_LEVEL) ?? "info") as "debug" | "info" | "warn" | "error"
    },
    workloadIdentity: {
      required: environment.ROUTECAIRN_WORKLOAD_IDENTITY_REQUIRED === "true",
      trustedIssuers: csv(environment.ROUTECAIRN_WORKLOAD_IDENTITY_ISSUERS),
      directMtls: environment.ROUTECAIRN_WORKLOAD_IDENTITY_DIRECT_MTLS === "true",
      ...(value(environment.ROUTECAIRN_WORKLOAD_IDENTITY_AUDIENCE) ? { audience: value(environment.ROUTECAIRN_WORKLOAD_IDENTITY_AUDIENCE) } : {}),
      ...(secretFile(environment, "ROUTECAIRN_MTLS_PROXY_SECRET") ? { mtlsProxySecret: secretFile(environment, "ROUTECAIRN_MTLS_PROXY_SECRET") } : {})
    }
  });
}

function value(input: string | undefined): string | undefined { const result = input?.trim(); return result ? result : undefined; }
function csv(input: string | undefined): string[] { return [...new Set((input ?? "").split(",").map((item) => item.trim()).filter(Boolean))]; }
function integer(input: string | undefined, fallback: number): number { const result = Number(input); return Number.isInteger(result) ? result : fallback; }
function secretFile(environment: NodeJS.ProcessEnv, name: string): string | undefined {
  const direct = value(environment[name]);
  const file = value(environment[`${name}_FILE`]);
  if (direct && file) throw new Error(`${name} and ${name}_FILE are mutually exclusive.`);
  if (!file) return direct;
  const content = readFileSync(file, "utf8").replace(/[\r\n]+$/, "");
  return content || undefined;
}
