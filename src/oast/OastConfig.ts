import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";
import { AppError } from "../core/errors/AppError.js";

const environmentName = z.string().regex(/^[A-Z][A-Z0-9_]{2,80}$/);
const hostname = z.string().min(1).max(253).regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i);
const tenantName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;

export const oastServiceConfigSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  mode: z.enum(["SELF_HOSTED", "HOSTED"]),
  listenHost: z.string().ip().default("127.0.0.1"),
  httpPort: z.number().int().min(1).max(65535),
  httpsPort: z.number().int().min(1).max(65535).optional(),
  dnsUdpPort: z.number().int().min(1).max(65535).default(53),
  dnsTcpPort: z.number().int().min(1).max(65535).default(53),
  baseDomain: hostname.refine((value) => value.length <= 187, "Base domain must leave space for two signed callback labels."),
  dnsNameServers: z.array(hostname).min(1).max(4).refine((value) => new Set(value.map((name) => name.toLowerCase())).size === value.length).optional(),
  dnsSoaSerial: z.number().int().min(1).max(0xffffffff).optional(),
  publishIpv6: z.boolean().optional(),
  maxConnections: z.number().int().min(4).max(10000).optional(),
  maxRequestsPerSecond: z.number().int().min(1).max(10000).optional(),
  maxLeases: z.number().int().min(1).max(1000000).optional(),
  evidenceRetentionSeconds: z.number().int().min(60).max(90 * 86400).optional(),
  publicHttpBaseUrl: z.string().url().optional(),
  publicHttpsBaseUrl: z.string().url().optional(),
  databasePath: z.string().min(1).max(4096),
  signingKeyEnv: environmentName.default("ROUTECAIRN_OAST_SIGNING_KEY"),
  tenantTokensEnv: environmentName.default("ROUTECAIRN_OAST_TENANT_TOKENS"),
  tlsKeyPath: z.string().min(1).max(4096).optional(),
  tlsCertPath: z.string().min(1).max(4096).optional(),
  maxLeaseSeconds: z.number().int().min(30).max(7 * 24 * 60 * 60).default(86400),
  maxEventsPerLease: z.number().int().min(1).max(100).default(20),
  maxRequestBytes: z.number().int().min(1024).max(1024 * 1024).default(65536),
  dnsAnswerIpv4: z.string().ip({ version: "v4" }).default("127.0.0.1"),
  dnsAnswerIpv6: z.string().ip({ version: "v6" }).default("::1")
}).strict().superRefine((value, ctx) => {
  for (const name of value.dnsNameServers ?? []) if (!name.toLowerCase().endsWith(`.${value.baseDomain.toLowerCase()}`)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Nameserver names must be below the configured authoritative zone." });
  if (value.httpPort === value.httpsPort || [value.httpPort, value.httpsPort].includes(value.dnsTcpPort)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "TCP listener ports must be distinct." });
  if ((value.tlsKeyPath || value.tlsCertPath) && !value.httpsPort) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "TLS certificate paths require an HTTPS listener." });
  if (value.publicHttpsBaseUrl && !value.httpsPort) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "HTTPS callback origin requires an HTTPS listener." });
  if ((value.tlsKeyPath && !value.tlsCertPath) || (!value.tlsKeyPath && value.tlsCertPath)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "TLS key and certificate paths must be supplied together." });
  if (value.httpsPort && !(value.tlsKeyPath && value.tlsCertPath)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "HTTPS requires TLS key and certificate paths." });
  if (value.mode === "HOSTED" && (!value.publicHttpsBaseUrl || !value.httpsPort)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Hosted OAST mode requires a public HTTPS base URL and HTTPS listener." });
  for (const [label, candidate, protocol] of [["HTTP", value.publicHttpBaseUrl, "http:"], ["HTTPS", value.publicHttpsBaseUrl, "https:"]] as const) {
    if (!candidate) continue;
    const parsed = new URL(candidate);
    if (parsed.protocol !== protocol || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) ctx.addIssue({ code: z.ZodIssueCode.custom, message: `${label} public base URL must be a credential-free origin.` });
  }
}).transform((value) => ({ ...value, databasePath: resolve(value.databasePath), ...(value.tlsKeyPath ? { tlsKeyPath: resolve(value.tlsKeyPath) } : {}), ...(value.tlsCertPath ? { tlsCertPath: resolve(value.tlsCertPath) } : {}) }));

export type OastServiceConfig = z.infer<typeof oastServiceConfigSchema> & { sourceSha256?: string };

export async function loadOastServiceConfig(path: string): Promise<OastServiceConfig> {
  let value: unknown;
  let source: Buffer;
  try { source = await readFile(resolve(path)); value = JSON.parse(source.toString("utf8")); }
  catch { throw new AppError("OAST service configuration is not valid JSON.", "OAST_CONFIG_INVALID"); }
  const parsed = oastServiceConfigSchema.safeParse(value);
  if (!parsed.success) throw new AppError(parsed.error.message, "OAST_CONFIG_INVALID");
  return { ...parsed.data, sourceSha256: createHash("sha256").update(source).digest("hex") };
}

export function readOastServiceSecrets(config: OastServiceConfig): { signingKey: Buffer; tenantTokens: ReadonlyMap<string, string> } {
  const signing = process.env[config.signingKeyEnv];
  if (!signing || Buffer.byteLength(signing) < 32) throw new AppError(`${config.signingKeyEnv} must contain at least 32 bytes.`, "OAST_SIGNING_KEY_REQUIRED");
  const encodedTokens = process.env[config.tenantTokensEnv];
  let rawTokens: unknown;
  try { rawTokens = JSON.parse(encodedTokens ?? ""); }
  catch { throw new AppError(`${config.tenantTokensEnv} must contain a JSON object of tenant IDs to API tokens.`, "OAST_TENANT_TOKENS_REQUIRED"); }
  const tokens = z.record(z.string(), z.string().min(24).max(200).regex(/^[A-Za-z0-9._~-]+$/)).refine((value) => Object.keys(value).length > 0 && Object.keys(value).length <= 1000 && Object.keys(value).every((key) => tenantName.test(key)) && new Set(Object.values(value)).size === Object.values(value).length).safeParse(rawTokens);
  if (!tokens.success) throw new AppError(`${config.tenantTokensEnv} must contain 1 to 1000 tenant API tokens of at least 24 characters.`, "OAST_TENANT_TOKENS_REQUIRED");
  return { signingKey: Buffer.from(signing), tenantTokens: new Map(Object.entries(tokens.data)) };
}
