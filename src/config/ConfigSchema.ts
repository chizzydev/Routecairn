import { z } from "zod";

export const scanModeSchema = z.enum([
  "quick",
  "full",
  "js",
  "api",
  "admin",
  "backup",
  "headers",
  "cookies",
  "cors",
  "methods",
  "browser"
]);

export const scopeSchema = z.object({
  program: z.string().min(1),
  allowedDomains: z.array(z.string().min(1)).min(1),
  disallowedPaths: z.array(z.string().startsWith("/")).default([]),
  allowedMethods: z.array(z.enum(["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"])).default(["GET", "HEAD", "OPTIONS"]),
  rateLimitPerSecond: z.number().positive().max(50).default(3),
  concurrency: z.number().int().positive().max(50).default(5),
  maxDepth: z.number().int().min(0).max(10).default(2),
  sameOriginOnly: z.boolean().default(true),
  includeSubdomains: z.boolean().default(true),
  respectRobotsTxt: z.boolean().default(false),
  userAgent: z.string().min(1).default("RouteCairn/0.1")
});

export const transportConfigSchema = z.object({
  poolingEnabled: z.boolean().default(true),
  http2Enabled: z.boolean().default(false),
  maxOrigins: z.number().int().min(1).max(1024).default(64),
  maxConnectionsPerOrigin: z.number().int().min(1).max(32).default(4),
  maxConcurrentHttp2Streams: z.number().int().min(1).max(256).default(32),
  maxHeaderSizeBytes: z.number().int().min(4096).max(65536).default(16384),
  keepAliveTimeoutMs: z.number().int().min(100).max(120000).default(10000),
  keepAliveMaxTimeoutMs: z.number().int().min(100).max(300000).default(30000),
  maxConnectionLifetimeMs: z.number().int().min(1000).max(900000).default(120000),
  maxRequestsPerConnection: z.number().int().min(1).max(10000).default(1000),
  dnsCacheTtlMs: z.number().int().min(0).max(60000).default(0)
}).strict().refine((value) => value.keepAliveMaxTimeoutMs >= value.keepAliveTimeoutMs, "keepAliveMaxTimeoutMs must be greater than or equal to keepAliveTimeoutMs.");

export const routeCairnConfigSchema = z.object({
  defaultMode: scanModeSchema.default("quick"),
  reportsDir: z.string().min(1).default("./reports"),
  defaultScopeFile: z.string().min(1).default("./examples/scope.example.json"),
  bodyPreviewBytes: z.number().int().positive().max(1024 * 1024).default(8192),
  requestTimeoutMs: z.number().int().positive().default(15000),
  transport: transportConfigSchema.default({}),
  nextJsReview: z.object({
    inspectNextJsSourceMaps: z.boolean().optional(),
    inspectKnownNextJsDataSurfaces: z.boolean().optional(),
    nextJsCacheReviewMode: z.enum(["PASSIVE_CACHE_REVIEW", "CONTROLLED_CACHE_DIFFERENTIAL"]).optional(),
    maxNextJsManifestRequests: z.number().int().positive().max(32).optional(),
    maxNextJsDataSurfaceRequests: z.number().int().positive().max(64).optional(),
    maxNextJsSourceMapRequests: z.number().int().positive().max(32).optional(),
    maxNextJsCacheDifferentialRequests: z.number().int().min(0).max(12).optional(),
    maxNextJsAssetsInspected: z.number().int().positive().max(500).optional(),
    maxNextJsRoutesProcessed: z.number().int().positive().max(2000).optional()
  }).strict().optional()
});

export type ScanMode = z.infer<typeof scanModeSchema>;
export type RouteCairnScope = z.infer<typeof scopeSchema>;
export type RouteCairnConfig = z.infer<typeof routeCairnConfigSchema>;
