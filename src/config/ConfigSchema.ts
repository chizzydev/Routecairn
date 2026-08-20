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
  allowedMethods: z.array(z.enum(["GET", "HEAD", "OPTIONS", "POST"])).default(["GET", "HEAD", "OPTIONS"]),
  rateLimitPerSecond: z.number().positive().max(50).default(3),
  concurrency: z.number().int().positive().max(50).default(5),
  maxDepth: z.number().int().min(0).max(10).default(2),
  sameOriginOnly: z.boolean().default(true),
  includeSubdomains: z.boolean().default(true),
  respectRobotsTxt: z.boolean().default(false),
  userAgent: z.string().min(1).default("RouteCairn/0.1")
});

export const routeCairnConfigSchema = z.object({
  defaultMode: scanModeSchema.default("quick"),
  reportsDir: z.string().min(1).default("./reports"),
  defaultScopeFile: z.string().min(1).default("./examples/scope.example.json"),
  bodyPreviewBytes: z.number().int().positive().max(1024 * 1024).default(8192),
  requestTimeoutMs: z.number().int().positive().default(15000),
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
