import type { RouteCairnConfig, RouteCairnScope } from "./ConfigSchema.js";

export const defaultConfig: RouteCairnConfig = {
  defaultMode: "quick",
  reportsDir: "./reports",
  defaultScopeFile: "./examples/scope.example.json",
  bodyPreviewBytes: 8192,
  requestTimeoutMs: 15000,
  transport: {
    poolingEnabled: true,
    http2Enabled: false,
    maxOrigins: 64,
    maxConnectionsPerOrigin: 4,
    maxConcurrentHttp2Streams: 32,
    maxHeaderSizeBytes: 16384,
    keepAliveTimeoutMs: 10000,
    keepAliveMaxTimeoutMs: 30000,
    maxConnectionLifetimeMs: 120000,
    maxRequestsPerConnection: 1000,
    dnsCacheTtlMs: 0
  }
};

export const exampleScope: RouteCairnScope = {
  program: "Authorized Security Test",
  allowedDomains: ["example.com", "*.example.com"],
  disallowedPaths: ["/logout", "/delete", "/checkout", "/payment", "/cart/remove"],
  allowedMethods: ["GET", "HEAD", "OPTIONS"],
  rateLimitPerSecond: 3,
  concurrency: 5,
  maxDepth: 2,
  sameOriginOnly: true,
  includeSubdomains: true,
  respectRobotsTxt: false,
  userAgent: "RouteCairn/0.1"
};
