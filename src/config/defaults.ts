import type { RouteCairnConfig, RouteCairnScope } from "./ConfigSchema.js";

export const defaultConfig: RouteCairnConfig = {
  defaultMode: "quick",
  reportsDir: "./reports",
  defaultScopeFile: "./examples/scope.example.json",
  bodyPreviewBytes: 8192,
  requestTimeoutMs: 15000
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
