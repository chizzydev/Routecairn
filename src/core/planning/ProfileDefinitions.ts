import type { ScanProfileDefinition } from "./ScanPlan.js";

const safeMethods = ["OPTIONS", "HEAD", "GET"] as const;

export const scanProfileDefinitions = {
  "pre-handover": {
    name: "pre-handover", displayName: "Internal Pre-Handover Assault",
    description: "Explicit disposable-actor workflow sequencing with authoritative setup and handover gates.",
    enabledModules: ["assisted-review"], disabledModules: [], moduleSettings: {},
    authentication: { required: true, level: "account-pair", requireSingleProfile: false, requireAccountPair: true },
    limits: { maxDepth: 1, rateLimitPerSecond: 5, concurrency: 2, requestTimeoutMs: 15000, bodyPreviewBytes: 8192, maxRequests: 500, maxScanDurationMs: 900000, retry: { maxAttempts: 1, baseDelayMs: 250, maxDelayMs: 1000, retryStatusCodes: [] } },
    perModuleLimits: {}, evidence: { level: "strong", collectRequestAudit: true, collectBodyPreview: false, requireReproducibleEvidence: true, retainProofBlocks: true },
    output: { json: true, markdown: true, html: true, stableForDiff: true, includePlan: true, includeRequestAudit: true },
    failurePolicy: "fail-fast", optionalModulesMayBeSkipped: false,
    reportFocus: ["disposable object ownership", "critical workflows", "cleanup", "fix/regression", "handover readiness"]
  },
  quick: {
    name: "quick",
    displayName: "Quick Recon",
    description: "Fast first-pass reconnaissance with core discovery and low scan volume.",
    enabledModules: ["baseline", "tech-fingerprint", "js-intelligence", "path-discovery", "api-mapper", "api-probe", "auth-surface", "parameter-analysis", "vulnerability-workflows"],
    disabledModules: ["browser-crawler", "authenticated-testing", "role-comparison", "state-aware-api", "object-pair-testing", "field-exposure-testing", "authorization-matrix-testing", "collection-authorization-testing", "bulk-authorization-testing", "file-authorization-testing", "equivalent-route-testing", "proof-mode"],
    moduleSettings: {
      "path-discovery": { pathSources: ["wordlist:common", "wordlist:api"] },
      "api-probe": { maxEndpoints: 12, safeMethods },
      "parameter-analysis": {},
      "vulnerability-workflows": {}
    },
    authentication: {
      required: false,
      level: "none",
      requireSingleProfile: false,
      requireAccountPair: false
    },
    limits: {
      maxDepth: 1,
      rateLimitPerSecond: 4,
      concurrency: 3,
      requestTimeoutMs: 10000,
      bodyPreviewBytes: 4096,
      maxRequests: 80,
      maxScanDurationMs: 120000,
      retry: { maxAttempts: 1, baseDelayMs: 250, maxDelayMs: 1000, retryStatusCodes: [408, 429, 500, 502, 503, 504] }
    },
    perModuleLimits: {},
    evidence: {
      level: "minimal",
      collectRequestAudit: true,
      collectBodyPreview: false,
      requireReproducibleEvidence: false,
      retainProofBlocks: false
    },
    output: { json: true, markdown: true, html: true, stableForDiff: false, includePlan: true, includeRequestAudit: true },
    failurePolicy: "continue-on-module-error",
    optionalModulesMayBeSkipped: true,
    reportFocus: ["surface map", "technologies", "API hints", "manual testing leads"]
  },
  full: {
    name: "full",
    displayName: "Full Review",
    description: "Broad safe review with browser crawling, security checks, exposure review, workflows, and reports.",
    enabledModules: [
      "baseline",
      "tech-fingerprint",
      "js-intelligence",
      "browser-crawler",
      "path-discovery",
      "api-mapper",
      "api-probe",
      "auth-surface",
      "parameter-analysis",
      "nextjs-review",
      "vulnerability-workflows",
      "workflow-validation",
      "header-review",
      "cookie-review",
      "cors-review",
      "method-review",
      "exposure-review",
      "secret-boundary"
    ],
    disabledModules: ["authenticated-testing", "role-comparison", "state-aware-api", "object-pair-testing", "field-exposure-testing", "authorization-matrix-testing", "collection-authorization-testing", "bulk-authorization-testing", "file-authorization-testing", "equivalent-route-testing", "proof-mode"],
    moduleSettings: {
      "browser-crawler": {
        browserMaxPages: 3,
        browserMaxLinksPerPage: 25,
        browserMaxPolicyEvents: 200,
        browserMaxRequestsPerPage: 80,
        browserBlockThirdParty: true,
        browserCaptureScreenshot: true
      },
      "path-discovery": { pathSources: ["wordlist:common", "wordlist:admin", "wordlist:api"] },
      "api-probe": { maxEndpoints: 40, safeMethods },
      "nextjs-review": { maxNextJsManifestRequests: 4, maxNextJsDataSurfaceRequests: 8, maxNextJsSourceMapRequests: 4, maxNextJsCacheDifferentialRequests: 0, maxNextJsRoutesProcessed: 200, nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW" }
    },
    authentication: {
      required: false,
      level: "none",
      requireSingleProfile: false,
      requireAccountPair: false
    },
    limits: {
      maxDepth: 2,
      rateLimitPerSecond: 8,
      concurrency: 5,
      requestTimeoutMs: 15000,
      bodyPreviewBytes: 8192,
      maxRequests: 300,
      maxScanDurationMs: 600000,
      retry: { maxAttempts: 2, baseDelayMs: 250, maxDelayMs: 2000, retryStatusCodes: [408, 429, 500, 502, 503, 504] }
    },
    perModuleLimits: {},
    evidence: {
      level: "normal",
      collectRequestAudit: true,
      collectBodyPreview: true,
      requireReproducibleEvidence: false,
      retainProofBlocks: false
    },
    output: { json: true, markdown: true, html: true, stableForDiff: false, includePlan: true, includeRequestAudit: true },
    failurePolicy: "continue-on-module-error",
    optionalModulesMayBeSkipped: true,
    reportFocus: ["findings", "browser evidence", "manual test pack", "safe security review"]
  },
  authenticated: {
    name: "authenticated",
    displayName: "Authenticated Review",
    description: "Logged-in review with explicit auth validation, authenticated comparison, Account A/B comparison, and state-aware API review.",
    enabledModules: [
      "baseline",
      "tech-fingerprint",
      "js-intelligence",
      "browser-crawler",
      "path-discovery",
      "api-mapper",
      "api-probe",
      "auth-surface",
      "parameter-analysis",
      "nextjs-review",
      "vulnerability-workflows",
      "workflow-validation",
      "authenticated-testing",
      "role-comparison",
      "state-aware-api",
      "header-review",
      "cookie-review",
      "cors-review",
      "method-review",
      "exposure-review",
      "secret-boundary",
      "proof-mode"
    ],
    disabledModules: ["object-pair-testing", "field-exposure-testing", "authorization-matrix-testing", "collection-authorization-testing", "bulk-authorization-testing", "file-authorization-testing", "equivalent-route-testing"],
    moduleSettings: {
      "browser-crawler": {
        browserMaxPages: 4,
        browserMaxLinksPerPage: 30,
        browserMaxPolicyEvents: 250,
        browserMaxRequestsPerPage: 90,
        browserBlockThirdParty: true,
        browserCaptureScreenshot: true
      },
      "path-discovery": { pathSources: ["wordlist:common", "wordlist:admin", "wordlist:api"] },
      "api-probe": { maxEndpoints: 45, safeMethods },
      "authenticated-testing": { maxComparisons: 20 },
      "role-comparison": { maxComparisons: 20 },
      "state-aware-api": { maxEndpointReviews: 30 },
      "nextjs-review": { maxNextJsManifestRequests: 4, maxNextJsDataSurfaceRequests: 8, maxNextJsSourceMapRequests: 4, maxNextJsCacheDifferentialRequests: 0, maxNextJsRoutesProcessed: 200, nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW" },
      "proof-mode": { enabled: true, maxProofTargets: 6 }
    },
    authentication: {
      required: true,
      level: "single-profile",
      requireSingleProfile: true,
      requireAccountPair: false
    },
    limits: {
      maxDepth: 2,
      rateLimitPerSecond: 12,
      concurrency: 3,
      requestTimeoutMs: 18000,
      bodyPreviewBytes: 8192,
      maxRequests: 360,
      maxScanDurationMs: 720000,
      retry: { maxAttempts: 2, baseDelayMs: 300, maxDelayMs: 2500, retryStatusCodes: [408, 429, 500, 502, 503, 504] }
    },
    perModuleLimits: {},
    evidence: {
      level: "strong",
      collectRequestAudit: true,
      collectBodyPreview: false,
      requireReproducibleEvidence: true,
      retainProofBlocks: true
    },
    output: { json: true, markdown: true, html: true, stableForDiff: false, includePlan: true, includeRequestAudit: true },
    failurePolicy: "fail-fast",
    optionalModulesMayBeSkipped: true,
    reportFocus: ["anonymous vs authenticated", "Account A/B differences", "auth-only surfaces", "state-aware API candidates"]
  },
  monitor: {
    name: "monitor",
    displayName: "Monitor",
    description: "Repeatable low-noise monitoring profile for comparing changes over time.",
    enabledModules: ["baseline", "tech-fingerprint", "path-discovery", "api-mapper", "api-probe", "auth-surface", "parameter-analysis", "vulnerability-workflows"],
    disabledModules: ["browser-crawler", "authenticated-testing", "role-comparison", "state-aware-api", "object-pair-testing", "field-exposure-testing", "authorization-matrix-testing", "collection-authorization-testing", "bulk-authorization-testing", "file-authorization-testing", "equivalent-route-testing", "proof-mode", "exposure-review"],
    moduleSettings: {
      "path-discovery": { pathSources: ["wordlist:common", "wordlist:api"] },
      "api-probe": { maxEndpoints: 20, safeMethods }
    },
    authentication: {
      required: false,
      level: "none",
      requireSingleProfile: false,
      requireAccountPair: false
    },
    limits: {
      maxDepth: 1,
      rateLimitPerSecond: 2,
      concurrency: 2,
      requestTimeoutMs: 12000,
      bodyPreviewBytes: 4096,
      maxRequests: 120,
      maxScanDurationMs: 180000,
      retry: { maxAttempts: 1, baseDelayMs: 250, maxDelayMs: 1000, retryStatusCodes: [408, 429, 500, 502, 503, 504] }
    },
    perModuleLimits: {},
    evidence: {
      level: "minimal",
      collectRequestAudit: true,
      collectBodyPreview: false,
      requireReproducibleEvidence: false,
      retainProofBlocks: false
    },
    output: { json: true, markdown: true, html: true, stableForDiff: true, includePlan: true, includeRequestAudit: true },
    failurePolicy: "continue-on-module-error",
    optionalModulesMayBeSkipped: false,
    reportFocus: ["new URLs", "removed URLs", "technology changes", "finding changes"]
  },
  proof: {
    name: "proof",
    displayName: "Proof Mode",
    description: "Reproducible evidence profile for suspected findings and manual verification packs.",
    enabledModules: [
      "baseline",
      "tech-fingerprint",
      "js-intelligence",
      "path-discovery",
      "api-mapper",
      "api-probe",
      "auth-surface",
      "parameter-analysis",
      "nextjs-review",
      "vulnerability-workflows",
      "workflow-validation",
      "state-aware-api",
      "header-review",
      "cookie-review",
      "cors-review",
      "method-review",
      "exposure-review",
      "secret-boundary",
      "proof-mode"
    ],
    disabledModules: ["browser-crawler", "object-pair-testing", "field-exposure-testing", "authorization-matrix-testing", "collection-authorization-testing", "bulk-authorization-testing", "file-authorization-testing", "equivalent-route-testing"],
    moduleSettings: {
      "path-discovery": { pathSources: ["wordlist:common", "wordlist:admin", "wordlist:api"] },
      "api-probe": { maxEndpoints: 45, safeMethods },
      "state-aware-api": { maxEndpointReviews: 25 },
      "nextjs-review": { maxNextJsManifestRequests: 8, maxNextJsDataSurfaceRequests: 16, maxNextJsSourceMapRequests: 8, maxNextJsCacheDifferentialRequests: 6, maxNextJsRoutesProcessed: 500, nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW" },
      "proof-mode": { enabled: true, maxProofTargets: 16 }
    },
    authentication: {
      required: false,
      level: "none",
      requireSingleProfile: false,
      requireAccountPair: false
    },
    limits: {
      maxDepth: 2,
      rateLimitPerSecond: 10,
      concurrency: 4,
      requestTimeoutMs: 20000,
      bodyPreviewBytes: 16384,
      maxRequests: 260,
      maxScanDurationMs: 600000,
      retry: { maxAttempts: 3, baseDelayMs: 300, maxDelayMs: 3000, retryStatusCodes: [408, 429, 500, 502, 503, 504] }
    },
    perModuleLimits: {},
    evidence: {
      level: "strong",
      collectRequestAudit: true,
      collectBodyPreview: true,
      requireReproducibleEvidence: true,
      retainProofBlocks: true
    },
    output: { json: true, markdown: true, html: true, stableForDiff: false, includePlan: true, includeRequestAudit: true },
    failurePolicy: "continue-on-module-error",
    optionalModulesMayBeSkipped: true,
    reportFocus: ["curl commands", "redacted evidence", "manual verification", "retest-ready proof"]
  }
} satisfies Record<string, ScanProfileDefinition>;
