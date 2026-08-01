import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";

let server: Server | undefined;
const tempDirs: string[] = [];

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
    server = undefined;
  }

  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("scan command", () => {
  it("requests an in-scope target and writes report.json", async () => {
    let port = 0;
    server = createServer((request, response) => {
      if (request.method === "OPTIONS") {
        response.writeHead(204, {
          allow: "GET, HEAD, OPTIONS, POST, DELETE",
          "access-control-allow-origin": "https://app.example.test",
          "access-control-allow-credentials": "true",
          "access-control-allow-methods": "GET, HEAD, OPTIONS, POST, DELETE",
          "access-control-allow-headers": "authorization, content-type"
        });
        response.end();
        return;
      }

      if (request.method === "HEAD") {
        response.writeHead(200, {
          "content-type": request.url === "/openapi.json" ? "application/json" : "application/json"
        });
        response.end();
        return;
      }

      if (request.url === "/openapi.json") {
        response.writeHead(200, {
          "content-type": "application/json"
        });
        response.end('{"openapi":"3.1.0","paths":{"/api/accounts/{id}":{}}}');
        return;
      }

      if (request.url === "/" || request.url === "/admin") {
        const origin = request.headers.origin;
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "x-powered-by": "Next.js",
          ...(origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : {})
        });
        response.end(
          '<!doctype html><html><head><title>Admin Portal</title><script src="/_next/static/chunks/app.js"></script></head><body><h1>Admin Portal</h1><p>RouteCairn fixture page with enough unique content to avoid matching the soft 404 fallback baseline.</p><nav>users reports settings audit-log</nav><script id="__NEXT_DATA__" type="application/json">{"buildId":"build123","page":"/","props":{"pageProps":{}}}</script></body></html>'
        );
        return;
      }

      if (request.url === "/account-a-only") {
        if (request.headers.cookie?.includes("session=account-a-routecairn-test")) {
          response.writeHead(200, {
            "content-type": "text/html; charset=utf-8"
          });
          response.end("<!doctype html><html><head><title>Account A Area</title></head><body>Account A owned object.</body></html>");
          return;
        }

        response.writeHead(request.headers.cookie ? 403 : 401, {
          "content-type": "text/html; charset=utf-8"
        });
        response.end("<!doctype html><html><head><title>Forbidden</title></head><body>not allowed</body></html>");
        return;
      }

      if (request.url === "/members") {
        if (request.headers.cookie?.includes("session=account-a-routecairn-test") || request.headers.cookie?.includes("session=account-b-routecairn-test")) {
          response.writeHead(200, {
            "content-type": "text/html; charset=utf-8"
          });
          response.end("<!doctype html><html><head><title>Members Area</title></head><body>Authenticated shared member area.</body></html>");
          return;
        }

        response.writeHead(401, {
          "content-type": "text/html; charset=utf-8"
        });
        response.end("<!doctype html><html><head><title>Login Required</title></head><body>login required</body></html>");
        return;
      }

      if (request.url === "/private") {
        if (request.headers.cookie?.includes("session=valid-routecairn-test")) {
          response.writeHead(200, {
            "content-type": "text/html; charset=utf-8"
          });
          response.end("<!doctype html><html><head><title>Private Area</title></head><body>Authenticated dashboard fixture with private controls and account settings.</body></html>");
          return;
        }

        response.writeHead(401, {
          "content-type": "text/html; charset=utf-8"
        });
        response.end("<!doctype html><html><head><title>Login Required</title></head><body>login required</body></html>");
        return;
      }

      if (request.url?.startsWith("/api/search")) {
        response.writeHead(200, {
          "content-type": "application/json"
        });
        response.end('{"items":[]}');
        return;
      }

      if (request.url === "/api/accounts/123") {
        if (request.headers.cookie?.includes("session=account-a-routecairn-test")) {
          response.writeHead(200, {
            "content-type": "application/json"
          });
          response.end('{"accountId":123,"owner":"account-a"}');
          return;
        }

        response.writeHead(request.headers.cookie ? 403 : 401, {
          "content-type": "application/json"
        });
        response.end('{"error":"not allowed"}');
        return;
      }

      if (request.url === "/api/members") {
        if (request.headers.cookie?.includes("session=account-a-routecairn-test") || request.headers.cookie?.includes("session=account-b-routecairn-test")) {
          response.writeHead(200, {
            "content-type": "application/json"
          });
          response.end('{"ok":true,"scope":"member"}');
          return;
        }

        response.writeHead(401, {
          "content-type": "application/json"
        });
        response.end('{"error":"login required"}');
        return;
      }

      if (request.url === "/api/auth/session") {
        response.writeHead(200, {
          "content-type": "application/json"
        });
        response.end('{"user":null}');
        return;
      }

      if (request.url === "/_next/data/build123/index.json") {
        response.writeHead(200, {
          "content-type": "application/json",
          "cache-control": "public, max-age=3600"
        });
        response.end('{"pageProps":{"user":{"email":"test@example.com","account":"demo"}},"__N_SSP":true}');
        return;
      }

      if (request.url === "/_next/static/chunks/app.js") {
        response.writeHead(200, {
          "content-type": "application/javascript"
        });
        response.end(`
          const NEXT_PUBLIC_API_BASE = "http://127.0.0.1:${port}/api";
          const baseURL = "/api";
          const privateRoute = "/internal/build-info";
          const absoluteRoute = "http://127.0.0.1:${port}/api/from-absolute-js";
          const exportRoute = "/api/users/123/export";
          const resetRoute = "/reset-password";
          const graphqlRoute = "/graphql";
          const privateRoute = "/private";
          const accountAOnlyRoute = "/account-a-only";
          const membersRoute = "/members";
          const accountApiRoute = "/api/accounts/123";
          const membersApiRoute = "/api/members";
          const openApiRoute = "/openapi.json";
          const searchApiRoute = "/api/search?q=laptop&page=2&sort=price_desc&minPrice=5000&userId=123";
          //${"#"} sourceMappingURL=app.js.map
        `);
        return;
      }

      if (
        request.url === "/internal/build-info" ||
        request.url === "/api/from-absolute-js" ||
        request.url === "/api/users/123/export" ||
        request.url === "/reset-password" ||
        request.url === "/graphql"
      ) {
        response.writeHead(200, {
          "content-type": "application/json"
        });
        response.end(request.url === "/graphql" ? '{"data":{"__schema":{"queryType":{"name":"Query"}}}}' : '{"ok":true}');
        return;
      }

      if (request.url === "/.env") {
        response.writeHead(200, {
          "content-type": "text/plain"
        });
        response.end("DATABASE_URL=postgres://user:pass@localhost/db\nJWT_SECRET=super-secret");
        return;
      }

      if (request.url === "/backup.zip") {
        response.writeHead(200, {
          "content-type": "application/zip"
        });
        response.end("PK fake backup archive");
        return;
      }

      if (request.url === "/debug.log") {
        response.writeHead(200, {
          "content-type": "text/plain"
        });
        response.end("Error: stack trace at /app/server.js");
        return;
      }

      if (request.url === "/_next/static/chunks/app.js.map") {
        response.writeHead(200, {
          "content-type": "application/json"
        });
        response.end('{"version":3,"sources":["webpack://src/app.ts"],"mappings":""}');
        return;
      }

      if (request.url?.startsWith("/.routecairn-nonexistent") || request.url === "/login") {
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8"
        });
        response.end("<!doctype html><html><head><title>Missing</title></head><body>not found</body></html>");
        return;
      }

      response.writeHead(404, {
        "content-type": "text/html; charset=utf-8"
      });
      response.end("<!doctype html><html><head><title>Not Found</title></head><body>nope</body></html>");
    });

    await listen(server);
    port = (server.address() as AddressInfo).port;
    const target = `http://127.0.0.1:${port}/`;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-scan-"));
    tempDirs.push(tempDir);

    const scopePath = join(tempDir, "scope.json");
    await writeFile(
      scopePath,
      `${JSON.stringify(
        {
          ...exampleScope,
          allowedDomains: ["127.0.0.1"],
          disallowedPaths: [],
          rateLimitPerSecond: 50,
          concurrency: 10,
          userAgent: "RouteCairn/Test"
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const authPath = join(tempDir, "auth.json");
    await writeFile(
      authPath,
      `${JSON.stringify(
        {
          label: "account-a",
          headers: { Cookie: "session=valid-routecairn-test" },
          notes: ["integration fixture"]
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const authAPath = join(tempDir, "auth-a.json");
    await writeFile(
      authAPath,
      `${JSON.stringify(
        {
          label: "account-a",
          headers: { Cookie: "session=account-a-routecairn-test" },
          notes: ["integration account A fixture"]
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const authBPath = join(tempDir, "auth-b.json");
    await writeFile(
      authBPath,
      `${JSON.stringify(
        {
          label: "account-b",
          headers: { Cookie: "session=account-b-routecairn-test" },
          notes: ["integration account B fixture"]
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const outputDir = join(tempDir, "reports");
    const result = await runScanCommand(target, {
      scope: scopePath,
      output: outputDir,
      profile: "authenticated",
      rate: "50",
      auth: authPath,
      authA: authAPath,
      authB: authBPath
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      baseline?: { probes: unknown[]; repeatedTitle?: string };
      discoveredUrls: Array<{ url: string; statusCode: number; title?: string; falsePositiveStatus: string }>;
      findings: Array<{ title: string; type: string; severity: string; riskScore: number; sourceModule: string; falsePositiveStatus: string }>;
      responses: Array<{ statusCode: number; title?: string; requestedUrl: string }>;
      technologies: Array<{ name: string; confidence: string }>;
      jsIntelligence?: {
        scripts: Array<{
          scriptUrl: string;
          downloaded: boolean;
          endpoints: string[];
          configValues: Array<{ name: string; classification: string }>;
          sourceMapUrls: string[];
        }>;
        queuedEndpoints: Array<{ path: string; source: string }>;
        sourceMaps: string[];
      };
      profile?: { name: string; displayName: string; mode: string; browserUse: string; authComparisonDepth: string; proofMode: boolean; modules: string[]; limits: Record<string, unknown>; reportFocus: string[] };
      scanPlan: {
        profile: string;
        metadata: { requestedProfile: string; resolvedProfile: string; legacyMode?: string; legacyModeTranslation?: string };
        modules: Array<{ id: string; settings: Record<string, unknown> }>;
        limits: { rateLimitPerSecond: number; concurrency: number; requestTimeoutMs: number; maxRequests: number; retry: { maxAttempts: number } };
        authentication: { required: boolean; hasSingleProfile: boolean; hasAccountPair: boolean };
        evidence: { level: string; requireReproducibleEvidence: boolean; retainProofBlocks: boolean };
      };
      apiMapper?: {
        endpoints: Array<{ endpoint: string; routeType: string; riskTags: string[]; likelyManualTests: string[] }>;
        graphQlEndpoints: string[];
      };
      proofMode?: { enabled: boolean; retestedTargets: number; blocks: Array<{ title: string; target: string; severityReason: string; stableEvidence: string[]; bountySubmissionSummary: string; comparisons: Array<{ label: string; request: { curlCommand: string; authMaterialRedacted: boolean }; response: { statusCode?: number; contentLength?: number; bodyHash?: string } }> }> };
      apiProbe?: {
        safeMethods: string[];
        skippedMethods: string[];
        schemaHints: string[];
        graphQlEndpoints: string[];
        endpointsReviewed: Array<{ endpoint: string; statusByMethod: Record<string, number | "error">; contentTypes: string[]; allowedMethods: string[]; corsHints: string[]; schemaHints: string[]; graphQl: { attempted: boolean; available: boolean; evidence: string } }>;
      };
      authSurface?: {
        surfaces: Array<{ endpoint: string; purpose: string; suggestedTests: string[] }>;
      };
      authenticatedScan?: {
        profile: { enabled: boolean; headerNames: string[]; redactionApplied: boolean };
        comparedUrls: number;
        authOnlySurfaces: Array<{ url: string; classification: string; proof: { authenticatedCurlCommand: string } }>;
        results: Array<{ url: string; classification: string; proof: { authenticatedCurlCommand: string } }>;
      };
      roleComparison?: {
        profileSet: { enabled: boolean; redactionApplied: boolean };
        comparedUrls: number;
        accountAOnly: Array<{ url: string; classification: string; needsManualVerification: boolean; proof: { accountACurlCommand: string; accountBCurlCommand: string } }>;
        onlyAuthenticatedAccess: Array<{ url: string; classification: string; needsManualVerification: boolean }>;
        results: Array<{ url: string; classification: string; needsManualVerification: boolean; proof: { accountACurlCommand: string; accountBCurlCommand: string } }>;
      };
      stateAwareApi?: {
        safeMethods: string[];
        skippedMethods: string[];
        reviewedEndpoints: Array<{ endpoint: string; candidateReasons: string[]; accessComparison: { signal: string; needsManualVerification: boolean }; safeMethodsTested: Array<{ method: string; statusCode?: number }>; skippedMethods: Array<{ method: string; safety: string }> }>;
        bolaIdorCandidates: Array<{ endpoint: string }>;
      };
      parameterAnalysis?: {
        totalParameters: number;
        highRiskParameters: Array<{ name: string; kind: string; riskTags: string[] }>;
        riskSummary: { authorizationSensitive: number; businessLogic: number; harmlessNavigation: number };
        workflowTargets: Array<{ url: string; reasons: string[]; suggestedWorkflow: string }>;
        analyzedUrls: Array<{ url: string; parameters: Array<{ name: string; kind: string; riskTags: string[] }> }>;
      };
      workflowValidation?: {
        templates: Array<{ kind: string; title: string; preconditions: string[]; steps: string[]; expectedSecureBehavior: string[]; evidenceToCapture: string[]; avoidActions: string[]; needsManualVerification: boolean }>;
      };
      nextJsReview?: {
        detected: boolean;
        buildIds: string[];
        dataRoutes: Array<{ url: string; statusCode?: number; cacheRisk: string; dataIndicators: string[]; cacheControl?: string }>;
        sourceMaps: Array<{ url: string; classification: string; severityHint: string; reason: string }>;
        cacheSignals: string[];
      };
      metadata: { totalRequests: number };
    };

    expect(result.reportPath).toBe(join(outputDir, "report.json"));
    expect(result.markdownReportPath).toBe(join(outputDir, "report.md"));
    expect(result.htmlReportPath).toBe(join(outputDir, "report.html"));
    expect(existsSync(result.markdownReportPath)).toBe(true);
    expect(existsSync(result.htmlReportPath)).toBe(true);
    const htmlReport = await readFile(result.htmlReportPath, "utf8");
    const markdownReport = await readFile(result.markdownReportPath, "utf8");
    expect(htmlReport).toContain("RouteCairn");
    expect(htmlReport).toContain("Vulnerability Workflows");
    expect(htmlReport).toContain("Proof Blocks");
    expect(report.metadata.totalRequests).toBeGreaterThan(1);
    expect(report.baseline?.probes.length).toBe(3);
    expect(report.baseline?.repeatedTitle).toBe("Missing");
    expect(report.responses[0]?.statusCode).toBe(200);
    expect(report.responses[0]?.title).toBe("Admin Portal");
    expect(report.responses[0]?.requestedUrl).toBe(target);
    expect(report.discoveredUrls.some((item) => item.url.endsWith("/admin") && item.falsePositiveStatus === "likely-valid")).toBe(true);
    expect(report.discoveredUrls.some((item) => item.url.endsWith("/login") && item.falsePositiveStatus === "maybe-false-positive")).toBe(true);
    expect(report.profile?.name).toBe("authenticated");
    expect(report.profile?.mode).toBe("full");
    expect(report.profile?.authComparisonDepth).toBe("account-pair");
    expect(report.profile?.proofMode).toBe(true);
    expect(report.scanPlan.profile).toBe("authenticated");
    expect(report.scanPlan.metadata.requestedProfile).toBe("authenticated");
    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(expect.arrayContaining(["authenticated-testing", "role-comparison", "state-aware-api", "proof-mode"]));
    expect(report.scanPlan.modules.find((module) => module.id === "api-probe")?.settings.maxEndpoints).toBe(45);
    expect(report.scanPlan.limits.rateLimitPerSecond).toBe(50);
    expect(report.scanPlan.limits.concurrency).toBe(3);
    expect(report.scanPlan.limits.retry.maxAttempts).toBe(2);
    expect(report.scanPlan.authentication).toMatchObject({ required: true, hasSingleProfile: true, hasAccountPair: true });
    expect(report.scanPlan.evidence).toMatchObject({ level: "strong", requireReproducibleEvidence: true, retainProofBlocks: true });
    expect(report.proofMode?.enabled).toBe(true);
    expect(report.proofMode?.retestedTargets).toBeGreaterThan(0);
    expect(report.proofMode?.blocks.some((block) => block.comparisons.some((comparison) => comparison.label === "anonymous") && block.comparisons.some((comparison) => comparison.label === "authenticated") && block.comparisons.some((comparison) => comparison.label === "account-a") && block.comparisons.some((comparison) => comparison.label === "account-b"))).toBe(true);
    expect(report.proofMode?.blocks.some((block) => block.stableEvidence.length > 0 && block.bountySubmissionSummary.includes("Evidence:"))).toBe(true);
    expect(JSON.stringify(report.proofMode)).not.toContain("valid-routecairn-test");
    expect(JSON.stringify(report.proofMode)).not.toContain("account-a-routecairn-test");
    expect(report.scope.concurrency).toBe(3);
    expect(report.technologies.some((item) => item.name === "Next.js" && item.confidence === "High")).toBe(true);
    expect(report.jsIntelligence?.scripts.some((script) => script.scriptUrl.endsWith("/_next/static/chunks/app.js") && script.downloaded)).toBe(
      true
    );
    expect(report.jsIntelligence?.queuedEndpoints).toEqual(
      expect.arrayContaining([
        { path: "/internal/build-info", source: "js:endpoint" },
        { path: "/api/from-absolute-js", source: "js:endpoint" },
        { path: "/api/users/123/export", source: "js:endpoint" },
        { path: "/reset-password", source: "js:endpoint" },
        { path: "/graphql", source: "js:endpoint" }
      ])
    );
    expect(report.jsIntelligence?.scripts[0]?.configValues).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "NEXT_PUBLIC_API_BASE", classification: "public-frontend-config" })])
    );
    expect(report.jsIntelligence?.sourceMaps.some((sourceMap) => sourceMap.endsWith("/_next/static/chunks/app.js.map"))).toBe(true);
    expect(report.discoveredUrls.some((item) => item.url.endsWith("/api/auth/session") && item.falsePositiveStatus === "likely-valid")).toBe(true);
    expect(report.discoveredUrls.some((item) => item.url.endsWith("/internal/build-info") && item.falsePositiveStatus === "likely-valid")).toBe(
      true
    );
    expect(report.apiMapper?.endpoints.some((endpoint) => endpoint.endpoint.endsWith("/api/users/123/export"))).toBe(true);
    expect(
      report.apiMapper?.endpoints.some(
        (endpoint) => endpoint.endpoint.endsWith("/api/users/123/export") && endpoint.riskTags.includes("object-id")
      )
    ).toBe(true);
    expect(report.apiMapper?.graphQlEndpoints.some((endpoint) => endpoint.endsWith("/graphql"))).toBe(true);
    expect(report.apiProbe?.safeMethods).toEqual(["OPTIONS", "HEAD", "GET"]);
    expect(report.apiProbe?.skippedMethods).toEqual(["POST", "PUT", "PATCH", "DELETE"]);
    expect(report.apiProbe?.endpointsReviewed.some((item) => item.endpoint.endsWith("/openapi.json") && item.schemaHints.includes("openapi") && item.contentTypes.includes("application/json"))).toBe(true);
    expect(report.apiProbe?.endpointsReviewed.some((item) => item.allowedMethods.includes("POST") && item.corsHints.some((hint) => hint.includes("allow-origin")))).toBe(true);
    expect(report.apiProbe?.endpointsReviewed.some((item) => item.endpoint.endsWith("/graphql") && item.graphQl.attempted && item.graphQl.available)).toBe(true);
    expect(report.authSurface?.surfaces.some((surface) => surface.endpoint.endsWith("/reset-password") && surface.purpose === "password reset")).toBe(
      true
    );
    expect(report.findings.some((item) => item.title === "Admin or login surface discovered" && item.sourceModule === "path-discovery")).toBe(true);
    expect(report.findings.some((item) => item.type === "CORS Issue" && item.severity === "High")).toBe(true);
    expect(report.findings.some((item) => item.type === "HTTP Method Issue")).toBe(true);
    expect(report.findings.some((item) => item.type === "Sensitive File Exposure" && item.riskScore > 0)).toBe(true);
    expect(report.findings.some((item) => item.type === "Backup File Exposure")).toBe(true);
    expect(report.findings.some((item) => item.type === "Debug/Dev Path")).toBe(true);
    expect(report.findings.some((item) => item.type === "Source Map Exposure")).toBe(true);
    expect(report.authenticatedScan?.profile.enabled).toBe(true);
    expect(report.authenticatedScan?.profile.headerNames).toEqual(["Cookie"]);
    expect(report.authenticatedScan?.authOnlySurfaces.some((item) => item.url.endsWith("/private") && item.classification === "auth-only")).toBe(true);
    expect(JSON.stringify(report.authenticatedScan)).not.toContain("valid-routecairn-test");
    expect(report.authenticatedScan?.results.some((item) => item.proof.authenticatedCurlCommand.includes("Cookie: <redacted>"))).toBe(true);
    expect(report.roleComparison?.profileSet.enabled).toBe(true);
    expect(report.roleComparison?.accountAOnly.some((item) => item.url.endsWith("/account-a-only") && item.classification === "account-a-only" && item.needsManualVerification)).toBe(true);
    expect(report.roleComparison?.onlyAuthenticatedAccess.some((item) => item.url.endsWith("/members") && item.classification === "only-authenticated-access" && item.needsManualVerification)).toBe(true);
    expect(JSON.stringify(report.roleComparison)).not.toContain("account-a-routecairn-test");
    expect(JSON.stringify(report.roleComparison)).not.toContain("account-b-routecairn-test");
    expect(report.roleComparison?.results.some((item) => item.proof.accountACurlCommand.includes("Cookie: <redacted>") && item.proof.accountBCurlCommand.includes("Cookie: <redacted>"))).toBe(true);
    expect(report.stateAwareApi?.safeMethods).toEqual(["GET", "HEAD", "OPTIONS"]);
    expect(report.stateAwareApi?.skippedMethods).toEqual(["POST", "PUT", "PATCH", "DELETE"]);
    expect(report.stateAwareApi?.reviewedEndpoints.some((item) => item.endpoint.endsWith("/api/accounts/123") && item.candidateReasons.includes("object-id") && item.accessComparison.signal === "account-a-only" && item.accessComparison.needsManualVerification)).toBe(true);
    expect(report.stateAwareApi?.reviewedEndpoints.some((item) => item.endpoint.endsWith("/api/members") && item.accessComparison.signal === "only-authenticated-access")).toBe(true);
    expect(report.stateAwareApi?.bolaIdorCandidates.some((item) => item.endpoint.endsWith("/api/accounts/123"))).toBe(true);
    expect(report.stateAwareApi?.reviewedEndpoints.every((item) => item.skippedMethods.some((method) => method.method === "POST" && method.safety === "destructive-skipped"))).toBe(true);
    expect(JSON.stringify(report.stateAwareApi)).not.toContain("account-a-routecairn-test");
    expect(JSON.stringify(report.stateAwareApi)).not.toContain("account-b-routecairn-test");
    expect(report.parameterAnalysis?.totalParameters).toBeGreaterThanOrEqual(5);
    expect(report.parameterAnalysis?.highRiskParameters.some((item) => item.name === "userId" && item.riskTags.includes("authorization-sensitive"))).toBe(true);
    expect(report.parameterAnalysis?.highRiskParameters.some((item) => item.name === "minPrice" && item.riskTags.includes("business-logic"))).toBe(true);
    expect(report.parameterAnalysis?.analyzedUrls.some((item) => item.url.includes("/api/search") && item.parameters.some((parameter) => parameter.name === "page" && parameter.kind === "pagination"))).toBe(true);
    expect(report.parameterAnalysis?.workflowTargets.some((item) => item.url.includes("/api/search") && item.reasons.includes("authorization-sensitive"))).toBe(true);
    expect(report.vulnerabilityWorkflows?.workflows.some((workflow) => workflow.category === "idor-bola" && workflow.relatedEndpoints.some((endpoint) => endpoint.includes("/api/search")))).toBe(true);
    expect(report.workflowValidation?.templates.map((template) => template.kind)).toEqual(expect.arrayContaining(["idor-bola", "auth-bypass", "rate-limit", "graphql", "price-filter"]));
    expect(report.workflowValidation?.templates.every((template) => template.needsManualVerification)).toBe(true);
    expect(report.workflowValidation?.templates.every((template) => template.preconditions.length > 0 && template.steps.length > 0 && template.expectedSecureBehavior.length > 0 && template.evidenceToCapture.length > 0 && template.avoidActions.length > 0)).toBe(true);
    expect(htmlReport).toContain("Manual Test Pack");
    expect(report.nextJsReview?.detected).toBe(true);
    expect(report.nextJsReview?.buildIds).toContain("build123");
    expect(report.nextJsReview?.dataRoutes.some((route) => route.url.endsWith("/_next/data/build123/index.json") && route.cacheRisk === "possible-private-data-cache" && route.dataIndicators.includes("sensitive-keywords"))).toBe(true);
    expect(report.nextJsReview?.sourceMaps.some((sourceMap) => sourceMap.url.endsWith("/_next/static/chunks/app.js.map") && sourceMap.classification === "nextjs-public-source-map-review" && sourceMap.severityHint === "low")).toBe(true);
    expect(htmlReport).toContain("Next.js Review");
    expect(htmlReport).toContain("API Probe");
    expect(htmlReport).toContain("Authenticated Review");
    expect(htmlReport).toContain("Proof Mode Evidence");
    expect(markdownReport).toContain("Proof Mode Evidence");
  });
});

function listen(targetServer: Server): Promise<void> {
  return new Promise((resolve) => {
    targetServer.listen(0, "127.0.0.1", resolve);
  });
}
