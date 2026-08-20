import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { defaultConfig } from "../../src/config/defaults.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { NextJsReviewModule } from "../../src/modules/nextjsReview/NextJsReviewModule.js";

let fixture: Server | undefined;
const directories: string[] = [];

afterEach(async () => {
  if (fixture) await new Promise<void>((resolve, reject) => fixture?.close((error) => error ? reject(error) : resolve()));
  fixture = undefined;
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("Next.js deep review controlled end-to-end fixture", () => {
  it("uses the real planner, engine, broker, parsers, findings, and report writers without leaking canaries", async () => {
    const canaries = {
      serialized: "routecairn-private-ssn-canary-40931",
      runtime: "routecairn-runtime-signing-canary-83371",
      sourceMap: "routecairn-source-map-api-canary-51729"
    };
    fixture = createServer((request, response) => {
      const url = request.url ?? "/";
      if (request.method === "HEAD") { response.writeHead(200, { "content-type": "text/html" }); response.end(); return; }
      if (url === "/") {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-powered-by": "Next.js" });
        response.end(`<!doctype html><html><head><title>Next Fixture</title><script src="/_next/static/build-a/_buildManifest.js"></script><script src="/_next/static/chunks/app-a1b2c3.js"></script></head><body><a href="/users/123">user</a><script id="__NEXT_DATA__" type="application/json">${JSON.stringify({ buildId: "build-a", page: "/", props: { pageProps: { publicTitle: "fixture", ssn: canaries.serialized } }, runtimeConfig: { NEXT_PUBLIC_ANALYTICS_ID: "analytics-public-123", SIGNING_SECRET: canaries.runtime } })}</script></body></html>`);
        return;
      }
      if (url === "/_next/static/build-a/_buildManifest.js") { response.writeHead(200, { "content-type": "application/javascript" }); response.end('self.__BUILD_MANIFEST = {"/users/[id]":["static/chunks/user-a1b2c3.js"],"/users/123":["static/chunks/user-a1b2c3.js"]};'); return; }
      if (url === "/_next/static/chunks/app-a1b2c3.js") { response.writeHead(200, { "content-type": "application/javascript" }); response.end('const rsc="/dashboard?_rsc=observed-token";\n//# sourceMappingURL=app-a1b2c3.js.map'); return; }
      if (url === "/_next/static/chunks/app-a1b2c3.js.map") { response.writeHead(200, { "content-type": "application/json" }); response.end(JSON.stringify({ version: 3, file: "app-a1b2c3.js", sources: ["C:\\Users\\Builder\\routecairn-fixture\\config.ts"], sourcesContent: [`const API_KEY='${canaries.sourceMap}';`], names: [], mappings: "AAAA" })); return; }
      if (url === "/_next/data/build-a/index.json") { response.writeHead(200, { "content-type": "application/json", "cache-control": "public, s-maxage=60", "x-nextjs-cache": "HIT" }); response.end(JSON.stringify({ pageProps: { ssn: canaries.serialized, marketing: "public" }, __N_SSG: true })); return; }
      if (url === "/_next/data/build-a/users/123.json") { response.writeHead(200, { "content-type": "application/json", "cache-control": "private, no-store" }); response.end(JSON.stringify({ pageProps: { publicTitle: "user profile" } })); return; }
      if (url.startsWith("/dashboard?_rsc=")) { response.writeHead(200, { "content-type": "text/x-component" }); response.end('1:I{"title":"Dashboard"}'); return; }
      response.writeHead(404, { "content-type": "text/html" }); response.end("<!doctype html><title>Missing</title><p>fixture missing route</p>");
    });
    await new Promise<void>((resolve) => fixture?.listen(0, "127.0.0.1", resolve));
    const port = (fixture.address() as AddressInfo).port, target = `http://127.0.0.1:${port}/`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-nextjs-deep-")); directories.push(directory);
    const scopePath = join(directory, "scope.json"), output = join(directory, "report");
    await writeFile(scopePath, JSON.stringify({ program: "Controlled Next.js fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 50, concurrency: 3, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Test" }));
    const paths = await runScanCommand(target, { scope: scopePath, output, profile: "proof", rate: "50" });
    const jsonText = await readFile(paths.reportPath, "utf8"), markdown = await readFile(paths.markdownReportPath, "utf8"), html = await readFile(paths.htmlReportPath, "utf8");
    const report = JSON.parse(jsonText) as any;
    expect(report.nextJsReview).toMatchObject({ detected: true, detectionConfidence: "CONFIRMED", routerKind: expect.stringMatching(/PAGES_ROUTER|MIXED/) });
    expect(report.nextJsReview.manifests).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "BUILD_MANIFEST", parseStatus: "PARSED", routes: expect.arrayContaining(["/users/[id]", "/users/123"]) })]));
    expect(report.nextJsReview.dataRoutes).toEqual(expect.arrayContaining([expect.objectContaining({ concreteRoute: "/", parseStatus: "PARSED", cacheRisk: "possible-private-data-cache" })]));
    expect(report.nextJsReview.sourceMaps).toEqual(expect.arrayContaining([expect.objectContaining({ parseStatus: "PARSED", sourceCount: 1, sourcesContentCount: 1, severityHint: "medium" })]));
    expect(report.nextJsReview.surfaces.some((surface: any) => surface.surfaceType === "RSC")).toBe(true);
    expect(report.findings.map((finding: any) => finding.type)).toEqual(expect.arrayContaining(["Next.js Public Serialized Sensitive Data Exposure", "Next.js Public Runtime Secret Exposure", "Next.js Source Map Sensitive Data Exposure"]));
    expect(report.findings.some((finding: any) => finding.type === "Next.js Shared Cache Private Data Exposure")).toBe(false);
    expect(report.nextJsReview.requestBudget.maximumAdditionalRequests).toBe(38);
    expect(report.nextJsReview.coverage.truncated).toBe(false);
    for (const canary of Object.values(canaries)) { expect(jsonText).not.toContain(canary); expect(markdown).not.toContain(canary); expect(html).not.toContain(canary); }
    expect(JSON.stringify(report.findings)).toContain("hmac-sha256:");
    expect(report.requestAudit.every((entry: any) => ["GET", "HEAD", "OPTIONS"].includes(entry.method))).toBe(true);
  });

  it("proves a controlled authenticated-to-public cache leak and rejects the isolated control", async () => {
    const cacheCanary = "routecairn-cache-private-ssn-72841";
    fixture = createServer((request, response) => {
      const url = request.url ?? "/";
      if (url === "/leaky" || url === "/isolated") {
        const page = url;
        response.writeHead(200, { "content-type": "text/html", "x-powered-by": "Next.js" });
        response.end(`<script id="__NEXT_DATA__" type="application/json">${JSON.stringify({ buildId: "cache-build", page, props: { pageProps: { title: "cache fixture" } } })}</script>`);
        return;
      }
      if (url === "/_next/data/cache-build/leaky.json" || url === "/_next/data/cache-build/isolated.json") {
        const authenticated = request.headers.cookie === "session=actor-a";
        const leaky = url.includes("/leaky.json");
        response.writeHead(200, { "content-type": "application/json", "cache-control": authenticated ? "private, no-store" : "public, s-maxage=60" });
        response.end(JSON.stringify({ pageProps: authenticated || leaky ? { ssn: cacheCanary } : { title: "public control" } }));
        return;
      }
      response.writeHead(404, { "content-type": "text/plain" }); response.end("missing");
    });
    await new Promise<void>((resolve) => fixture?.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(fixture.address() as AddressInfo).port}`;
    const run = async (path: "/leaky" | "/isolated") => {
      const scope = { program: "cache control fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"] as const, rateLimitPerSecond: 50, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Test" };
      const authProfile = { label: "actor-a", safeAlias: "actor-a", principalId: "principal-a", headers: { Cookie: "session=actor-a" }, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, notes: [] };
      const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "full", scope: scope as any, config: defaultConfig, authProfile, overrides: { includeModules: ["baseline", "tech-fingerprint", "nextjs-review"], moduleSettings: { "nextjs-review": { inspectNextJsSourceMaps: false, inspectKnownNextJsDataSurfaces: true, nextJsCacheReviewMode: "CONTROLLED_CACHE_DIFFERENTIAL", maxNextJsManifestRequests: 1, maxNextJsDataSurfaceRequests: 1, maxNextJsSourceMapRequests: 1, maxNextJsCacheDifferentialRequests: 2, maxNextJsAssetsInspected: 10, maxNextJsRoutesProcessed: 10 } } } });
      const context = new ScanContext({ target: `${origin}${path}`, scope: scope as any, config: defaultConfig, plan, outputDir: ".", authProfile });
      const seed = await context.httpClient.send({ url: `${origin}${path}`, method: "GET" }); context.state.recordResponse(seed); context.state.recordTechnologies([{ name: "Next.js", category: "framework", confidence: "High", signals: ["fixture"] }]);
      const result = await new NextJsReviewModule().run(context);
      return { result, audit: context.state.getRequestAudit() };
    };
    const leaky = await run("/leaky"), isolated = await run("/isolated");
    expect(leaky.result.findings?.some((finding) => finding.type === "Next.js Shared Cache Private Data Exposure")).toBe(true);
    expect(isolated.result.findings?.some((finding) => finding.type === "Next.js Shared Cache Private Data Exposure")).toBe(false);
    expect(leaky.result.nextJsReview?.coverage?.cacheDifferential).toBe("EXECUTED");
    expect(leaky.audit.filter((entry) => entry.requestedUrl.includes("/leaky.json")).every((entry) => entry.outcome === "sent")).toBe(true);
    expect(JSON.stringify(leaky.result)).not.toContain(cacheCanary);
  });

  it("proves a bounded Account A to Account B exposure without retaining the private value", async () => {
    const crossActorCanary = "routecairn-cross-actor-ssn-18429";
    fixture = createServer((request, response) => {
      const url = request.url ?? "/";
      if (url === "/account") {
        response.writeHead(200, { "content-type": "text/html", "x-powered-by": "Next.js" });
        response.end(`<script id="__NEXT_DATA__" type="application/json">${JSON.stringify({ buildId: "actor-build", page: "/account", props: { pageProps: { title: "account" } } })}</script>`);
        return;
      }
      if (url === "/_next/data/actor-build/account.json") {
        const actor = request.headers.cookie === "session=actor-a" ? "a" : request.headers.cookie === "session=actor-b" ? "b" : "public";
        response.writeHead(200, { "content-type": "application/json", "cache-control": "private, no-store" });
        response.end(JSON.stringify({ pageProps: actor === "public" ? { title: "public" } : { ssn: crossActorCanary } }));
        return;
      }
      response.writeHead(404, { "content-type": "text/plain" }); response.end("missing");
    });
    await new Promise<void>((resolve) => fixture?.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(fixture.address() as AddressInfo).port}`;
    const scope = { program: "cross actor fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"] as const, rateLimitPerSecond: 50, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Test" };
    const actor = (suffix: "a" | "b") => ({ label: `actor-${suffix}`, safeAlias: `actor-${suffix}`, principalId: `principal-${suffix}`, headers: { Cookie: `session=actor-${suffix}` }, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, notes: [] });
    const authProfileSet = { accountA: actor("a"), accountB: actor("b") };
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "full", scope: scope as any, config: defaultConfig, authProfileSet, overrides: { includeModules: ["baseline", "tech-fingerprint", "nextjs-review"], moduleSettings: { "nextjs-review": { inspectNextJsSourceMaps: false, inspectKnownNextJsDataSurfaces: true, nextJsCacheReviewMode: "CONTROLLED_CACHE_DIFFERENTIAL", maxNextJsManifestRequests: 1, maxNextJsDataSurfaceRequests: 1, maxNextJsSourceMapRequests: 1, maxNextJsCacheDifferentialRequests: 4, maxNextJsAssetsInspected: 10, maxNextJsRoutesProcessed: 10 } } } });
    const context = new ScanContext({ target: `${origin}/account`, scope: scope as any, config: defaultConfig, plan, outputDir: ".", authProfileSet });
    const seed = await context.httpClient.send({ url: `${origin}/account`, method: "GET" }); context.state.recordResponse(seed); context.state.recordTechnologies([{ name: "Next.js", category: "framework", confidence: "High", signals: ["fixture"] }]);
    const result = await new NextJsReviewModule().run(context);
    const crossActor = result.findings?.find((finding) => finding.type === "Next.js Cross-Actor Data Exposure");
    expect(crossActor).toMatchObject({ tags: expect.arrayContaining(["cross-actor"]), evidence: { valueAttestations: expect.arrayContaining([expect.objectContaining({ fingerprintAlgorithm: "HMAC-SHA-256", fingerprintScope: "scan" })]) } });
    expect(result.findings?.some((finding) => finding.type === "Next.js Shared Cache Private Data Exposure")).toBe(false);
    expect(result.nextJsReview?.requestBudget?.cacheDifferential.used).toBe(4);
    expect(JSON.stringify(result)).not.toContain(crossActorCanary);
  });
});
