import { describe, expect, it } from "vitest";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { NextJsReviewModule } from "../../src/modules/nextjsReview/NextJsReviewModule.js";
import {
  analyzeStructuredBody,
  cacheMetadata,
  classifyRscSurface,
  derivePagesDataUrl,
  extractNextDataFromHtml,
  extractSourceMapReferences,
  isDynamicRouteTemplate,
  normalizeRouteTemplate,
  parseManifest,
  parseSourceMap
} from "../../src/modules/nextjsReview/NextJsParsers.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { testPlan } from "../helpers/plan.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";

describe("NextJsReviewModule", () => {
  it("skips safely when Next.js is not detected", async () => {
    const context = new ScanContext({ target: "https://example.test/", scope: exampleScope, config: defaultConfig, plan: testPlan("quick"), outputDir: "." });
    const result = await new NextJsReviewModule().run(context);
    expect(result.nextJsReview).toMatchObject({ detected: false, detectionConfidence: "NOT_DETECTED", dataRoutes: [], sourceMaps: [], coverage: { moduleState: "SKIPPED_NOT_DETECTED" } });
  });

  it("keeps expected public Next.js behavior observational rather than findings", async () => {
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "full", scope: exampleScope, config: defaultConfig, overrides: { includeModules: ["baseline", "tech-fingerprint", "nextjs-review"], moduleSettings: { "nextjs-review": { inspectNextJsSourceMaps: false, inspectKnownNextJsDataSurfaces: false, maxNextJsManifestRequests: 1, maxNextJsDataSurfaceRequests: 1, maxNextJsSourceMapRequests: 1, maxNextJsCacheDifferentialRequests: 0, maxNextJsAssetsInspected: 10, maxNextJsRoutesProcessed: 10, nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW" } } } });
    const context = new ScanContext({ target: "https://example.test/", scope: exampleScope, config: defaultConfig, plan, outputDir: "." });
    context.state.recordTechnologies([{ name: "Next.js", category: "framework", confidence: "High", signals: ["fixture"] }]);
    context.state.recordResponse({ requestedUrl: "https://example.test/", finalUrl: "https://example.test/", method: "GET", statusCode: 200, headers: { "cache-control": "public, s-maxage=60", "x-nextjs-cache": "HIT" }, contentType: "text/html", bodyPreview: '<script id="__NEXT_DATA__" type="application/json">{"buildId":"public-build","page":"/","props":{"pageProps":{"marketing":"hello"}},"runtimeConfig":{"NEXT_PUBLIC_ANALYTICS_ID":"analytics-12345"}}</script>', responseTimeMs: 1, redirectChain: [] });
    context.state.recordResponse({ requestedUrl: "https://example.test/_next/static/public/_buildManifest.js", finalUrl: "https://example.test/_next/static/public/_buildManifest.js", method: "GET", statusCode: 200, headers: {}, contentType: "application/javascript", bodyPreview: 'self.__BUILD_MANIFEST={"/admin":["static/admin.js"]};', responseTimeMs: 1, redirectChain: [] });
    context.state.recordBrowserCrawl({ startUrl: "https://example.test/", renderedLinks: [], networkRequests: [{ url: "https://example.test/dashboard?_rsc=opaque-observed", method: "GET", resourceType: "fetch", transmitted: true }], consoleErrors: [], formsDetected: 0, formsSubmitted: 0, notes: [] });
    const result = await new NextJsReviewModule().run(context);
    expect(result.findings ?? []).toEqual([]);
    expect(result.nextJsReview).toMatchObject({ detected: true, routerKind: "MIXED", coverage: { cacheDifferential: "DISABLED", sourceMapReview: "DISABLED" } });
  });

  it("honors cancellation before secondary Next.js work", async () => {
    const controller = new AbortController(); controller.abort(new Error("fixture cancellation"));
    const context = new ScanContext({ target: "https://example.test/", scope: exampleScope, config: defaultConfig, plan: testPlan("full"), outputDir: ".", abortSignal: controller.signal });
    context.state.recordTechnologies([{ name: "Next.js", category: "framework", confidence: "High", signals: ["fixture"] }]);
    context.state.recordResponse({ requestedUrl: "https://example.test/", finalUrl: "https://example.test/", method: "GET", statusCode: 200, headers: {}, contentType: "text/html", bodyPreview: '<script id="__NEXT_DATA__">{"buildId":"b","page":"/","props":{}}</script>', responseTimeMs: 1, redirectChain: [] });
    await expect(new NextJsReviewModule().run(context)).rejects.toThrow("fixture cancellation");
  });
});

describe("bounded Next.js parsers", () => {
  it("parses __NEXT_DATA__ structurally and excludes raw props from its result", () => {
    const canary = "routecairn-private-ssn-90210";
    const parsed = extractNextDataFromHtml(`<script id="__NEXT_DATA__" type="application/json">${JSON.stringify({ buildId: "build-1", page: "/users/123", props: { pageProps: { ssn: canary, publicTitle: "Hello" } }, runtimeConfig: { NEXT_PUBLIC_ANALYTICS_ID: "public-123" } })}</script>`);
    expect(parsed).toMatchObject({ status: "PARSED", buildId: "build-1", page: "/users/123", routerKind: "PAGES_ROUTER" });
    expect(parsed.propertyPaths).toEqual(expect.arrayContaining(["props.pageProps.ssn", "props.pageProps.publicTitle"]));
    expect(parsed.sensitivity).toEqual([expect.objectContaining({ category: "PRIVATE_FIELD", fieldPath: "props.pageProps.ssn" })]);
    expect(JSON.stringify({ ...parsed, sensitivity: parsed.sensitivity.map(({ rawValue: _rawValue, ...safe }) => safe) })).not.toContain(canary);
  });

  it("treats harmless NEXT_PUBLIC values as public but validates actual runtime secrets", () => {
    const harmless = analyzeStructuredBody(JSON.stringify({ runtimeConfig: { NEXT_PUBLIC_API_BASE: "https://api.example.test", NEXT_PUBLIC_ANALYTICS_ID: "analytics-1234" } }));
    const secret = analyzeStructuredBody(JSON.stringify({ runtimeConfig: { SIGNING_SECRET: "routecairn-signing-secret-canary" } }));
    expect(harmless.sensitivity).toEqual([]);
    expect(secret.sensitivity).toEqual([expect.objectContaining({ fieldPath: "runtimeConfig.SIGNING_SECRET", confidence: "HIGH" })]);
  });

  it("extracts assigned build and SSG manifests without executing JavaScript", () => {
    (globalThis as Record<string, unknown>).__routeCairnExecuted = false;
    const build = parseManifest('self.__BUILD_MANIFEST = {"/about":["static/chunks/about-a1b2c3.js"],"/users/[id]":["static/chunks/user.js"]};', "https://example.test/_next/static/build/_buildManifest.js");
    const ssg = parseManifest('self.__SSG_MANIFEST = {"routes":["/","/blog/post"]};', "https://example.test/_next/static/build/_ssgManifest.js");
    const hostile = parseManifest('self.__BUILD_MANIFEST = {"/":[]}; globalThis.__routeCairnExecuted=true', "https://example.test/_buildManifest.js");
    expect(build).toMatchObject({ kind: "BUILD_MANIFEST", parseStatus: "PARSED", routes: expect.arrayContaining(["/about", "/users/[id]"]) });
    expect(ssg).toMatchObject({ kind: "SSG_MANIFEST", parseStatus: "PARSED", routes: expect.arrayContaining(["/", "/blog/post"]) });
    expect(hostile.parseStatus).toBe("MALFORMED");
    expect((globalThis as Record<string, unknown>).__routeCairnExecuted).toBe(false);
  });

  it("rejects prototype-related keys, deep structures, and oversized bodies", () => {
    expect(analyzeStructuredBody('{"__proto__":{"polluted":true}}').status).toBe("UNSUPPORTED_SHAPE");
    expect(analyzeStructuredBody(JSON.stringify({ a: { b: { c: 1 } } }), { maxBodyBytes: 1024, maxInlineMapEncodedBytes: 1024, maxInlineMapDecodedBytes: 1024, maxEntries: 20, maxDepth: 1, maxStringLength: 100, maxSourcesContentBytes: 100 }).status).toBe("TOO_LARGE");
    expect(parseManifest(`{"routes":["/${"x".repeat(200)}"]}`, "https://example.test/manifest.json", { maxBodyBytes: 64, maxInlineMapEncodedBytes: 64, maxInlineMapDecodedBytes: 64, maxEntries: 10, maxDepth: 4, maxStringLength: 32, maxSourcesContentBytes: 32 }).parseStatus).toBe("TOO_LARGE");
  });

  it("normalizes route groups and never expands dynamic templates", () => {
    expect(normalizeRouteTemplate("/(marketing)/docs/[...slug]/")).toBe("/docs/[...slug]");
    expect(isDynamicRouteTemplate("/users/[id]")).toBe(true);
    expect(isDynamicRouteTemplate("/docs/[[...slug]]")).toBe(true);
    expect(derivePagesDataUrl("https://example.test/", "build-1", "/users/[id]")).toBeUndefined();
    expect(derivePagesDataUrl("https://example.test/", "build-1", "/users/123?locale=en")).toBe("https://example.test/_next/data/build-1/users/123.json?locale=en");
  });

  it("recognizes observed RSC signals without generating RSC values", () => {
    expect(classifyRscSurface("https://example.test/dashboard?_rsc=opaque-observed")).toBe(true);
    expect(classifyRscSurface("https://example.test/dashboard", "text/x-component")).toBe(true);
    expect(classifyRscSurface("https://example.test/dashboard", "text/html")).toBe(false);
  });

  it("discovers only explicit external and bounded inline source maps", () => {
    const inline = Buffer.from(JSON.stringify({ version: 3, sources: ["app.ts"], names: [], mappings: "" })).toString("base64");
    expect(extractSourceMapReferences("console.log(1)", "https://example.test/app.js")).toEqual([]);
    expect(extractSourceMapReferences("//# sourceMappingURL=app.js.map", "https://example.test/app.js")).toEqual([{ url: "https://example.test/app.js.map" }]);
    expect(extractSourceMapReferences(`//# sourceMappingURL=data:application/json;base64,${inline}`, "https://example.test/app.js")[0]).toMatchObject({ url: "https://example.test/app.js#inline-source-map", inlineBody: expect.any(String) });
  });

  it("parses source maps, redacts local paths, and distinguishes harmless maps from secret exposure", () => {
    const harmless = parseSourceMap(JSON.stringify({ version: 3, file: "app.js", sources: ["C:\\Users\\Alice\\company\\app.ts"], sourcesContent: ["export const title='public';"], names: [], mappings: "AAAA" }), "https://example.test/app.js.map", false);
    const secret = parseSourceMap(JSON.stringify({ version: 3, sources: ["webpack://src/config.ts"], sourcesContent: ["const API_KEY='routecairn-source-map-canary-12345';"], names: [], mappings: "AAAA" }), "https://example.test/app.js.map", false);
    expect(harmless).toMatchObject({ parseStatus: "PARSED", sourceCount: 1, sourcesContentCount: 1, severityHint: "low" });
    expect(harmless.sourcePaths?.[0]).toContain("<local-user>");
    expect(secret.transientSensitivity).toEqual([expect.objectContaining({ category: "API_KEY", confidence: "HIGH" })]);
  });

  it("models cache headers as signals rather than findings", () => {
    const metadata = cacheMetadata({ "cache-control": "public, s-maxage=60", vary: "Accept-Encoding", age: "4", etag: '"secret-looking-etag"', "x-nextjs-cache": "HIT" }, "PUBLIC", "sha256:body", "NONE");
    expect(metadata).toMatchObject({ cacheControl: "public, s-maxage=60", age: 4, vary: ["Accept-Encoding"], nextJsCacheState: "HIT", dataSensitivity: "NONE" });
    expect(metadata.etagFingerprint).toMatch(/^sha256:/);
    expect(JSON.stringify(metadata)).not.toContain("secret-looking-etag");
  });

  it("fails malformed and truncated inputs without throwing", () => {
    expect(extractNextDataFromHtml('<script id="__NEXT_DATA__">{"buildId":').status).toBe("MALFORMED");
    expect(parseManifest("self.__BUILD_MANIFEST = {", "https://example.test/_buildManifest.js").parseStatus).toBe("MALFORMED");
    expect(parseSourceMap("not json", "https://example.test/app.js.map", false).parseStatus).toBe("MALFORMED");
  });
});
