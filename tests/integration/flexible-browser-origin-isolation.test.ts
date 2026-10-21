import { expect, it as platformTest } from "vitest";
import { createServer } from "node:http";
import { randomUUID, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { actorRegistrySchema, credentialDigest } from "../../src/core/auth/ActorRegistry.js";
import { targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
import { BrowserCrawlerModule } from "../../src/modules/browserCrawler/BrowserCrawlerModule.js";
import { PlaywrightCrawler } from "../../src/modules/browserCrawler/PlaywrightCrawler.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { testPlan } from "../helpers/plan.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
const it = platformTest.skipIf(process.platform !== "win32");
it.each(["COOKIE", "BEARER", "API_KEY"] as const)(
  "actual Edge separates %s material from a separately in-scope same-host origin",
  async (mechanism) => {
    const root = createOwnedTestDirectory("r3-browser-origin"),
      secret = randomUUID(),
      bindingKey = randomBytes(32).toString("base64url");
    const foreign: Array<{ cookie: boolean; bearer: boolean; key: boolean }> = [],
      primary: Array<{ authenticated: boolean }> = [];
    let origin = "";
    const secondary = createServer((q, r) => {
      foreign.push({
        cookie: q.headers.cookie === "sid=" + secret,
        bearer: q.headers.authorization === "Bearer " + secret,
        key: q.headers["x-fixture-key"] === secret
      });
      r.writeHead(200, {
        "content-type": "application/json",
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true"
      }).end('{"owned":true}');
    });
    await new Promise<void>((r) => secondary.listen(0, "127.0.0.1", r));
    const b = secondary.address();
    if (!b || typeof b === "string") throw Error("fixture");
    const other = "http://127.0.0.1:" + b.port;
    const app = createServer((q, r) => {
      primary.push({
        authenticated:
          q.headers.cookie === "sid=" + secret ||
          q.headers.authorization === "Bearer " + secret ||
          q.headers["x-fixture-key"] === secret
      });
      r.writeHead(200, { "content-type": "text/html" }).end(
        '<html><h1>Owned primary app</h1><script>fetch("' +
          other +
          '/foreign",{credentials:"include"}).then(()=>{document.title="finished"}).catch(()=>{document.title="blocked"})</script></html>'
      );
    });
    await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
    const a = app.address();
    if (!a || typeof a === "string") throw Error("fixture");
    origin = "http://127.0.0.1:" + a.port;
    const profile = authProfileSchema.parse({
      label: "Generated browser actor",
      headers:
        mechanism === "BEARER"
          ? { Authorization: "Bearer " + secret }
          : mechanism === "API_KEY"
            ? { "X-Fixture-Key": secret }
            : {},
      cookies: mechanism === "COOKIE" ? [{ name: "sid", value: secret }] : [],
      identityVerification: { mode: "disabled" }
    });
    const registry = actorRegistrySchema.parse({
      contractVersion: 2,
      registryId: randomUUID(),
      organizationId: "owned-r3-browser",
      targetOrigin: origin,
      actors: [
        {
          id: "actor0",
          label: "Owned actor",
          authentication: {
            mechanism,
            credentialRef: "generated-credential",
            credentialDigest: credentialDigest(profile, bindingKey),
            credentialExpiresAt: new Date(Date.now() + 60000).toISOString(),
            accountProvenance: "FRESH_DISPOSABLE",
            suitableForTesting: true
          }
        }
      ],
      workflows: [{ id: "browser", family: "BROWSER_OBSERVATION", actorIds: ["actor0"], reviewed: true }]
    });
    const scope = {
        ...exampleScope,
        allowedDomains: ["127.0.0.1"],
        disallowedPaths: [],
        allowedMethods: ["GET" as const],
        rateLimitPerSecond: 20,
        concurrency: 1,
        sameOriginOnly: false
      },
      base = testPlan("quick", { scope }),
      now = Date.now();
    const auth = targetAuthorizationSchema.parse({
      schemaVersion: 1,
      mode: "BUG_BOUNTY_AUTHORIZED",
      targetOrigin: origin,
      proof: { reference: "Generated owned origin isolation conformance", sha256: "a".repeat(64) },
      bugBounty: {
        program: "Generated separate-origin application",
        platform: "LOCAL",
        scopeDocumentSha256: "b".repeat(64),
        inScope: [
          { origin, pathPrefix: "/" },
          { origin: other, pathPrefix: "/" }
        ],
        outOfScope: [],
        rules: ["Read scope is distinct from actor credential-use consent"],
        prohibitedActions: ["No credential forwarding to secondary origin"],
        startsAt: new Date(now - 1000).toISOString(),
        expiresAt: new Date(now + 60000).toISOString(),
        maxRequests: 12,
        rateLimitPerSecond: 20,
        authenticationPermitted: true,
        requests: [],
        reportMode: "BUG_BOUNTY_SAFE"
      }
    });
    const context = new ScanContext({
      target: origin + "/app",
      scope,
      config: defaultConfig,
      outputDir: root,
      organizationId: registry.organizationId,
      actorBindingKey: bindingKey,
      actorProfiles: { actor0: profile },
      plan: {
        ...base,
        actorRegistry: registry,
        targetAuthorization: auth,
        authentication: { ...base.authentication, required: false },
        limits: { ...base.limits, maxDepth: 0, maxRequests: 12, cleanupReservedRequests: 0, requestTimeoutMs: 5000 },
        modules: [
          {
            id: "browser-crawler",
            phase: "intelligence",
            settings: {
              browserAllowPrivateNetwork: true,
              browserAllowedPrivateOrigins: [origin, other],
              browserAllowedThirdPartyOrigins: [other],
              browserAllowedResourceTypes: ["document", "fetch"],
              browserMaxPages: 1,
              browserCaptureScreenshot: true
            },
            limits: {},
            includedBecause: ["Owned browser origin isolation adversary"]
          }
        ]
      }
    });
    try {
      const module = new BrowserCrawlerModule({
          crawl: (o) => new PlaywrightCrawler().crawl({ ...o, browserChannel: "msedge" })
        }),
        result = await module.run(context);
      writeFileSync(
        join(root, "BROWSER_ORIGIN_RECEIPT.json"),
        JSON.stringify(
          {
            mechanism,
            primary,
            foreign,
            result,
            scopeApprovedBothOrigins: true,
            secondaryCredentialUseApproved: false
          },
          null,
          2
        ),
        { flag: "wx" }
      );
      expect(primary.some((p) => p.authenticated)).toBe(true);
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(foreign.some((p) => p.cookie || p.bearer || p.key)).toBe(false);
      expect(
        result.browserCrawl?.networkRequests.some(
          (q) => q.reason === "authenticated-secondary-origin-credential-grant-required"
        ) ||
          result.browserCrawl?.policyEvents?.some(
            (q) => q.reason === "authenticated-secondary-origin-credential-grant-required"
          )
      ).toBe(true);
    } finally {
      await context.httpClient.close();
      app.closeAllConnections();
      secondary.closeAllConnections();
      await Promise.all([
        new Promise<void>((r) => app.close(() => r())),
        new Promise<void>((r) => secondary.close(() => r()))
      ]);
      retainOwnedTestDirectory(root);
    }
  }
);
