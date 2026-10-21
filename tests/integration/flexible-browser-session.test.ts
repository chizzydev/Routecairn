import { it as platformTest, expect } from "vitest";
const it = platformTest.skipIf(process.platform !== "win32");
import { createServer } from "node:http";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { actorRegistrySchema, credentialDigest } from "../../src/core/auth/ActorRegistry.js";
import { assessWorkflow } from "../../src/core/auth/AssessmentCapabilities.js";
import { BrowserCrawlerModule } from "../../src/modules/browserCrawler/BrowserCrawlerModule.js";
import { PlaywrightCrawler } from "../../src/modules/browserCrawler/PlaywrightCrawler.js";
import { targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { testPlan } from "../helpers/plan.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
it.each(["COOKIE_SESSION", "FORM_LOGIN"] as const)(
  "actual Windows Edge expiring-authority HTTP registry %s preserves the native browser boundary",
  async (mode) => {
    const root = createOwnedTestDirectory("flexible-edge-session"),
      session = randomBytes(24).toString("base64url"),
      password = randomBytes(24).toString("base64url"),
      bindingKey = randomBytes(32).toString("base64url"),
      wire: Array<{ path: string; method: string; authenticated: boolean }> = [];
    const body = "username=fixture-user&password=" + password,
      server = createServer((q, r) => {
        const authenticated = q.headers.cookie === "sid=" + session;
        wire.push({ path: q.url ?? "", method: q.method ?? "", authenticated });
        r.setHeader("content-type", "text/html");
        if (q.url === "/login") {
          r.end(
            '<form action="/session" method="post"><input name="username"><input name="password" type="password"><button>Sign in</button></form>'
          );
          return;
        }
        if (q.url === "/session" && q.method === "POST") {
          let received = "";
          q.on("data", (b) => {
            received += String(b);
          });
          q.on("end", () => {
            if (received !== body) {
              r.writeHead(401).end("invalid");
              return;
            }
            r.writeHead(302, { location: "/app", "set-cookie": "sid=" + session + "; HttpOnly; SameSite=Lax" }).end();
          });
          return;
        }
        if (!authenticated) {
          r.writeHead(401).end('<p id="denied">Authentication required</p>');
          return;
        }
        r.end(
          '<html><h1 id="authenticated">Owned private application</h1><a href="https://foreign.invalid/">External identity provider is not a target</a></html>'
        );
      });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const a = server.address();
    if (!a || typeof a === "string") throw Error("fixture");
    const origin = "http://127.0.0.1:" + a.port;
    const profile = authProfileSchema.parse({
        label: "Existing browser test account",
        headers: {},
        cookies: mode === "COOKIE_SESSION" ? [{ name: "sid", value: session }] : [],
        identityVerification: { mode: "disabled" },
        browserBootstrap: {
          schemaVersion: 1,
          ...(mode === "FORM_LOGIN"
            ? {
                loginSecrets: { username: "fixture-user", password },
                login: {
                  startUrl: origin + "/login",
                  allowedWritePaths: ["/session"],
                  successUrlPrefix: origin + "/app",
                  steps: [
                    { action: "fill", selector: "input[name=username]", valueRef: "username" },
                    { action: "fill", selector: "input[name=password]", valueRef: "password" },
                    { action: "click", selector: "button" },
                    { action: "waitForUrl", urlPrefix: origin + "/app" }
                  ]
                }
              }
            : {}),
          journeys: [],
          proofCases: []
        }
      }),
      registry = actorRegistrySchema.parse({
        contractVersion: 2,
        registryId: randomUUID(),
        organizationId: "owned-browser-fixture",
        targetOrigin: origin,
        actors: [
          {
            id: "actor0",
            label: "Browser actor",
            authentication: {
              mechanism: "BROWSER_SESSION",
              credentialRef: "owned-profile",
              credentialDigest: credentialDigest(profile, bindingKey),
              credentialExpiresAt: new Date(Date.now() + 60000).toISOString(),
              accountProvenance: "OWNER_APPROVED_EXISTING_TEST",
              suitableForTesting: true
            }
          }
        ],
        workflows: [{ id: "browser", family: "BROWSER_OBSERVATION", actorIds: ["actor0"], reviewed: true }]
      }),
      scope = {
        ...exampleScope,
        allowedDomains: ["127.0.0.1"],
        allowedMethods: ["GET" as const, "POST" as const],
        disallowedPaths: [],
        sameOriginOnly: true
      },
      base = testPlan("quick", { scope }),
      now = Date.now(),
      authorization = targetAuthorizationSchema.parse({
        schemaVersion: 1,
        mode: "BUG_BOUNTY_AUTHORIZED",
        targetOrigin: origin,
        proof: { reference: "Explicit owner synthetic native browser fixture", sha256: "a".repeat(64) },
        bugBounty: {
          program: "Owned local browser session fixture",
          platform: "LOCAL",
          scopeDocumentSha256: "b".repeat(64),
          inScope: [{ origin, pathPrefix: "/" }],
          outOfScope: [],
          rules: ["Only exact login POST and owned read-only application"],
          prohibitedActions: ["No external or other application requests"],
          startsAt: new Date(now - 1000).toISOString(),
          expiresAt: new Date(now + 60000).toISOString(),
          maxRequests: 30,
          rateLimitPerSecond: 20,
          authenticationPermitted: true,
          requests:
            mode === "FORM_LOGIN"
              ? [
                  {
                    origin,
                    path: "/session",
                    method: "POST",
                    effect: "AUTHENTICATION",
                    bodySha256: createHash("sha256").update(body).digest("hex")
                  }
                ]
              : [],
          reportMode: "BUG_BOUNTY_SAFE"
        }
      }),
      context = new ScanContext({
        target: origin + "/app",
        scope,
        config: defaultConfig,
        outputDir: root,
        plan: {
          ...base,
          actorRegistry: registry,
          targetAuthorization: authorization,
          authentication: { ...base.authentication, required: false },
          limits: { ...base.limits, maxDepth: 0, maxRequests: 30, cleanupReservedRequests: 0, requestTimeoutMs: 10000 },
          modules: [
            {
              id: "browser-crawler",
              phase: "intelligence",
              settings: {
                browserAllowPrivateNetwork: true,
                browserAllowedPrivateOrigins: [origin],
                browserMaxPages: 1,
                browserCaptureScreenshot: true,
                browserAllowedResourceTypes: ["document"]
              },
              limits: {},
              includedBecause: ["Explicit browser session fixture"]
            }
          ]
        },
        eventSink: {
          emit: (event) => {
            appendFileSync(join(root, "EDGE_NATIVE_EVENTS.jsonl"), JSON.stringify(event) + "\n");
          }
        },
        actorProfiles: { actor0: profile },
        actorBindingKey: bindingKey,
        organizationId: registry.organizationId
      });
    try {
      const expected = new WeakMap<object, Record<string, string>>(),
        normal = (headers: Readonly<Record<string, string | string[]>>) =>
          Object.fromEntries(
            Object.entries(headers).map(([k, v]) => [
              k.toLowerCase(),
              createHmac("sha256", bindingKey)
                .update(Array.isArray(v) ? v.join(", ") : v.trim())
                .digest("hex")
            ])
          );
      const evaluate = context.httpClient.evaluateBrowserRequest.bind(context.httpClient),
        login = context.httpClient.evaluateBrowserLoginRequest.bind(context.httpClient),
        matches = context.httpClient.matchesBrowserProxyRequest.bind(context.httpClient);
      context.httpClient.evaluateBrowserRequest = (input, source) => {
        const d = evaluate(input, source);
        if (source) expected.set(d, normal(source.headers));
        return d;
      };
      context.httpClient.evaluateBrowserLoginRequest = (input, source) => {
        const d = login(input, source);
        if (source) expected.set(d, normal(source.headers));
        return d;
      };
      context.httpClient.matchesBrowserProxyRequest = (decision, session, actual) => {
        const match = matches(decision, session, actual);
        if (!match) {
          const want = expected.get(decision) ?? {},
            got = normal(actual.headers);
          appendFileSync(
            join(root, "EDGE_HEADER_DIFFERENCES.jsonl"),
            JSON.stringify({
              path: new URL(actual.url).pathname,
              method: actual.method,
              expectedNames: Object.keys(want),
              actualNames: Object.keys(got),
              changed: Object.keys(want).filter((k) => want[k] !== got[k]),
              added: Object.keys(got).filter((k) => !(k in want))
            }) + "\n"
          );
        }
        return match;
      };
      const module = new BrowserCrawlerModule({
          crawl: (o) =>
            new PlaywrightCrawler().crawl({
              ...o,
              browserChannel: "msedge",
              dnsResolver: async (hostname) => {
                if (hostname !== "127.0.0.1") throw Error("FIXTURE_DNS_OUTSIDE_OWNED_HOST");
                return ["127.0.0.1"];
              }
            })
        }),
        result = await module.run(context);
      writeFileSync(
        join(root, "EDGE_NATIVE_SESSION_RECEIPT.json"),
        JSON.stringify(
          {
            platform: process.platform,
            mode,
            wire,
            result,
            budget: context.requestLedger.snapshot(),
            independentAccuracy: false
          },
          null,
          2
        ),
        { flag: "wx" }
      );
      expect(result.browserCrawl?.authentication?.bootstrapSucceeded).toBe(true);
      expect(result.browserCrawl?.networkIsolation?.state).toBe("HEALTHY");
      expect(wire.some((w) => w.path === "/app" && w.authenticated)).toBe(true);
      expect(wire.filter((w) => w.method === "POST")).toHaveLength(mode === "FORM_LOGIN" ? 1 : 0);
      expect(JSON.stringify(result)).not.toContain(session);
      expect(JSON.stringify(result)).not.toContain(password);
      expect(context.state.getIdentityVerification()).toBeUndefined();
      const https = { ...registry, targetOrigin: "https://owned.example.test" };
      expect(assessWorkflow(https, "browser").status).toBe("BLOCKED");
      expect(assessWorkflow(https, "browser").reason).toContain("HTTPS_BROWSER_TRANSPORT_HOLD");
    } finally {
      await context.dispose();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
      retainOwnedTestDirectory(root);
    }
  }
);
