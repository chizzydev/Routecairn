import { expect, it as platformTest } from "vitest";
import { createServer, request } from "node:https";
import { chromium } from "playwright";
import { generate } from "selfsigned";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { BrowserNetworkBoundary } from "../../src/modules/browserCrawler/BrowserNetworkBoundary.js";
import { browserPolicyFromSettings } from "../../src/modules/browserCrawler/BrowserPolicy.js";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
import {
  TargetAuthorizationGuard,
  targetAuthorizationSchema
} from "../../src/core/authorization/TargetAuthorization.js";
import { exampleScope } from "../../src/config/defaults.js";
import { testPlan } from "../helpers/plan.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
const it = platformTest.skipIf(process.platform !== "win32");
it("real Edge HTTPS CONNECT stays refused under expiring authority; owned TLS control validates its certificate", async () => {
  const root = createOwnedTestDirectory("r3-https-transport-hold"),
    wire: Array<{ path: string; authenticated: boolean }> = [];
  const cert = await generate([{ name: "commonName", value: "localhost" }], {
    extensions: [
      {
        name: "subjectAltName",
        altNames: [
          { type: 2, value: "localhost" },
          { type: 7, ip: "127.0.0.1" }
        ]
      }
    ]
  });
  const server = createServer({ key: cert.private, cert: cert.cert }, (q, r) => {
    wire.push({ path: q.url ?? "", authenticated: !!q.headers.authorization || !!q.headers.cookie });
    r.end("Owned TLS fixture");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const a = server.address();
  if (!a || typeof a === "string") throw Error("fixture");
  const origin = "https://127.0.0.1:" + a.port,
    now = Date.now();
  const guard = new TargetAuthorizationGuard(
    targetAuthorizationSchema.parse({
      schemaVersion: 1,
      mode: "BUG_BOUNTY_AUTHORIZED",
      targetOrigin: origin,
      proof: { reference: "Generated TLS application transport refusal only", sha256: "a".repeat(64) },
      bugBounty: {
        program: "Owned R3 TLS fixture",
        platform: "LOCAL",
        scopeDocumentSha256: "b".repeat(64),
        inScope: [{ origin, pathPrefix: "/" }],
        outOfScope: [],
        rules: ["Exact owned GET only"],
        prohibitedActions: ["No external network"],
        startsAt: new Date(now - 1000).toISOString(),
        expiresAt: new Date(now + 60000).toISOString(),
        maxRequests: 8,
        rateLimitPerSecond: 20,
        authenticationPermitted: true,
        requests: [],
        reportMode: "BUG_BOUNTY_SAFE"
      }
    })
  );
  const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], sameOriginOnly: true },
    base = testPlan("quick", { scope });
  const broker = new RequestSafetyBroker(
    {
      userAgent: "RouteCairn/0.1",
      timeoutMs: 3000,
      bodyPreviewBytes: 2048,
      maxResponseBytes: 2048,
      rateLimitPerSecond: 20,
      concurrency: 1,
      maxRequests: 8,
      retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1, retryStatusCodes: [] }
    },
    new ScopeMatcher(origin, scope, guard),
    () => {}
  );
  const boundary = new BrowserNetworkBoundary({
    targetUrl: origin,
    requestBroker: broker,
    policy: browserPolicyFromSettings(
      { browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: [origin] },
      base.limits,
      base.evidence
    ),
    timeoutMs: 3000
  });
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  try {
    const status = await new Promise<number>((resolve, reject) => {
      const q = request(origin + "/certificate-control", { ca: cert.cert, rejectUnauthorized: true }, (r) => {
        r.resume();
        r.on("end", () => resolve(r.statusCode ?? 0));
      });
      q.on("error", reject);
      q.end();
    });
    expect(status).toBe(200);
    await boundary.start();
    browser = await chromium.launch({
      channel: "msedge",
      headless: true,
      proxy: boundary.playwrightProxy(),
      args: [
        "--proxy-bypass-list=<-loopback>",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-quic"
      ]
    });
    const context = await browser.newContext({ ignoreHTTPSErrors: false });
    const page = await context.newPage();
    await expect(page.goto(origin + "/private", { timeout: 5000 })).rejects.toThrow();
    expect(wire).toEqual([{ path: "/certificate-control", authenticated: false }]);
    expect(boundary.diagnostics().lastFailureCode).toBe("EXPIRING_AUTHORITY_BROWSER_TUNNEL_UNSUPPORTED");
    writeFileSync(
      join(root, "HTTPS_REFUSAL_RECEIPT.json"),
      JSON.stringify(
        {
          wire,
          certificateControlStatus: status,
          certificateVerification: true,
          diagnostics: boundary.diagnostics(),
          verdict: "HOLD_NO_HTTPS_BROWSER_ACCEPTANCE",
          reason: "An opaque CONNECT tunnel cannot check exact application requests at final initiation"
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    await browser?.close();
    await boundary.close();
    await broker.close();
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    retainOwnedTestDirectory(root);
  }
});
