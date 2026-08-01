import { describe, expect, it } from "vitest";
import { toPathCandidates } from "../../src/modules/browserCrawler/PlaywrightCrawler.js";
import { BrowserPolicyEngine, browserPolicyFromSettings, isProhibitedAddress } from "../../src/modules/browserCrawler/BrowserPolicy.js";
import { testPlan } from "../helpers/plan.js";
import { BrowserCrawlerModule } from "../../src/modules/browserCrawler/BrowserCrawlerModule.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";

describe("browser crawler helpers", () => {
  it("converts rendered links into scoped path candidates", () => {
    const candidates = toPathCandidates(
      ["/dashboard", "https://example.com/api/rendered", "https://cdn.example.net/app.js", "mailto:test@example.com", "#local"],
      "https://example.com/",
      true
    );

    expect(candidates).toEqual([
      { path: "/dashboard", source: "browser:rendered-link" },
      { path: "/api/rendered", source: "browser:rendered-link" }
    ]);
  });

  it("can retain cross-origin rendered links when same-origin is disabled", () => {
    const candidates = toPathCandidates(["https://api.example.net/v1"], "https://example.com/", false);

    expect(candidates).toEqual([{ path: "/v1", source: "browser:rendered-link" }]);
  });

  it("derives browser policy from resolved module settings and evidence policy", () => {
    const fullPlan = testPlan("full");
    const fullPolicy = browserPolicyFromSettings(
      fullPlan.modules.find((modulePlan) => modulePlan.id === "browser-crawler")?.settings ?? {},
      fullPlan.limits,
      fullPlan.evidence
    );
    const minimalPolicy = browserPolicyFromSettings({ browserCaptureScreenshot: true }, fullPlan.limits, { ...fullPlan.evidence, level: "minimal" });

    expect(fullPolicy.maxPages).toBe(3);
    expect(fullPolicy.blockThirdParty).toBe(true);
    expect(fullPolicy.captureScreenshot).toBe(true);
    expect(minimalPolicy.captureScreenshot).toBe(false);
  });

  it("blocks unsafe browser resources before broker budget accounting", async () => {
    const policy = browserPolicyFromSettings({ browserMaxRequestsPerPage: 1 }, testPlan("full").limits, testPlan("full").evidence);
    const engine = new BrowserPolicyEngine("https://app.example.test/", policy, async () => ["203.0.113.10"]);

    await expect(
      engine.evaluateRequest({
        url: "javascript:alert(1)",
        pageUrl: "https://app.example.test/",
        resourceType: "document",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "prohibited-protocol" });
    await expect(
      engine.evaluateRequest({
        url: "https://cdn.example.test/app.js",
        pageUrl: "https://app.example.test/",
        resourceType: "script",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "third-party-blocked" });
    await expect(
      engine.evaluateRequest({
        url: "https://app.example.test/too-many",
        pageUrl: "https://app.example.test/",
        resourceType: "document",
        requestsSeenForPage: 2
      })
    ).resolves.toMatchObject({ allowed: false, reason: "page-request-budget-exceeded" });
  });

  it("blocks private, metadata, localhost, internal, alternate-IP, and DNS-resolved private destinations by default", async () => {
    const policy = browserPolicyFromSettings({}, testPlan("full").limits, testPlan("full").evidence);
    const engine = new BrowserPolicyEngine("https://app.example.test/", policy, async (hostname) => (hostname === "public-looking.example.test" ? ["10.0.0.7"] : ["203.0.113.10"]));

    for (const url of [
      "http://127.0.0.1/",
      "http://[::1]/",
      "http://10.0.0.1/",
      "http://192.168.1.5/",
      "http://172.16.0.1/",
      "http://169.254.169.254/latest/meta-data/",
      "http://localhost/",
      "http://intranet/",
      "http://app.internal/",
      "http://0x7f000001/",
      "http://2130706433/",
      "http://0177.0000.0000.0001/",
      "http://public-looking.example.test/"
    ]) {
      const decision = await engine.evaluateRequest({ url, pageUrl: "https://app.example.test/", resourceType: "document", requestsSeenForPage: 1 });
      expect(decision.allowed, url).toBe(false);
      expect(["private-destination-blocked", "internal-hostname-blocked", "third-party-blocked"]).toContain(decision.reason);
    }

    expect(isProhibitedAddress("169.254.169.254")).toBe(true);
  });

  it("fails closed when any DNS answer is private or resolution fails", async () => {
    const policy = browserPolicyFromSettings({}, testPlan("full").limits, testPlan("full").evidence);

    await expect(
      new BrowserPolicyEngine("https://app.example.test/", policy, async () => ["203.0.113.10", "10.0.0.8"]).evaluateRequest({
        url: "https://mixed.example.test/app",
        pageUrl: "https://app.example.test/",
        resourceType: "document",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "private-destination-blocked" });

    await expect(
      new BrowserPolicyEngine("https://app.example.test/", policy, async () => {
        throw new Error("dns failed");
      }).evaluateRequest({
        url: "https://unknown.example.test/app",
        pageUrl: "https://app.example.test/",
        resourceType: "document",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "private-destination-blocked" });
  });

  it("allows private destinations only when the resolved browser policy explicitly permits their exact origin", async () => {
    const policy = browserPolicyFromSettings({ browserAllowPrivateNetwork: true }, testPlan("full").limits, testPlan("full").evidence);
    const exactPolicy = browserPolicyFromSettings(
      { browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: ["http://127.0.0.1"] },
      testPlan("full").limits,
      testPlan("full").evidence
    );

    await expect(
      new BrowserPolicyEngine("http://127.0.0.1/", policy).evaluateRequest({
        url: "http://127.0.0.1/app",
        pageUrl: "http://127.0.0.1/",
        resourceType: "document",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "private-destination-blocked" });
    await expect(
      new BrowserPolicyEngine("http://127.0.0.1/", exactPolicy).evaluateRequest({
        url: "http://127.0.0.1/app",
        pageUrl: "http://127.0.0.1/",
        resourceType: "document",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: true });
  });

  it("defines third party as a different origin and supports narrow origin exceptions", async () => {
    const base = testPlan("full");
    const blocked = browserPolicyFromSettings({ browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: ["https://app.example.test"] }, base.limits, base.evidence);
    const withException = browserPolicyFromSettings(
      { browserAllowPrivateNetwork: true, browserAllowedThirdPartyOrigins: ["https://static.example.test:8443"] },
      base.limits,
      base.evidence
    );

    await expect(
      new BrowserPolicyEngine("https://app.example.test/", blocked, async () => ["203.0.113.10"]).evaluateRequest({
        url: "https://app.example.test:8443/app.js",
        pageUrl: "https://app.example.test/",
        resourceType: "script",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "third-party-blocked" });
    await expect(
      new BrowserPolicyEngine("https://app.example.test/", blocked, async () => ["203.0.113.10"]).evaluateRequest({
        url: "https://cdn.example.test/app.js",
        pageUrl: "https://app.example.test/",
        resourceType: "script",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "third-party-blocked" });
    await expect(
      new BrowserPolicyEngine("https://app.example.co.uk/", blocked, async () => ["203.0.113.10"]).evaluateRequest({
        url: "https://cdn.example.co.uk/app.js",
        pageUrl: "https://app.example.co.uk/",
        resourceType: "script",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "third-party-blocked" });
    await expect(
      new BrowserPolicyEngine("https://app.example.test/", withException, async () => ["203.0.113.10"]).evaluateRequest({
        url: "https://static.example.test:8443/app.js",
        pageUrl: "https://app.example.test/",
        resourceType: "script",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: true });
  });

  it("controls WebSocket destinations with explicit WebSocket policy and exact origin exceptions", async () => {
    const base = testPlan("full");
    const blocked = browserPolicyFromSettings({}, base.limits, base.evidence);
    const allowed = browserPolicyFromSettings(
      {
        browserAllowWebSockets: true,
        browserAllowedThirdPartyOrigins: ["wss://socket.example.test"],
        browserAllowPrivateNetwork: true,
        browserAllowedPrivateOrigins: ["ws://127.0.0.1:8080"]
      },
      base.limits,
      base.evidence
    );

    await expect(
      new BrowserPolicyEngine("https://app.example.test/", blocked, async () => ["203.0.113.10"]).evaluateRequest({
        url: "wss://app.example.test/socket",
        pageUrl: "https://app.example.test/",
        resourceType: "websocket",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "websocket-blocked" });
    await expect(
      new BrowserPolicyEngine("https://app.example.test/", allowed, async () => ["203.0.113.10"]).evaluateRequest({
        url: "wss://other.example.test/socket",
        pageUrl: "https://app.example.test/",
        resourceType: "websocket",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: false, reason: "third-party-blocked" });
    await expect(
      new BrowserPolicyEngine("https://app.example.test/", allowed, async () => ["203.0.113.10"]).evaluateRequest({
        url: "wss://socket.example.test/socket",
        pageUrl: "https://app.example.test/",
        resourceType: "websocket",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: true });
    await expect(
      new BrowserPolicyEngine("http://127.0.0.1:8080/", allowed).evaluateRequest({
        url: "ws://127.0.0.1:8080/socket",
        pageUrl: "http://127.0.0.1:8080/",
        resourceType: "websocket",
        requestsSeenForPage: 1
      })
    ).resolves.toMatchObject({ allowed: true });
  });

  it("uses traversal depth and canonical URLs rather than URL path depth", async () => {
    const policy = browserPolicyFromSettings(
      { browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: ["https://app.example.test"] },
      { ...testPlan("full").limits, maxDepth: 1 },
      testPlan("full").evidence
    );
    const engine = new BrowserPolicyEngine("https://app.example.test/root", policy, async () => ["203.0.113.10"]);

    await expect(engine.shouldQueueUrl("/a/b/c?z=2&a=1#fragment", 1)).resolves.toEqual({
      allowed: true,
      normalizedUrl: "https://app.example.test/a/b/c?z=2&a=1"
    });
    await expect(engine.shouldQueueUrl("/page?item=1", 1)).resolves.toMatchObject({ allowed: true });
    await expect(engine.shouldQueueUrl("/page?item=2", 1)).resolves.toMatchObject({ allowed: true });
    await expect(engine.shouldQueueUrl("/too-deep", 2)).resolves.toEqual({ allowed: false, reason: "max-depth-exceeded" });
  });

  it("normalizes host casing, default ports, and fragments without reordering query strings", async () => {
    const policy = browserPolicyFromSettings({}, testPlan("full").limits, testPlan("full").evidence);
    const engine = new BrowserPolicyEngine("HTTP://APP.EXAMPLE.TEST:80/root", policy, async () => ["203.0.113.10"]);

    await expect(engine.shouldQueueUrl("HTTP://APP.EXAMPLE.TEST:80/path?role=user&role=admin&empty=&flag#frag", 1)).resolves.toEqual({
      allowed: true,
      normalizedUrl: "http://app.example.test/path?role=user&role=admin&empty=&flag"
    });
    await expect(engine.shouldQueueUrl("HTTP://APP.EXAMPLE.TEST:80/path?role=admin&role=user", 1)).resolves.toEqual({
      allowed: true,
      normalizedUrl: "http://app.example.test/path?role=admin&role=user"
    });
  });

  it("does not silently run an anonymous browser crawl for authenticated plans", async () => {
    const basePlan = testPlan("full");
    const plan = { ...basePlan, authentication: { ...basePlan.authentication, required: true } };
    const context = new ScanContext({
      target: "https://example.com/",
      scope: exampleScope,
      config: defaultConfig,
      plan,
      outputDir: "."
    });

    const result = await new BrowserCrawlerModule().run(context);

    expect(result.browserCrawl).toBeUndefined();
    expect(result.notes.join(" ")).toContain("authenticated browser bootstrap is not implemented");
  });
});
