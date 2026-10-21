import { it, expect } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  prepareProductionWebCampaign,
  productionCampaignDigest,
  runProductionWebCampaign
} from "../../src/cli/commands/webAssessment.js";
import {
  TargetAuthorizationGuard,
  targetAuthorizationSchema
} from "../../src/core/authorization/TargetAuthorization.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { productionCampaignSchema } from "../../src/core/authorization/ProductionCampaign.js";
it("executes the real existing engine with exact public controls and retained discovery candidates", async () => {
  const root = createOwnedTestDirectory("production23-native"),
    wire: Array<{ url: string; method: string }> = [];
  const server = createServer((req, res) => {
    wire.push({ url: req.url ?? "", method: req.method ?? "" });
    res.setHeader("content-type", req.url?.endsWith(".js") ? "application/javascript" : "text/html");
    res.end(
      req.url?.endsWith(".js")
        ? 'fetch("/api/private");fetch("https://analytics.example.test/collect")'
        : '<html><script src="/_next/static/app.js"></script><a href="/api/private">unapproved endpoint</a><form action="/login"></form></html>'
    );
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port,
      input = prepareProductionWebCampaign(origin + "/", "Owner synthetic Windows native fixture"),
      p = input.authorization.productionCampaign!;
    p.staticAssets = [{ origin, pathPrefix: "/_next/static/", extensions: [".js"] }];
    p.rateLimitPerSecond = 3;
    const digest = productionCampaignDigest(input);
    await expect(runProductionWebCampaign(input, "0".repeat(64), join(root, "rejected"))).rejects.toThrow(
      "REVIEW_DIGEST_MISMATCH"
    );
    expect(wire).toEqual([]);
    const result = await runProductionWebCampaign(input, digest, join(root, "native"));
    expect(result.status).toBe("COMPLETED");
    expect(wire.some((r) => r.url === "/_next/static/app.js")).toBe(true);
    expect(wire.every((r) => r.url === "/" || r.url === "/_next/static/app.js")).toBe(true);
    expect(
      result.assessment.routeFamilies.some((r) => r.pathTemplate === "/api/private" && r.executionAuthority === "NONE")
    ).toBe(true);
    expect(result.assessment.scopeExpandedAutomatically).toBe(false);
    expect(result.assessment.applicationSecureConclusion).toBe(false);
    expect(result.assessment.publicControls.every((c) => c.outcome === "EXPECTED_HTTP_CONTROL_OBSERVED")).toBe(true);
    writeFileSync(
      join(root, "NATIVE_CAMPAIGN_RECEIPT.json"),
      JSON.stringify(
        { wire, result, retainedReport: JSON.parse(readFileSync(join(result.root, "retention.json"), "utf8")) },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    retainOwnedTestDirectory(root);
  }
});
it("production authority denies unknown endpoints, query effects, third parties, writes and expiration", () => {
  const input = prepareProductionWebCampaign(
      "https://owned.example.test/",
      "Owner reviewed synthetic exact authorization"
    ),
    p = input.authorization.productionCampaign!;
  p.staticAssets = [{ origin: input.authorization.targetOrigin, pathPrefix: "/_next/static/", extensions: [".js"] }];
  let now = Date.now();
  const guard = new TargetAuthorizationGuard(targetAuthorizationSchema.parse(input.authorization), () => now);
  expect(guard.check("https://owned.example.test/", "GET")).toBeUndefined();
  expect(guard.check("https://owned.example.test/_next/static/app.js", "GET")).toBeUndefined();
  for (const [url, method] of [
    ["https://owned.example.test/api/private", "GET"],
    ["https://owned.example.test/?delete=true", "GET"],
    ["https://owned.example.test/_next/static/app.js?redirect=foreign", "GET"],
    ["https://foreign.example.test/", "GET"],
    ["https://owned.example.test/", "POST"],
    ["https://owned.example.test/logout", "GET"],
    ["https://owned.example.test/_next/static/app.js.map", "GET"]
  ])
    expect(guard.check(url!, method!)).toBeDefined();
  expect(guard.check("https://owned.example.test/", "GET", "body")).toBeDefined();
  now += p.maxDurationMs + 1;
  expect(guard.check("https://owned.example.test/", "GET")).toBeDefined();
  expect(Object.isFrozen(guard.plan.productionCampaign)).toBe(true);
});
it("refuses anonymous adoption of credentials or fake authenticated identity/effect declarations", () => {
  const input = prepareProductionWebCampaign("https://owned.example.test/", "Synthetic owner approval"),
    p = input.authorization.productionCampaign!;
  expect(productionCampaignSchema.safeParse({ ...p, authenticationPermitted: true }).success).toBe(false);
  expect(productionCampaignSchema.safeParse({ ...p, mutationPermitted: true }).success).toBe(false);
  expect(productionCampaignSchema.safeParse({ ...p, requests: [{ ...p.requests[0], method: "POST" }] }).success).toBe(
    false
  );
  expect(
    productionCampaignSchema.safeParse({
      ...p,
      effects: { sessionHousekeeping: "SESSION_LAST_USED_AT_UPDATE", approved: false }
    }).success
  ).toBe(false);
});
