import { expect, it } from "vitest";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
import { exampleScope } from "../../src/config/defaults.js";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
it.each(["Authorization", "Cookie", "X-Application-Key", "PUBLIC_CONTROL"])(
  "broker never forwards target-bound %s across separately allowed origins",
  async (header) => {
    const root = createOwnedTestDirectory("r3-credential-redirect"),
      secret = "generated-" + randomUUID();
    const observed: Array<{ present: boolean; method: string }> = [],
      audits: unknown[] = [];
    const second = createServer((q, r) => {
      observed.push({ present: q.headers[header.toLowerCase()] === secret, method: q.method ?? "" });
      r.end("fixture");
    });
    await new Promise<void>((r) => second.listen(0, "127.0.0.1", r));
    const a = second.address();
    if (!a || typeof a === "string") throw Error("fixture");
    const secondary = "http://127.0.0.1:" + a.port;
    const first = createServer((_q, r) => r.writeHead(302, { location: secondary + "/resource" }).end());
    await new Promise<void>((r) => first.listen(0, "127.0.0.1", r));
    const b = first.address();
    if (!b || typeof b === "string") throw Error("fixture");
    const primary = "http://127.0.0.1:" + b.port;
    const broker = new RequestSafetyBroker(
      {
        userAgent: "RouteCairn/0.1",
        timeoutMs: 3000,
        bodyPreviewBytes: 1024,
        maxResponseBytes: 1024,
        rateLimitPerSecond: 20,
        concurrency: 1,
        maxRequests: 5,
        retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1, retryStatusCodes: [] },
        allowedPrivateOrigins: [primary, secondary],
        privateHeaderNames: [header],
        privateValues: [secret]
      },
      new ScopeMatcher(primary, {
        ...exampleScope,
        allowedDomains: ["127.0.0.1"],
        sameOriginOnly: false,
        disallowedPaths: [],
        allowedMethods: ["GET"]
      }),
      (e) => audits.push(e)
    );
    try {
      const response = await broker.send({
        url: primary + "/start",
        method: "GET",
        headers: header === "PUBLIC_CONTROL" ? {} : { [header]: secret },
        disableRetries: true
      });
      writeFileSync(
        join(root, "CREDENTIAL_REDIRECT_RECEIPT.json"),
        JSON.stringify({ header, observed, response, audits }, null, 2),
        { flag: "wx" }
      );
      expect(observed).toEqual(header === "PUBLIC_CONTROL" ? [{ present: false, method: "GET" }] : []);
      expect(response.error?.name).toBe(header === "PUBLIC_CONTROL" ? undefined : "OutOfScopeRedirect");
      expect(JSON.stringify(audits)).not.toContain(secret);
    } finally {
      await broker.close();
      first.closeAllConnections();
      second.closeAllConnections();
      await Promise.all([
        new Promise<void>((r) => first.close(() => r())),
        new Promise<void>((r) => second.close(() => r()))
      ]);
      retainOwnedTestDirectory(root);
    }
  }
);
