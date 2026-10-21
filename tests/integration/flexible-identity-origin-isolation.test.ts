import { expect, it } from "vitest";
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it.each(["BEARER", "COOKIE", "API_KEY"] as const)(
  "native identity redirect cannot export %s credentials into a separately in-scope origin",
  async (mechanism) => {
    const received: Array<{ authorization: boolean; cookie: boolean; key: boolean }> = [];
    const other = createServer((q, r) => {
      received.push({
        authorization: !!q.headers.authorization,
        cookie: !!q.headers.cookie,
        key: !!q.headers["x-fixture-key"]
      });
      r.setHeader("content-type", "application/json");
      r.end('{"id":"actor0"}');
    });
    await new Promise<void>((r) => other.listen(0, "127.0.0.1", r));
    const a = other.address();
    if (!a || typeof a === "string") throw Error("fixture");
    const secondary = "http://127.0.0.1:" + a.port;
    const f = await flexibleFixture(1, { mechanism, identityRedirect: secondary + "/who" });
    try {
      const scope = JSON.parse(readFileSync(f.scopePath, "utf8"));
      scope.sameOriginOnly = false;
      writeFileSync(f.scopePath, JSON.stringify(scope));
      const auth = JSON.parse(readFileSync(f.authorizationPath, "utf8"));
      delete auth.productionCampaign;
      auth.mode = "INTERNAL_STAGING";
      writeFileSync(f.authorizationPath, JSON.stringify(auth));
      const r = await f.run();
      writeFileSync(
        f.root + "/IDENTITY_REDIRECT_RECEIPT.json",
        JSON.stringify(
          {
            mechanism,
            received,
            wire: f.wire,
            identity: r.report.identityVerification,
            scopeIsBroaderThanCredentialConsent: true
          },
          null,
          2
        ),
        { flag: "wx" }
      );
      expect(received).toEqual([]);
      expect(f.wire.some((w) => w.path === "/who")).toBe(true);
      expect(r.report.identityVerification.actors.actor0.verified).toBe(false);
    } finally {
      await f.close();
      other.closeAllConnections();
      await new Promise<void>((r) => other.close(() => r()));
    }
  }
);
