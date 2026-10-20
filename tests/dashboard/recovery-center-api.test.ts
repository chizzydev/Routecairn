import { describe, it, expect } from "vitest";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";

describe("operator recovery center HTTP integration", () => {
  it("exposes uncertainty inventory without authorizing a reset or execution", async () => {
    const root = createOwnedTestDirectory("recovery-center-api-");
    const handle = await startDashboardServer({ dataDir: root, port: 0 });
    try {
      expect((await fetch(handle.url + "/api/recovery-center")).status).toBe(401);
      const token = new URL(handle.bootstrapUrl!).hash.slice("#bootstrap=".length),
        auth = await fetch(handle.url + "/api/session/bootstrap", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token })
        });
      const cookie = auth.headers.get("set-cookie")!.split(";")[0]!;
      const result = await fetch(handle.url + "/api/recovery-center", { headers: { cookie } });
      expect(result.status).toBe(200);
      expect(result.headers.get("cache-control")).toBe("no-store");
      expect(
        (
          await fetch(handle.url + "/api/recovery-center/reviews", {
            method: "POST",
            headers: { cookie, "content-type": "application/json" },
            body: "{}"
          })
        ).status
      ).toBe(401);
      expect((await fetch(handle.url + "/api/recovery-center?kind=RESET", { headers: { cookie } })).status).toBe(400);
      const body = await result.json();
      expect(body).toMatchObject({ schemaVersion: 1, issues: [], automaticReplay: false });
    } finally {
      await handle.close();
      retainOwnedTestDirectory(root);
    }
  });
});
