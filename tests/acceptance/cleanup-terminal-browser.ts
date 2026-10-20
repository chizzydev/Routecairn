import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { terminalProjectionFixture } from "../helpers/cleanup-terminal-projection-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
const output = process.argv[2];
if (!output || process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB)
  throw Error("Owned Windows browser lab required");
mkdirSync(output);
const cases: Record<string, unknown>[] = [];
let status = "FAILED",
  failure: string | undefined,
  browserVersion = "";
try {
  for (const family of ["CONTROLLED", "WORKFLOW"] as const) {
    const f = terminalProjectionFixture(family),
      directory = join(output, family.toLowerCase()),
      saved = process.env.ROUTECAIRN_MUTATION_DIR;
    mkdirSync(directory);
    process.env.ROUTECAIRN_MUTATION_DIR = join(f.root, "j");
    let backend: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
      vite: Awaited<ReturnType<typeof createServer>> | undefined,
      browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined;
    try {
      f.ledger.interrupt(f.attemptId);
      const history = f.ledger.history(f.attemptId);
      backend = await startDashboardServer({
        dataDir: f.root,
        port: 0,
        masterKey: Buffer.alloc(32, 6).toString("base64url")
      });
      assert.equal((f.status() as { status: string }).status, "CLEANUP_FAILED");
      assert.deepEqual(f.ledger.history(f.attemptId), history);
      vite = await createServer({
        configFile: false,
        root: resolve("apps/dashboard-ui"),
        cacheDir: join(directory, "vite-cache"),
        plugins: [react()],
        server: { host: "127.0.0.1", port: 0, proxy: { "/api": { target: backend.url, changeOrigin: false } } }
      });
      await vite.listen();
      const origin = vite.resolvedUrls!.local[0]!.replace(/\/$/, ""),
        profile = join(directory, "owned-edge-profile");
      mkdirSync(profile);
      browser = await chromium.launchPersistentContext(profile, {
        executablePath: "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
        headless: true,
        viewport: { width: 1440, height: 1000 },
        serviceWorkers: "block",
        acceptDownloads: false
      });
      browserVersion = browser.browser()!.version();
      await browser.route("**/*", (route) =>
        ["127.0.0.1", "localhost"].includes(new URL(route.request().url()).hostname) ? route.continue() : route.abort()
      );
      const page = await browser.newPage(),
        errors: string[] = [];
      page.on("pageerror", (e) => errors.push(e.name));
      await page.goto(origin + "/" + new URL(backend.bootstrapUrl!).hash);
      await page.getByRole("button", { name: "Recovery & Uncertainty", exact: true }).click();
      const article = page.getByRole("article", { name: "RECOVERY attempt:" + f.attemptId });
      await article.getByText("RECOVERY · UNKNOWN", { exact: true }).waitFor();
      await article.getByRole("button", { name: "Inspect immutable attempt history" }).click();
      await article.getByText("Current attempt: UNKNOWN", { exact: true }).waitFor();
      assert.equal(
        await article.getByRole("button", { name: /retry|replay|reset|clear|authorized cleanup/i }).count(),
        0
      );
      const api = (await page.evaluate(
        async (input) => {
          const response = await fetch(
            input.family === "CONTROLLED"
              ? "/api/controlled-mutations/approvals/" + input.approvalId
              : "/api/workflow-mutations/status"
          );
          return { status: response.status, body: await response.json() };
        },
        { family, approvalId: f.approvalId }
      )) as {
        status: number;
        body: {
          approval?: { status: string; recoveryErrorSummary?: string };
          jobs?: Array<{ id: string; status: string; safe_summary?: string }>;
        };
      };
      assert.equal(api.status, 200);
      if (family === "CONTROLLED") {
        assert.equal(api.body.approval?.status, "CLEANUP_FAILED");
        assert.equal(api.body.approval?.recoveryErrorSummary, "RECOVERY_OUTCOME_UNKNOWN");
      } else {
        const job = api.body.jobs?.find((j) => j.id === f.jobId);
        assert.equal(job?.status, "CLEANUP_FAILED");
        assert.match(job?.safe_summary ?? "", /UNKNOWN/);
      }
      await article.getByRole("checkbox").check();
      await article.getByRole("button", { name: "Acknowledge review", exact: true }).click();
      await page.getByText("Review recorded. Uncertainty and safety blockers remain in force.").waitFor();
      assert.deepEqual(f.ledger.history(f.attemptId), history);
      assert.equal((f.status() as { status: string }).status, "CLEANUP_FAILED");
      await page.screenshot({ path: join(directory, "unknown-after-projection-and-review.png"), fullPage: true });
      assert.deepEqual(errors, []);
      f.capture("BROWSER_PROJECTED_UNKNOWN_" + family);
      cases.push({
        case: "BROWSER_" + family + "_STARTUP_PROJECTION_API_AND_REVIEW_PRESERVE_UNKNOWN",
        status: "PASS",
        attemptId: f.attemptId,
        fixtureRoot: f.root,
        api
      });
    } finally {
      await browser?.close();
      await vite?.close();
      await backend?.close();
      f.close();
      if (saved === undefined) delete process.env.ROUTECAIRN_MUTATION_DIR;
      else process.env.ROUTECAIRN_MUTATION_DIR = saved;
    }
  }
  status = "PASS";
} catch (error) {
  failure = error instanceof Error ? error.message.slice(0, 600) : String(error);
} finally {
  writeFileSync(
    join(output, "BROWSER_RECEIPT.json"),
    JSON.stringify(
      {
        status,
        failure,
        browserVersion,
        platform: process.platform,
        cases,
        provenance: "SEEDED_OWNED_SQLITE_ACTUAL_WINDOWS_EDGE_HTTP_API_NO_TARGET_EXECUTION",
        sourceMode: true,
        releaseBuild: false,
        externalTargets: false
      },
      null,
      2
    ),
    { flag: "wx" }
  );
}
if (status !== "PASS") throw Error("TERMINAL_PROJECTION_BROWSER_FAILED:" + failure);
