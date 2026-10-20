import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { recoveryCenterFixture } from "../helpers/recovery-center-fixture.js";
const output = process.argv[2];
if (!output || process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB)
  throw Error("Explicit owned Windows browser fixture required");
mkdirSync(output);
const f = recoveryCenterFixture(),
  receipts: Record<string, unknown>[] = [];
let backend: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
  vite: Awaited<ReturnType<typeof createServer>> | undefined,
  browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined;
let status = "FAILED",
  browserVersion = "",
  failure: string | undefined;
const consoleErrors: string[] = [];
try {
  backend = await startDashboardServer({ dataDir: f.root, port: 0 });
  vite = await createServer({
    configFile: false,
    root: resolve("apps/dashboard-ui"),
    cacheDir: join(output, "vite-cache"),
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: 0,
      strictPort: false,
      proxy: { "/api": { target: backend.url, changeOrigin: false } }
    }
  });
  await vite.listen();
  const origin = vite.resolvedUrls!.local[0]!.replace(/\/$/, ""),
    profile = join(output, "owned-edge-profile");
  mkdirSync(profile);
  browser = await chromium.launchPersistentContext(profile, {
    executablePath: "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    headless: true,
    viewport: { width: 1440, height: 1000 },
    serviceWorkers: "block",
    acceptDownloads: false
  });
  browserVersion = browser.browser()!.version();
  await browser.route("**/*", (route) => {
    const u = new URL(route.request().url());
    return ["127.0.0.1", "localhost"].includes(u.hostname) ? route.continue() : route.abort();
  });
  const page = await browser.newPage();
  page.on("pageerror", (e) => consoleErrors.push(e.name));
  await page.goto(origin + "/" + new URL(backend.bootstrapUrl!).hash);
  await page.getByRole("button", { name: "Recovery & Uncertainty", exact: true }).click();
  await page.getByRole("heading", { name: "Recovery & Uncertainty", exact: true }).waitFor();
  await page.getByRole("heading", { name: "Worker custody needs review" }).waitFor();
  const custody = page.getByRole("article", { name: "CUSTODY " + f.resourceId });
  assert.equal(await custody.getByRole("button", { name: "Acknowledge review", exact: true }).isDisabled(), true);
  await custody.getByRole("checkbox").check();
  await custody.getByRole("button", { name: "Acknowledge review", exact: true }).click();
  await page.getByText("Review recorded. Uncertainty and safety blockers remain in force.").waitFor();
  assert.equal(
    (f.database.db.prepare("SELECT state FROM worker_resources").get() as { state: string }).state,
    "UNKNOWN_RETAINED"
  );
  await page.screenshot({ path: join(output, "recovery-center.png"), fullPage: true });
  receipts.push({ case: "NATIVE_BROWSER_REVIEW_PRESERVES_UNKNOWN", status: "PASS" });
  const comparison = page.getByRole("article", { name: "COMPARISON " + f.comparisonId });
  await comparison
    .getByRole("checkbox", { name: "I authorize a new comparison only. No scan or historical gate change." })
    .check();
  await comparison.getByRole("button", { name: "Create new comparison evidence" }).click();
  await page
    .getByText("New comparison attempt retained. Original evidence and historical assurance gates are unchanged.")
    .waitFor();
  assert.equal(
    (f.database.db.prepare("SELECT state FROM scan_comparisons WHERE id=?").get(f.comparisonId) as { state: string })
      .state,
    "FAILED"
  );
  assert.equal(
    (f.database.db.prepare("SELECT gate_status FROM continuous_assurance_runs").get() as { gate_status: string })
      .gate_status,
    "INCONCLUSIVE"
  );
  receipts.push({ case: "NATIVE_BROWSER_OFFLINE_COMPARISON_PRESERVES_HISTORY", status: "PASS" });
  await page.getByRole("button", { name: "Open worker diagnostics" }).click();
  await page.getByRole("heading", { name: "Worker Operations" }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Release dispatch", exact: true }).isDisabled(), true);
  await page.screenshot({ path: join(output, "custody-quarantine.png"), fullPage: true });
  receipts.push({ case: "NATIVE_BROWSER_RELEASE_DISABLED", status: "PASS" });
  assert.deepEqual(consoleErrors, []);
  status = "PASS";
  f.capture("NATIVE_BROWSER_SQLITE_RECEIPT");
} catch (e) {
  failure = e instanceof Error ? e.name + ": " + e.message.slice(0, 600) : "Unknown browser error";
} finally {
  await browser?.close();
  await vite?.close();
  await backend?.close();
  f.close();
  writeFileSync(
    join(output, "BROWSER_RECEIPT.json"),
    JSON.stringify(
      {
        status,
        browserVersion,
        platform: process.platform,
        nativeProcesses: true,
        sourceModeDevServer: true,
        releaseBuild: false,
        persistentProfileRetained: true,
        nonLoopbackPageRequestsAllowed: false,
        cases: receipts,
        consoleErrors,
        failure,
        fixtureRoot: f.root
      },
      null,
      2
    ),
    { flag: "wx" }
  );
}
if (status !== "PASS") throw Error("NATIVE_BROWSER_RECOVERY_ACCEPTANCE_FAILED");
