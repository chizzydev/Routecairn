import { it as platformTest, expect } from "vitest";
const it = platformTest.skipIf(process.platform !== "win32");
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";
import { chromium } from "playwright";
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
it("real Edge onboarding to registry review, immutable preview, native worker and evidence coverage", async () => {
  const f = await flexibleDashboardFixture(1, true);
  let server: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
    browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  const receipts: unknown[] = [];
  try {
    await f.execution.shutdown();
    const ui = join(f.root, "owned-ui");
    mkdirSync(join(ui, "assets"), { recursive: true });
    await build({
      entryPoints: [join(process.cwd(), "apps/dashboard-ui/src/main.tsx")],
      outdir: join(ui, "assets"),
      entryNames: "app",
      bundle: true,
      format: "esm",
      platform: "browser",
      jsx: "automatic",
      logLevel: "silent"
    });
    writeFileSync(
      join(ui, "index.html"),
      '<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/assets/app.css"></head><body><div id="root"></div><script type="module" src="/assets/app.js"></script></body></html>',
      { flag: "wx" }
    );
    server = await startDashboardServer({
      dataDir: f.root,
      mode: "local",
      port: 0,
      uiDistDir: ui,
      masterKey: f.key.toString("base64url")
    });
    browser = await chromium.launch({
      channel: "msedge",
      headless: true,
      args: ["--disable-background-networking", "--disable-component-update", "--no-pings"]
    });
    const context = await browser.newContext();
    await context.route("**/*", (route) =>
      new URL(route.request().url()).origin === server!.url ? route.continue() : route.abort("blockedbyclient")
    );
    const page = await context.newPage();
    page.setDefaultTimeout(7000);
    page.on("pageerror", (e) => receipts.push({ pageError: e.message }));
    page.on("response", (r) => {
      if (r.url().includes("/api/") && r.status() >= 400)
        receipts.push({ url: new URL(r.url()).pathname, status: r.status() });
    });
    await page.goto(server.bootstrapUrl!);
    await page.getByRole("button", { name: "New Scan", exact: true }).click();
    receipts.push({ initialStudioText: await page.locator("body").innerText() });
    await page.getByRole("combobox", { name: /Saved target/ }).selectOption(f.targetId);
    await page.getByLabel(/I confirm I am authorized/).check();
    for (let i = 0; i < 3; i++) await page.getByRole("button", { name: "Next", exact: true }).click();
    await page.getByRole("heading", { name: "Configure the accounts you actually have" }).waitFor();
    await page.getByLabel("Exact reviewed read-only path", { exact: true }).fill("/private");
    await page.getByRole("button", { name: "Add account", exact: true }).click();
    await page.getByRole("combobox", { name: /Saved credential/ }).selectOption(f.actors[0]!.credentialProfileId);
    await page.getByLabel(/I approve the exact GET path/).check();
    await page.getByLabel(/I approve known authenticated-read/).check();
    const registryResponse = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/scans/actor-registry");
    await page.getByRole("button", { name: "Review available checks", exact: true }).click();
    const reviewed = await registryResponse;
    receipts.push({ registryStatus: reviewed.status(), body: await reviewed.json() });
    expect(reviewed.status()).toBe(200);
    await page.getByRole("table", { name: "Checks, missing evidence and additional opportunities" }).waitFor();
    await page.screenshot({ path: join(f.root, "EDGE_ACTOR_REVIEW.png"), fullPage: true });
    for (let i = 0; i < 5; i++) await page.getByRole("button", { name: "Next", exact: true }).click();
    const previewResponse = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/scans/plan-preview");
    await page.getByRole("button", { name: "Resolve Plan", exact: true }).click();
    const preview = await previewResponse;
    receipts.push({ previewStatus: preview.status(), body: await preview.json() });
    expect(preview.status()).toBe(200);
    await page.getByRole("button", { name: "Continue to Launch", exact: true }).click();
    const launchResponse = page.waitForResponse(
      (r) => new URL(r.url()).pathname === "/api/scans" && r.request().method() === "POST"
    );
    await page.getByRole("button", { name: "Confirm and Launch", exact: true }).click();
    const launch = await launchResponse,
      launched = (await launch.json()) as { scanId?: string; id?: string };
    receipts.push({ launchStatus: launch.status(), body: launched });
    expect(launch.status()).toBe(202);
    const scanId = launched.scanId ?? launched.id;
    expect(scanId).toBeTruthy();
    const end = Date.now() + 15000;
    let row: { status: string; error_summary: string | null } | undefined;
    while (Date.now() < end) {
      row = f.database.db.prepare("SELECT status,error_summary FROM scans WHERE id=?").get(scanId) as typeof row;
      if (row && ["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(row.status)) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    receipts.push({
      scanId,
      row,
      wire: f.wire,
      integrity: f.database.db.pragma("integrity_check"),
      foreignKeys: f.database.db.pragma("foreign_key_check")
    });
    expect(row?.status).toBe("COMPLETED");
    await page.getByRole("heading", { name: "What was assessed" }).waitFor();
    await page.screenshot({ path: join(f.root, "EDGE_CAPABILITY_EVIDENCE.png"), fullPage: true });
    expect(f.wire.some((w) => w.path === "/private" && w.actor === "actor0")).toBe(true);
    expect(f.wire.some((w) => w.path === "/who")).toBe(false);
    expect(await page.locator("body").innerText()).toContain("CREDENTIAL_SUPPLIED_IDENTITY_UNVERIFIED");
    for (const token of f.tokens) expect(JSON.stringify(receipts)).not.toContain(token);
    writeFileSync(join(f.root, "EDGE_NATIVE_JOURNEY_RECEIPT.json"), JSON.stringify(receipts, null, 2), { flag: "wx" });
  } catch (e) {
    writeFileSync(
      join(f.root, "EDGE_NATIVE_JOURNEY_FAILURE.json"),
      JSON.stringify({ receipts, error: e instanceof Error ? e.message : String(e) }, null, 2),
      { flag: "wx" }
    );
    throw e;
  } finally {
    await browser?.close();
    await server?.close();
    await f.close();
  }
});
