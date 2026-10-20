import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { cleanupAttemptFixture } from "../helpers/cleanup-attempt-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
const output = process.argv[2];
if (!output || process.platform !== "win32" || !process.env.ROUTECAIRN_WORKER_LAB)
  throw Error("Owned Windows browser lab required");
mkdirSync(output);
const f = await cleanupAttemptFixture(),
  cases: Record<string, unknown>[] = [];
let backend: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
  vite: Awaited<ReturnType<typeof createServer>> | undefined,
  browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined,
  status = "FAILED",
  failure: string | undefined,
  browserVersion = "";
const errors: string[] = [];
try {
  backend = await startDashboardServer({
    dataDir: f.root,
    port: 0,
    masterKey: Buffer.alloc(32, 6).toString("base64url")
  });
  vite = await createServer({
    configFile: false,
    root: resolve("apps/dashboard-ui"),
    cacheDir: join(output, "vite-cache"),
    plugins: [react()],
    server: { host: "127.0.0.1", port: 0, proxy: { "/api": { target: backend.url, changeOrigin: false } } }
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
  await browser.route("**/*", (route) =>
    ["127.0.0.1", "localhost"].includes(new URL(route.request().url()).hostname) ? route.continue() : route.abort()
  );
  const page = await browser.newPage();
  page.on("pageerror", (e) => errors.push(e.name));
  await page.goto(origin + "/" + new URL(backend.bootstrapUrl!).hash);
  await page.getByRole("button", { name: "Recovery & Uncertainty", exact: true }).click();
  const issue = page.getByRole("article", { name: "CLEANUP approval:" + f.input.approvalId });
  await issue.getByRole("button", { name: "Open authorized cleanup recovery" }).click();
  const panel = page.locator('section[aria-label="Bound controlled cleanup"]');
  await panel.getByRole("combobox").selectOption(f.input.credentialProfileId);
  assert.equal(await panel.getByRole("button", { name: "Request bound cleanup" }).isDisabled(), true);
  await panel.getByRole("checkbox").check();
  const response = page.waitForResponse(
    (r) => r.url().endsWith("/api/recovery-center/controlled-cleanup") && r.request().method() === "POST"
  );
  await panel.getByRole("button", { name: "Request bound cleanup" }).click();
  const accepted = await response;
  assert.equal(accepted.status(), 202);
  const body = (await accepted.json()) as { attemptId: string },
    submitted = accepted.request().postDataJSON() as Record<string, unknown>;
  assert.match(String(submitted.requestId), /^[a-f0-9-]{36}$/);
  const deadline = Date.now() + 25000;
  let observedPhase = "";
  while (Date.now() < deadline) {
    observedPhase = await page.evaluate(async (id) => {
      const r = await fetch("/api/recovery-center/attempts/" + id);
      return r.ok ? ((await r.json()) as { phase: string }).phase : "UNAVAILABLE";
    }, body.attemptId);
    if (observedPhase === "RESTORATION_VERIFIED") break;
    if (["FAILED", "UNKNOWN", "NOT_EXECUTED"].includes(observedPhase))
      throw Error("Native cleanup terminal phase: " + observedPhase);
    await new Promise<void>((r) => setTimeout(r, 200));
  }
  assert.equal(observedPhase, "RESTORATION_VERIFIED");
  assert.deepEqual(f.requests, ["GET /identity", "POST /rollback", "GET /state"]);
  cases.push({
    case: "BROWSER_EXPLICIT_BOUND_CLEANUP_TO_NATIVE_INDEPENDENT_PROOF",
    status: "PASS",
    attemptId: body.attemptId
  });
  await page.getByRole("button", { name: "Refresh evidence" }).click();
  const history = page.getByRole("article", { name: "RECOVERY attempt:" + body.attemptId });
  await history.getByRole("button", { name: "Inspect immutable attempt history" }).click();
  await history.getByText(/10\. RESTORATION_VERIFIED/).waitFor();
  assert.equal(await history.getByRole("button", { name: "Acknowledge review" }).count(), 0);
  await page.screenshot({ path: join(output, "verified-cleanup-attempt.png"), fullPage: true });
  cases.push({ case: "BROWSER_ORDERED_HISTORY_AND_CONSUMED_AUTHORITY", status: "PASS" });
  const repeated = (await page.evaluate(async (input) => {
    const moduleUrl = "/src/api.ts",
      api = await import(moduleUrl);
    return api.apiMutation("/api/recovery-center/controlled-cleanup", "POST", input);
  }, submitted)) as { alreadyRecorded: boolean; attemptId: string };
  assert.equal(repeated.alreadyRecorded, true);
  assert.equal(repeated.attemptId, body.attemptId);
  assert.equal(f.requests.length, 3);
  cases.push({ case: "BROWSER_LOST_ACKNOWLEDGEMENT_RETURNS_ORIGINAL_WITHOUT_REPLAY", status: "PASS" });
  assert.deepEqual(errors, []);
  f.capture("NATIVE_BROWSER_ATTEMPT_RECEIPT");
  status = "PASS";
} catch (e) {
  try {
    await browser
      ?.pages()
      .at(-1)
      ?.screenshot({ path: join(output, "failed-browser.png"), fullPage: true });
  } catch {
    /* Preserve the original browser failure. */
  }
  failure = e instanceof Error ? e.name + ": " + e.message.slice(0, 600) : "Unknown browser failure";
} finally {
  await browser?.close();
  await vite?.close();
  await backend?.close();
  await f.close();
  writeFileSync(
    join(output, "BROWSER_RECEIPT.json"),
    JSON.stringify(
      {
        status,
        browserVersion,
        platform: process.platform,
        cases,
        errors,
        failure,
        nativeWorkerExecuted: f.requests.length > 0,
        sourceMode: true,
        externalTargets: false,
        profileRetained: true,
        fixtureRoot: f.root
      },
      null,
      2
    ),
    { flag: "wx" }
  );
}
if (status !== "PASS") throw Error("BROWSER_CLEANUP_ATTEMPT_ACCEPTANCE_FAILED");
