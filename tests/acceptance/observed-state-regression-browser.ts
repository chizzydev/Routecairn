import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { observedStateRegressionFixture } from "../helpers/observed-state-regression-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
const output = process.argv[2],
  app = process.argv[3] === "membership" ? "membership" : "procurement";
if (!output || !process.env.ROUTECAIRN_WORKER_LAB) throw Error("OWNED_EDGE_LAB_REQUIRED");
mkdirSync(output);
const f = await observedStateRegressionFixture(app),
  p = await f.prepare(),
  healthy = await f.acquire();
await f.execution.shutdown();
f.ca.shutdown();
let backend: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
  vite: Awaited<ReturnType<typeof createServer>> | undefined,
  browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined,
  status = "FAILED",
  browserVersion: string | undefined,
  failure: string | undefined;
const cases: unknown[] = [],
  errors: string[] = [];
try {
  backend = await startDashboardServer({ dataDir: f.root, port: 0, masterKey: f.key.toString("base64url") });
  vite = await createServer({
    configFile: false,
    root: resolve("apps/dashboard-ui"),
    cacheDir: join(output, "vite-cache"),
    plugins: [react()],
    server: { host: "127.0.0.1", port: 0, proxy: { "/api": { target: backend.url, changeOrigin: false } } }
  });
  await vite.listen();
  const profile = join(output, "owned-edge-profile");
  mkdirSync(profile);
  browser = await chromium.launchPersistentContext(profile, {
    executablePath: "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    headless: true,
    viewport: { width: 1600, height: 1100 },
    serviceWorkers: "block",
    acceptDownloads: false
  });
  browserVersion = browser.browser()?.version();
  await browser.route("**/*", (r) =>
    ["127.0.0.1", "localhost"].includes(new URL(r.request().url()).hostname) ? r.continue() : r.abort()
  );
  const page = await browser.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(vite.resolvedUrls!.local[0]! + new URL(backend.bootstrapUrl!).hash);
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByText("Observed-State Regression & Continuous Assurance", { exact: true }).click();
  const panel = page.getByRole("region", { name: "Reviewed observed-state regression" });
  await panel.getByLabel("Reviewed transition matrix", { exact: true }).selectOption(p.decision.matrix!.revisionId);
  for (const r of f.workflow.routeIds)
    await panel.getByLabel("Revision marker for " + r, { exact: true }).fill("record.revision");
  const wire = f.wire.length;
  await panel.getByRole("button", { name: "Preview observed-state policy", exact: true }).click();
  await panel.getByLabel("Observed-state policy preview").waitFor();
  await panel.getByRole("button", { name: "Save immutable observation policy", exact: true }).click();
  await panel.getByText(/Selected policy: REVIEW_REQUIRED/).waitFor();
  await panel.getByLabel(/I trust the exact reviewed authority/).check();
  await panel.getByRole("button", { name: "Approve exact observation policy", exact: true }).click();
  await panel.getByText(/Selected policy: APPROVED/).waitFor();
  assert.equal(f.wire.length, wire);
  await page.screenshot({ path: join(output, "01-reviewed-policy.png"), fullPage: true });
  cases.push({ case: "GUI_REVIEW_IMMUTABLE_EXACT_STATE_POLICY", status: "PASS", noTargetTraffic: true });
  await panel
    .getByLabel("Observation authorization reference", { exact: true })
    .fill("fixture://owned-browser-observation-only");
  await panel.getByLabel("Observation authorization SHA-256", { exact: true }).fill("a".repeat(64));
  await panel.getByRole("button", { name: "Create and review observation-only assurance", exact: true }).click();
  await panel.getByLabel("Later native map revision UUID (blank uses newest)", { exact: true }).waitFor();
  await panel.getByRole("button", { name: "Evaluate retained observations", exact: true }).click();
  const history = panel.getByRole("region", { name: "Observation policy immutable history" });
  await history.getByRole("heading", { name: /MATCHED/ }).waitFor();
  await history.getByText(/State-change authorization: NOT_TESTED/).waitFor();
  assert.equal(f.wire.length, wire);
  await page.screenshot({ path: join(output, "02-native-healthy-observation-only.png"), fullPage: true });
  cases.push({
    case: "GUI_HEALTHY_NATIVE_COMPARISON_SCOPE_NOT_FULL_PASS",
    status: "PASS",
    source: healthy.revision.revisionId
  });
  const native = async () => {
    const revision = (await page.evaluate(async (input) => {
      const modulePath = "/src/api.ts",
        api = await import(modulePath);
      const r = await api.apiMutation("/api/authorization-workbench/mapping/acquisitions", "POST", input);
      const run = await api.apiMutation("/api/authorization-workbench/mapping/" + r.revisionId + "/execute", "POST", {
        digest: r.digest,
        confirmation: "I_AUTHORIZE_THE_EXACT_READ_ONLY_OBSERVATIONS"
      });
      return { ...r, scanId: run.scanId };
    }, f.mappingInput)) as { revisionId: string; scanId: string };
    const until = Date.now() + 20000;
    while (Date.now() < until) {
      const row = f.database.db.prepare("SELECT status FROM scans WHERE id=?").get(revision.scanId) as
        { status: string } | undefined;
      if (row?.status === "COMPLETED") return revision;
      if (row && ["FAILED", "CANCELLED", "INTERRUPTED"].includes(row.status))
        throw Error("NATIVE_BROWSER_" + row.status);
      await new Promise((r) => setTimeout(r, 100));
    }
    throw Error("ORIGINAL_NATIVE_20S_DEADLINE");
  };
  f.control.actorValues = {
    [app === "procurement" ? "account_a" : "account_b"]: {
      [app === "procurement" ? "business.phase" : "consent.state"]: app === "procurement" ? 3 : "REACTIVATED"
    }
  };
  await native();
  const driftWire = f.wire.length;
  await panel.getByRole("button", { name: "Evaluate retained observations", exact: true }).click();
  await history.getByRole("heading", { name: /DRIFT/ }).waitFor();
  assert.equal(f.wire.length, driftWire);
  await panel
    .getByRole("region", { name: "Observed-state attention" })
    .getByRole("button", { name: /Inspect observed-state alert/ })
    .first()
    .waitFor();
  await page.screenshot({ path: join(output, "03-actor-specific-regression.png"), fullPage: true });
  cases.push({ case: "GUI_REAL_LATER_NATIVE_SELECTIVE_DRIFT", status: "PASS", analysisWire: 0 });
  f.control.revision++;
  await native();
  await panel.getByRole("button", { name: "Evaluate retained observations", exact: true }).click();
  await history.getByRole("heading", { name: /INCONCLUSIVE/ }).waitFor();
  await page.screenshot({ path: join(output, "04-explicit-inconclusive-and-history.png"), fullPage: true });
  cases.push({ case: "GUI_CHANGED_REVISION_INCONCLUSIVE_HISTORY_RETAINS_DRIFT", status: "PASS" });
  for (const nav of ["Recovery & Uncertainty", "Findings", "Continuous Assurance"]) {
    const button = page.getByRole("button", { name: nav, exact: true });
    await button.click();
    if (nav === "Continuous Assurance")
      await page.getByText("Observed-State Regression & Continuous Assurance", { exact: true }).click();
    if (nav !== "Continuous Assurance")
      await page.getByText("Observed-state attention & evidence", { exact: true }).click();
    const attention = page.getByRole("region", { name: "Observed-state attention" });
    await attention
      .getByRole("button", { name: /Inspect observed-state alert/ })
      .first()
      .waitFor();
    await attention
      .getByRole("button", { name: /Inspect observed-state alert/ })
      .first()
      .click();
    await attention.getByRole("article", { name: "Immutable observed-state assessment" }).waitFor();
    await page.screenshot({
      path: join(output, "05-attention-" + nav.replaceAll(/\W/g, "-") + ".png"),
      fullPage: true
    });
    cases.push({ case: "GUI_ATTENTION_" + nav, status: "PASS" });
    if (nav === "Recovery & Uncertainty") {
      const linked = page.waitForResponse(
        (r) =>
          new URL(r.url()).pathname === "/api/scans/" + p.after.run.scanId + "/detail" && r.request().method() === "GET"
      );
      await attention.getByRole("button", { name: "Open baseline observation evidence", exact: true }).click();
      assert.equal((await linked).status(), 200);
      await page.getByRole("heading", { name: "Scan Detail", exact: true }).waitFor();
      await page.screenshot({ path: join(output, "06-baseline-source-navigation.png"), fullPage: true });
      cases.push({ case: "GUI_BASELINE_NATIVE_SOURCE_NAVIGATION", status: "PASS" });
      await page.getByRole("button", { name: "Recovery & Uncertainty", exact: true }).click();
      await page.getByText("Observed-state attention & evidence", { exact: true }).click();
      const a = page.getByRole("region", { name: "Observed-state attention" });
      await a
        .getByRole("button", { name: /Inspect observed-state alert/ })
        .first()
        .click();
      await a
        .getByRole("button", { name: "Open native scan comparison (policy assessed separately)", exact: true })
        .click();
      await page.getByRole("tablist", { name: "Comparison sections" }).waitFor();
      await page.screenshot({ path: join(output, "07-native-comparison-navigation.png"), fullPage: true });
      cases.push({ case: "GUI_NATIVE_COMPARISON_NAVIGATION_SEPARATE_SCOPE", status: "PASS" });
    }
  }
  assert.deepEqual(errors, []);
  assert.ok(f.wire.every((r) => r.method === "GET"));
  f.receipt("OBSERVED_STATE_EDGE_NATIVE_SQLITE", { cases });
  status = "PASS";
} catch (e) {
  const page = browser?.pages().at(-1);
  if (page) {
    await page.screenshot({ path: join(output, "FAILED_STEP.png"), fullPage: true }).catch(() => {});
    writeFileSync(join(output, "FAILED_PAGE.html"), await page.content(), { flag: "wx" });
  }
  failure = e instanceof Error ? e.message : String(e);
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
        failure,
        cases,
        errors,
        app,
        platform: process.platform,
        actualEdge: true,
        browserVersion,
        actualSQLite: true,
        actualNativeWorkers: true,
        preparedReviewedBaseline: true,
        baselineReviewInBrowser: cases.some(
          (c) => (c as { case: string }).case === "GUI_REVIEW_IMMUTABLE_EXACT_STATE_POLICY"
        ),
        laterAcquisitionViaAuthenticatedHttp: cases.some(
          (c) => (c as { case: string }).case === "GUI_REAL_LATER_NATIVE_SELECTIVE_DRIFT"
        ),
        targetMutationsByProduct: false,
        stateChangingAuthorization: "NOT_TESTED",
        externalTargets: false,
        releaseBuild: false
      },
      null,
      2
    ),
    { flag: "wx" }
  );
}
if (status !== "PASS") throw Error("OBSERVED_STATE_BROWSER_FAILED:" + failure);
