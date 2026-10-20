import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { heldOutApplicationFixture } from "../helpers/heldout-application-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
const output = process.argv[2],
  seedName = "helpdesk" as const;
if (!output || !process.env.ROUTECAIRN_WORKER_LAB) throw Error("OWNED_EDGE_LAB_REQUIRED");
mkdirSync(output);
const start = Date.now(),
  f = await heldOutApplicationFixture(seedName, false);
await f.execution.shutdown();
let backend: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
  vite: Awaited<ReturnType<typeof createServer>> | undefined,
  browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined,
  status = "FAILED",
  failure: string | undefined,
  browserVersion: string | undefined,
  actions = 0;
const cases: { case: string; status: string; detail?: unknown }[] = [],
  errors: string[] = [],
  apiRequests: { method: string; path: string }[] = [];
const act = async (fn: () => Promise<unknown>) => {
  await fn();
  actions++;
};
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
  mkdirSync(join(output, "owned-edge-profile"));
  browser = await chromium.launchPersistentContext(join(output, "owned-edge-profile"), {
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
  page.on("request", (r) => {
    if (new URL(r.url()).pathname.startsWith("/api/"))
      apiRequests.push({ method: r.method(), path: new URL(r.url()).pathname });
  });
  await page.goto(vite.resolvedUrls!.local[0]! + new URL(backend.bootstrapUrl!).hash);
  await act(() => page.getByRole("button", { name: "Application Authorization", exact: true }).click());
  await act(() => page.getByRole("button", { name: "Start guided application mapping", exact: true }).click());
  const initialForm = page.getByRole("region", { name: "Guided authenticated application mapping" });
  await act(() => initialForm.getByText("Set up an owned local application and actors", { exact: true }).click());
  const setup = page.getByRole("region", { name: "Application onboarding" }),
    initialWire = f.wire.length;
  assert.equal((f.database.db.prepare("SELECT count(*) n FROM targets").get() as { n: number }).n, 0);
  await act(() => setup.getByLabel("Application name", { exact: true }).fill("Owned Helpdesk GUI onboarding"));
  await act(() => setup.getByLabel("Owned application origin", { exact: true }).fill(f.origin));
  await act(() =>
    setup
      .getByLabel("Owner authorization explanation", { exact: true })
      .fill("I own this disposable Helpdesk and authorize separately approved read-only GET observations.")
  );
  await act(() => setup.getByLabel("Initial permitted GET path", { exact: true }).fill(f.prefix + "catalog/start"));
  await act(() => setup.getByLabel("Evidence fields", { exact: true }).check());
  await act(() => setup.getByLabel("Onboarding objectField", { exact: true }).fill(f.identityPath));
  await act(() => setup.getByLabel("Onboarding objectTenantField", { exact: true }).fill(f.tenantPath));
  await act(() => setup.getByLabel("Test actors", { exact: true }).check());
  await setup.getByLabel("Test actors", { exact: true }).focus();
  await setup.getByLabel("Test actors", { exact: true }).press("ArrowRight");
  assert.equal(await setup.getByLabel("Evidence fields", { exact: true }).isChecked(), true);
  await setup.getByLabel("Evidence fields", { exact: true }).press("ArrowLeft");
  assert.equal(await setup.getByLabel("Test actors", { exact: true }).isChecked(), true);
  cases.push({ case: "GUI_NATIVE_KEYBOARD_STEP_NAVIGATION", status: "PASS" });
  for (const [slot, a] of Object.entries(f.app.actors))
    for (const [field, value] of Object.entries({
      ...a,
      authorizationHeader: "Bearer heldout-helpdesk-" + slot,
      expiresAt: "2099-01-01T00:00:00Z"
    }))
      await act(() => setup.getByLabel(slot + " " + field, { exact: true }).fill(value));
  await act(() => setup.getByLabel("Review", { exact: true }).check());
  await page.screenshot({ path: join(output, "00-guided-review-no-secrets.png"), fullPage: true });
  let release!: () => void, committed!: () => void;
  const delayed = new Promise<void>((r) => {
      release = r;
    }),
    serverCommitted = new Promise<void>((r) => {
      committed = r;
    });
  await page.route(
    "**/api/authorization-workbench/mapping/onboarding",
    async (route) => {
      const response = await route.fetch();
      committed();
      await delayed;
      await route.fulfill({ response });
    },
    { times: 1 }
  );
  await act(() => setup.getByLabel(/I own this local application/).check());
  await act(() => setup.getByRole("button", { name: "Save declarations without sending requests" }).click());
  await serverCommitted;
  await act(() => setup.getByLabel("Scope", { exact: true }).check());
  await act(() => setup.getByLabel("Application name", { exact: true }).fill("Edited draft after committed request"));
  release();
  await setup.getByRole("alert").filter({ hasText: "may have saved" }).waitFor();
  assert.equal(await setup.getByLabel("primary authorizationHeader", { exact: true }).inputValue(), "");
  assert.equal(f.wire.length, initialWire);
  await page.screenshot({ path: join(output, "00-stale-committed-response-not-selected.png"), fullPage: true });
  cases.push({ case: "GUI_REAL_COMMITTED_STALE_RESPONSE_NOT_SELECTED_NO_TARGET_IO", status: "PASS" });
  await act(() => setup.getByLabel("Test actors", { exact: true }).check());
  await setup.getByLabel("Test actors", { exact: true }).focus();
  await setup.getByLabel("Test actors", { exact: true }).press("ArrowRight");
  assert.equal(await setup.getByLabel("Evidence fields", { exact: true }).isChecked(), true);
  await setup.getByLabel("Evidence fields", { exact: true }).press("ArrowLeft");
  assert.equal(await setup.getByLabel("Test actors", { exact: true }).isChecked(), true);
  cases.push({ case: "GUI_NATIVE_KEYBOARD_AFTER_UNCERTAIN_COMMIT", status: "PASS" });
  for (const slot of Object.keys(f.app.actors))
    await setup.getByLabel(slot + " authorizationHeader", { exact: true }).fill("Bearer heldout-helpdesk-" + slot);
  await act(() => setup.getByLabel("Review", { exact: true }).check());
  await page.route(
    "**/api/authorization-workbench/mapping/onboarding",
    async (route) => {
      await route.fetch();
      await route.abort("failed");
    },
    { times: 1 }
  );
  await act(() => setup.getByLabel(/I own this local application/).check());
  await act(() => setup.getByRole("button", { name: "Save declarations without sending requests" }).click());
  await setup.getByRole("alert").filter({ hasText: "could not be confirmed" }).waitFor();
  assert.equal((f.database.db.prepare("SELECT count(*) n FROM targets").get() as { n: number }).n, 2);
  assert.equal(await initialForm.getByLabel("Owned loopback target", { exact: true }).inputValue(), "");
  assert.equal(await setup.getByLabel("primary authorizationHeader", { exact: true }).inputValue(), "");
  assert.equal(f.wire.length, initialWire);
  await page.screenshot({ path: join(output, "00-real-lost-save-response-uncertain.png"), fullPage: true });
  cases.push({ case: "GUI_REAL_COMMITTED_LOST_RESPONSE_UNCERTAIN_NO_RETRY_OR_SCAN", status: "PASS" });
  await act(() => setup.getByLabel("Test actors", { exact: true }).check());
  for (const slot of Object.keys(f.app.actors))
    await setup.getByLabel(slot + " authorizationHeader", { exact: true }).fill("Bearer heldout-helpdesk-" + slot);
  await act(() => setup.getByLabel("Review", { exact: true }).check());
  await act(() => setup.getByLabel(/I own this local application/).check());
  await act(() => setup.getByRole("button", { name: "Save declarations without sending requests" }).click());
  await setup.getByText(/Application declarations saved/).waitFor();
  assert.equal(f.wire.length, initialWire);
  assert.equal((f.database.db.prepare("SELECT count(*) n FROM targets").get() as { n: number }).n, 3);
  assert.equal(await setup.getByLabel("primary authorizationHeader", { exact: true }).inputValue(), "");
  await page.screenshot({ path: join(output, "00-onboarding-no-target-io.png"), fullPage: true });
  cases.push({ case: "GUI_OWNER_ONBOARDING_ENCRYPTED_ACTORS_ZERO_TARGET_IO", status: "PASS" });
  await act(() =>
    initialForm.getByLabel("I confirm these disposable actor, role and tenant bindings.", { exact: true }).check()
  );
  await act(() =>
    initialForm
      .getByLabel("I confirm the exact listed GET handlers are authorized and non-mutating.", { exact: true })
      .check()
  );
  await act(() => initialForm.getByRole("button", { name: "Review observation requests", exact: true }).click());
  await initialForm.getByText("Observation status: REVIEW_REQUIRED", { exact: true }).waitFor();
  assert.equal(f.wire.length, initialWire);
  await act(() =>
    initialForm.getByLabel("I approve only these exact bounded native observation requests.", { exact: true }).check()
  );
  await act(() => initialForm.getByRole("button", { name: "Authorize native observations", exact: true }).click());
  await initialForm.getByText("Observation status: COMPLETED", { exact: true }).waitFor({ timeout: 20000 });
  cases.push({ case: "GUI_ONBOARDED_ACTORS_VERIFIED_BY_SEPARATE_NATIVE_WORKER", status: "PASS" });
  const panel = page.getByRole("region", { name: "Bounded application discovery" }),
    wire = f.wire.length;
  await act(() => panel.getByLabel("Approved discovery path prefixes (one per line)").fill("https://outside.invalid/"));
  await act(() => panel.getByLabel(/I reviewed this local scope/).check());
  await act(() => panel.getByRole("button", { name: "Review discovery suggestions" }).click());
  await panel.getByRole("alert").waitFor();
  assert.equal(f.wire.length, wire);
  cases.push({ case: "GUI_INVALID_SCOPE_NO_TARGET_TRAFFIC", status: "PASS" });
  await act(() => panel.getByLabel("Approved discovery path prefixes (one per line)").fill(f.prefix));
  await act(() => panel.getByLabel(/I reviewed this local scope/).check());
  await act(() => panel.getByRole("button", { name: "Review discovery suggestions" }).click());
  await panel.getByText(/7 scoped suggestions/).waitFor();
  assert.equal(f.wire.length, wire);
  await act(() => panel.getByText("Exclusions and missing controls").click());
  await panel.getByText(/ORIGIN_MISMATCH/).waitFor();
  await page.screenshot({ path: join(output, "01-native-scoped-discovery.png"), fullPage: true });
  cases.push({ case: "GUI_NATIVE_PROVENANCE_SCOPE_EXCLUSIONS_NO_AUTO_FOLLOW", status: "PASS" });
  await act(() => panel.getByLabel("Discovered object identity field").fill(f.identityPath));
  await act(() => panel.getByLabel("Discovered tenant field (optional)").fill(f.tenantPath));
  for (const c of f.cases) await act(() => panel.getByLabel("Select discovered " + c.path, { exact: true }).check());
  await act(() => panel.getByRole("button", { name: "Use selected routes in mapping review" }).click());
  const form = page.getByRole("region", { name: "Guided authenticated application mapping" });
  await form.getByText(/Native-discovered selection remains bound/).waitFor();
  assert.equal(f.wire.length, wire);
  const count = await form.getByLabel(/Route \d+ exact URL/).count();
  assert.equal(count, 6);
  let privateRoute = "";
  for (let i = 1; i <= count; i++) {
    const url = await form.getByLabel("Route " + i + " exact URL", { exact: true }).inputValue();
    if (url === f.origin + f.cases.find((c) => c.id === "restricted")!.path)
      privateRoute = await form.getByLabel("Route " + i + " label", { exact: true }).inputValue();
  }
  await act(() =>
    form.getByLabel("I confirm these disposable actor, role and tenant bindings.", { exact: true }).check()
  );
  await act(() =>
    form.getByLabel("I confirm the exact listed GET handlers are authorized and non-mutating.", { exact: true }).check()
  );
  await act(() => form.getByRole("button", { name: "Review observation requests", exact: true }).click());
  await form.getByText("Observation status: REVIEW_REQUIRED", { exact: true }).waitFor();
  assert.equal(f.wire.length, wire);
  await form.getByText(/Maximum 28 shared requests/).waitFor();
  await page.screenshot({ path: join(output, "02-explicit-budgeted-get-review.png"), fullPage: true });
  cases.push({ case: "GUI_SELECTION_NO_JSON_EXACT_BUDGET_AND_APPROVAL", status: "PASS" });
  await act(() =>
    form.getByLabel("I approve only these exact bounded native observation requests.", { exact: true }).check()
  );
  await act(() => form.getByRole("button", { name: "Authorize native observations", exact: true }).click());
  await form.getByText("Observation status: COMPLETED", { exact: true }).waitFor({ timeout: 20000 });
  assert.equal(f.wire.length, wire + 28);
  await page.screenshot({ path: join(output, "03-discovered-native-actor-map.png"), fullPage: true });
  cases.push({ case: "GUI_REAL_WORKER_DISCOVERED_ROUTE_OBSERVATION", status: "PASS" });
  await act(() => form.getByText("Evidence-grounded security hypotheses", { exact: true }).click());
  await act(() => form.getByRole("button", { name: "Generate grounded hypotheses", exact: true }).click());
  await form.getByRole("table", { name: "Grounded hypothesis candidates" }).waitFor();
  assert.equal(
    await form
      .getByRole("table", { name: "Grounded hypothesis candidates" })
      .getByText("ABSTAIN", { exact: false })
      .count(),
    4
  );
  await page.screenshot({ path: join(output, "04-grounded-questions-and-abstentions.png"), fullPage: true });
  cases.push({ case: "GUI_GROUNDED_REASONING_COUNTEREXAMPLES_AND_ABSTENTION", status: "PASS" });
  await act(() => form.getByRole("button", { name: "Inspect hypothesis " + privateRoute, exact: true }).click());
  const hypothesis = page.getByRole("region", { name: "Hypothesis evidence review" });
  await act(() =>
    hypothesis
      .getByLabel("Expected hypothesis object marker", { exact: true })
      .fill(f.cases.find((c) => c.id === "restricted")!.ref)
  );
  await act(() => hypothesis.getByLabel("Expected hypothesis tenant marker", { exact: true }).fill("north"));
  await act(() =>
    hypothesis
      .getByLabel("Hypothesis policy rationale", { exact: true })
      .fill("Owned Helpdesk private ticket belongs only to its manager in north tenant.")
  );
  for (const actor of ["account-a", "account-b", "anonymous"])
    await act(() => hypothesis.getByLabel("Hypothesis policy " + actor, { exact: true }).selectOption("DENY"));
  await act(() => hypothesis.getByLabel(/I explicitly confirm ownership/).check());
  await act(() => hypothesis.getByLabel(/I declare the expected policy/).check());
  const beforeProof = f.wire.length;
  await act(() =>
    hypothesis.getByRole("button", { name: "Record policy and review bounded matrix", exact: true }).click()
  );
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  assert.equal(f.wire.length, beforeProof);
  cases.push({ case: "GUI_POLICY_REVIEW_CREATES_MATRIX_WITHOUT_TRANSMISSION", status: "PASS" });
  await act(() => page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check());
  await act(() => page.getByRole("button", { name: "Authorize and run selected matrix", exact: true }).click());
  await page.getByText(/^Execution outcome: FINDINGS/).waitFor({ timeout: 20000 });
  await page.screenshot({ path: join(output, "05-native-reviewed-findings.png"), fullPage: true });
  cases.push({ case: "GUI_SEPARATE_NATIVE_PROOF_FINDINGS", status: "PASS" });
  const initialStatus = await page.getByRole("status").filter({ hasText: "READY_READ_ONLY" }).textContent(),
    baselineId = initialStatus!.match(/[a-f0-9-]{36}/)![0];
  f.setFixed();
  const revisedResponse = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/authorization-workbench/revisions" && r.request().method() === "POST"
  );
  await act(() => page.getByRole("button", { name: "Create versioned matrix", exact: true }).click());
  const revised = (await (await revisedResponse).json()) as { revisionId: string };
  await page.getByText(new RegExp("READY_READ_ONLY · revision " + revised.revisionId)).waitFor();
  await act(() => page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check());
  await act(() => page.getByRole("button", { name: "Authorize and run selected matrix", exact: true }).click());
  await page.getByText(/^Execution outcome: PASS/).waitFor({ timeout: 20000 });
  await act(() => page.getByLabel("Baseline revision", { exact: true }).selectOption(baselineId));
  await act(() => page.getByRole("button", { name: "Compare retained executions", exact: true }).click());
  await page.getByText(/resolved 2/).waitFor();
  await page.screenshot({ path: join(output, "06-native-remediation-comparison.png"), fullPage: true });
  cases.push({ case: "GUI_REAL_REMEDIATION_COMPARISON_NO_HISTORY_REWRITE", status: "PASS" });
  assert.deepEqual(errors, []);
  assert.ok(f.wire.every((w) => w.method === "GET"));
  status = "PASS";
  f.capture("DISCOVERY_EDGE_NATIVE_SQLITE", { cases, actions, apiRequests });
} catch (e) {
  failure = e instanceof Error ? e.message : String(e);
  const page = browser?.pages().at(-1);
  if (page) {
    await page.screenshot({ path: join(output, "FAILED_STEP.png"), fullPage: true }).catch(() => {});
    writeFileSync(join(output, "FAILED_PAGE.html"), await page.content(), { flag: "wx" });
  }
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
        actions,
        apiRequests,
        elapsedMs: Date.now() - start,
        actualEdge: true,
        browserVersion,
        platform: process.platform,
        actualNativeWindowsWorkers: true,
        actualSQLite: true,
        preparedSeedOnly: false,
        targetAndCredentialsCreatedThroughGUI: true,
        routeSelectionApprovalProofViaGUI: true,
        noHandEditedJSON: true,
        independentOwnerAcceptance: false,
        externalTargets: false,
        releaseBuild: false
      },
      null,
      2
    ),
    { flag: "wx" }
  );
}
if (status !== "PASS") throw Error("DISCOVERY_BROWSER_FAILED:" + failure);
