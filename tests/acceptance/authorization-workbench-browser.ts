import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { authorizationWorkbenchFixture } from "../helpers/authorization-workbench-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
const output = process.argv[2];
if (!output || !process.env.ROUTECAIRN_WORKER_LAB) throw Error("Owned browser lab required");
mkdirSync(output);
const f = await authorizationWorkbenchFixture();
await f.execution.shutdown();
let backend: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
  vite: Awaited<ReturnType<typeof createServer>> | undefined,
  browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined,
  status = "FAILED",
  failure: string | undefined;
const cases: Record<string, unknown>[] = [];
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
  await browser.route("**/*", (r) =>
    ["127.0.0.1", "localhost"].includes(new URL(r.request().url()).hostname) ? r.continue() : r.abort()
  );
  const page = await browser.newPage(),
    errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(vite.resolvedUrls!.local[0]! + new URL(backend.bootstrapUrl!).hash);
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByLabel("Import authorization expectations").setInputFiles({
    name: "owned-application-expectations.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(f.input))
  });
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  const first = await page.getByRole("status").filter({ hasText: "READY_READ_ONLY" }).textContent();
  const firstRevision = first!.match(/[a-f0-9-]{36}/)![0];
  assert.equal(
    await page.getByRole("table", { name: "Role, tenant and object operation matrix" }).getByRole("row").count(),
    17
  );
  await page.screenshot({ path: join(output, "01-reviewed-matrix.png"), fullPage: true });
  const noCsrf = await page.evaluate(
    async ({ id, digest }) => {
      const r = await fetch("/api/authorization-workbench/" + id + "/execute", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ digest, confirmation: "I_AUTHORIZE_THE_EXACT_READ_ONLY_FIXTURE_CHECKS" })
      });
      return r.status;
    },
    {
      id: firstRevision,
      digest: (
        f.database.db.prepare("SELECT digest FROM authorization_workbench_revisions WHERE id=?").get(firstRevision) as {
          digest: string;
        }
      ).digest
    }
  );
  assert.equal(noCsrf, 401);
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByText(/^Execution outcome: FINDINGS/).waitFor({ timeout: 20000 });
  const before: any = await page.evaluate(
    async (id) => (await fetch("/api/authorization-workbench/" + id)).json(),
    firstRevision
  );
  assert.equal(before.result.findings.length, 2);
  assert.equal(
    before.result.checks.filter((c: any) => c.checkId.startsWith("secure-") && c.outcome !== "PASS").length,
    0
  );
  assert.equal(
    before.result.checks.filter((c: any) => c.checkId.startsWith("masked-") && c.outcome === "FAIL").length,
    0
  );
  await page.screenshot({ path: join(output, "02-executed-proof.png"), fullPage: true });
  cases.push({
    case: "NATIVE_MATRIX_FINDINGS_SECURE_AND_NEAR_MISS",
    status: "PASS",
    revisionId: firstRevision,
    scanId: before.result.scanId,
    result: before.result
  });
  await page.getByRole("button", { name: "Open scan and finding evidence" }).click();
  await page.getByRole("button", { name: /Review.*findings/i }).click();
  await page
    .getByRole("heading", { name: /Findings/i })
    .first()
    .waitFor();
  await page.getByText("API Authorization Issue", { exact: false }).first().waitFor();
  await page.screenshot({ path: join(output, "03-existing-findings-view.png"), fullPage: true });
  cases.push({ case: "EXISTING_FINDING_EVIDENCE_VIEW", status: "PASS" });
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByLabel("Retained workbench revision").selectOption(firstRevision);
  await page.getByText(/^Execution outcome: FINDINGS/).waitFor();
  f.setFixed();
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByText(/^Execution outcome: INCONCLUSIVE/).waitFor({ timeout: 20000 });
  const currentText = await page.getByRole("status").filter({ hasText: "READY_READ_ONLY" }).textContent(),
    currentRevision = currentText!.match(/[a-f0-9-]{36}/)![0];
  await page.getByLabel("Baseline revision").selectOption(firstRevision);
  await page.getByRole("button", { name: "Compare retained executions" }).click();
  await page.getByText(/Remediation comparison:/).waitFor();
  const after: any = await page.evaluate(
    async (id) => (await fetch("/api/authorization-workbench/" + id)).json(),
    currentRevision
  );
  assert.equal(after.result.findings.length, 0);
  assert.equal(after.result.verifiedPass, false);
  const comparisons = f.database.db
    .prepare("SELECT id,state,summary_json FROM scan_comparisons WHERE older_scan_id=? AND newer_scan_id=?")
    .all(before.result.scanId, after.result.scanId) as Array<{ id: string; state: string; summary_json: string }>;
  assert.equal(comparisons.length, 1);
  assert.equal(JSON.parse(comparisons[0]!.summary_json).resolved, 2);
  await page.screenshot({ path: join(output, "04-remediation-comparison.png"), fullPage: true });
  await page.getByRole("button", { name: "Open existing comparison evidence" }).click();
  await page.getByText("Finding comparison", { exact: true }).waitFor();
  await page.screenshot({ path: join(output, "05-existing-comparison-view.png"), fullPage: true });
  cases.push({
    case: "NATIVE_REMEDIATION_COMPARISON_HISTORY_PRESERVED",
    status: "PASS",
    revisionId: currentRevision,
    result: after.result,
    comparisons
  });
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByLabel("Retained workbench revision").selectOption(currentRevision);
  await page.getByText(/^Execution outcome: INCONCLUSIVE/).waitFor();
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  const count = f.wire.length;
  f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.input.targetId);
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByRole("alert").filter({ hasText: "WORKBENCH_BINDINGS_CHANGED" }).waitFor();
  assert.equal(f.wire.length, count);
  const other = new OrganizationService(f.database).create(
    { name: "Other owned review organization", slug: "other-review" },
    "local-operator"
  );
  const foreign = await page.evaluate(
    async ({ id, org }) =>
      (await fetch("/api/authorization-workbench/" + id, { headers: { "x-routecairn-organization-id": org } })).status,
    { id: firstRevision, org: other }
  );
  assert.equal(foreign, 404);
  await page.screenshot({ path: join(output, "06-stale-binding-refusal.png"), fullPage: true });
  assert.deepEqual(errors, []);
  cases.push({
    case: "HTTP_CSRF_ORGANIZATION_AND_STALE_BINDING_NO_WIRE",
    status: "PASS",
    noCsrf,
    foreign,
    requestsUnchanged: true
  });
  f.capture("EDGE_NATIVE_COMPARISON_ACCEPTANCE");
  status = "PASS";
} catch (e) {
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
        platform: process.platform,
        actualNativeWorkers: true,
        actualSQLite: true,
        actualEdge: true,
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
if (status !== "PASS") throw Error("WORKBENCH_BROWSER_FAILED:" + failure);
