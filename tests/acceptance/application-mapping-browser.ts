import { z } from "zod";
import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import assert from "node:assert/strict";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
const resultEvidence = z
  .object({
    result: z
      .object({
        scanId: z.string().uuid(),
        findings: z.array(z.unknown()),
        checks: z.array(z.object({ checkId: z.string(), outcome: z.string() }).passthrough()),
        verifiedPass: z.boolean()
      })
      .passthrough()
  })
  .passthrough();
const observedEvidence = z
  .object({
    observationIsPolicyOrFinding: z.literal(false),
    verifiedApplicationPass: z.literal(false),
    observations: z.array(
      z.object({ cells: z.array(z.object({ observedMarkers: z.array(z.unknown()) }).passthrough()) }).passthrough()
    )
  })
  .passthrough();
const output = process.argv[2];
if (!output || !process.env.ROUTECAIRN_WORKER_LAB) throw Error("Owned Windows Edge lab required");
mkdirSync(output);
const f = await applicationMappingFixture();
await f.execution.shutdown();
assert.equal(f.wire.length, 0);
assert.equal(existsSync(join(f.root, "EXPECTATIONS.json")), false);
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
  await page.getByRole("button", { name: "Start guided application mapping" }).click();
  await page.getByLabel("Owned loopback target").selectOption(f.mappingInput.targetId);
  for (const slot of ["primary", "account_a", "account_b"] as const)
    await page.getByLabel(slot + " saved credential").selectOption(f.mappingInput.credentials[slot]);
  await page.getByRole("checkbox", { name: "I confirm these disposable actor, role and tenant bindings." }).check();
  for (const [rIndex, r] of f.mappingInput.routes.entries()) {
    if (rIndex) await page.getByRole("button", { name: "Add permitted route" }).click();
    const n = rIndex + 1;
    await page.getByLabel("Route " + n + " label", { exact: true }).fill(r.id);
    await page.getByLabel("Route " + n + " kind", { exact: true }).selectOption(r.kind);
    await page.getByLabel("Route " + n + " exact URL", { exact: true }).fill(r.url);
    await page.getByLabel("Route " + n + " template", { exact: true }).fill(r.pathTemplate);
  }
  await page
    .getByRole("checkbox", { name: "I confirm the exact listed GET handlers are authorized and non-mutating." })
    .check();
  await page.getByRole("button", { name: "Review observation requests" }).click();
  await page.getByText("Observation status: REVIEW_REQUIRED", { exact: true }).waitFor();
  assert.equal(f.wire.length, 0);
  assert.equal(
    await page.getByRole("table", { name: "Exact observation request preview" }).getByRole("row").count(),
    21
  );
  const acquisition = f.database.db.prepare("SELECT id,digest FROM application_mapping_revisions").get() as {
    id: string;
    digest: string;
  };
  const noCsrf = await page.evaluate(
    async (a) =>
      (
        await fetch("/api/authorization-workbench/mapping/" + a.id + "/execute", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ digest: a.digest, confirmation: "I_AUTHORIZE_THE_EXACT_READ_ONLY_OBSERVATIONS" })
        })
      ).status,
    acquisition
  );
  assert.equal(noCsrf, 401);
  assert.equal(f.wire.length, 0);
  await page.screenshot({ path: join(output, "01-guided-exact-observation-preview.png"), fullPage: true });
  await page.getByRole("checkbox", { name: "I approve only these exact bounded native observation requests." }).check();
  await page.getByRole("button", { name: "Authorize native observations" }).click();
  await page.getByText("Observation status: COMPLETED", { exact: true }).waitFor({ timeout: 20000 });
  assert.equal(f.wire.length, 20);
  assert.equal(await page.getByRole("table", { name: "Observed application map" }).getByRole("row").count(), 17);
  const observed = observedEvidence.parse(
    await page.evaluate(
      async (id) => (await fetch("/api/authorization-workbench/mapping/" + id)).json(),
      acquisition.id
    )
  );
  assert.equal(observed.observationIsPolicyOrFinding, false);
  assert.equal(observed.verifiedApplicationPass, false);
  assert.equal(observed.observations[0]!.cells[0]!.observedMarkers.length, 2);
  await page.screenshot({ path: join(output, "02-native-map-no-json-onboarding.png"), fullPage: true });
  cases.push({ case: "GUIDED_NATIVE_ACQUISITION_NO_PREPARED_SCAN_OR_JSON", status: "PASS", noCsrf, observed });
  for (const p of f.policy.expectations) {
    await page.getByLabel(p.routeId + " expected identity", { exact: true }).fill(String(p.identity!.expectedValue));
    await page.getByLabel(p.routeId + " expected tenant", { exact: true }).fill(String(p.tenant!.expectedValue));
    for (const [actor, decision] of Object.entries(p.decisions))
      await page.getByLabel(p.routeId + " policy " + actor, { exact: true }).selectOption(decision);
  }
  await page
    .getByRole("checkbox", {
      name: "I confirm these are declared policy expectations, not discovered authorization truth."
    })
    .check();
  await page.getByRole("button", { name: "Build reviewed authorization matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  const firstText = await page.getByRole("status").filter({ hasText: "READY_READ_ONLY" }).textContent(),
    firstId = firstText!.match(/[a-f0-9-]{36}/)![0];
  await page.screenshot({ path: join(output, "03-guided-native-proof-matrix.png"), fullPage: true });
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByText(/^Execution outcome: FINDINGS/).waitFor({ timeout: 20000 });
  const before = resultEvidence.parse(
    await page.evaluate(async (id) => (await fetch("/api/authorization-workbench/" + id)).json(), firstId)
  );
  assert.equal(before.result.findings.length, 2);
  assert.equal(before.result.checks.filter((c) => c.checkId.startsWith("secure-") && c.outcome !== "PASS").length, 0);
  assert.equal(before.result.checks.filter((c) => c.checkId.startsWith("masked-") && c.outcome === "FAIL").length, 0);
  cases.push({
    case: "GUIDED_TWO_TRUE_FINDINGS_SECURE_NEAR_MISS_AND_ACTOR_ISOLATION",
    status: "PASS",
    result: before.result
  });
  await page.getByRole("button", { name: "Open scan and finding evidence" }).click();
  await page.getByRole("button", { name: /Review.*findings/i }).click();
  await page
    .getByRole("heading", { name: /Findings/i })
    .first()
    .waitFor();
  await page.getByText("API Authorization Issue", { exact: false }).first().waitFor();
  await page.screenshot({ path: join(output, "04-existing-findings-evidence.png"), fullPage: true });
  cases.push({ case: "EXISTING_FINDINGS_VIEW_FROM_GUIDED_EXECUTION", status: "PASS" });
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByLabel("Retained workbench revision").selectOption(firstId);
  await page.getByText(/^Execution outcome: FINDINGS/).waitFor();
  f.setFixed();
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  const text = await page.getByRole("status").filter({ hasText: "READY_READ_ONLY" }).textContent(),
    afterId = text!.match(/[a-f0-9-]{36}/)![0];
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByText(/^Execution outcome: INCONCLUSIVE/).waitFor({ timeout: 20000 });
  await page.getByLabel("Baseline revision").selectOption(firstId);
  await page.getByRole("button", { name: "Compare retained executions" }).click();
  await page.getByText(/Remediation comparison:/).waitFor();
  const after = resultEvidence.parse(
    await page.evaluate(async (id) => (await fetch("/api/authorization-workbench/" + id)).json(), afterId)
  );
  assert.equal(after.result.findings.length, 0);
  assert.equal(after.result.verifiedPass, false);
  const comparison = f.database.db
    .prepare("SELECT id,state,summary_json FROM scan_comparisons WHERE older_scan_id=? AND newer_scan_id=?")
    .get(before.result.scanId, after.result.scanId) as { id: string; state: string; summary_json: string };
  assert.equal(JSON.parse(comparison.summary_json).resolved, 2);
  assert.equal(f.wire.length, 60);
  await page.screenshot({ path: join(output, "05-guided-remediation-retained-comparison.png"), fullPage: true });
  await page.getByRole("button", { name: "Open existing comparison evidence" }).click();
  await page.getByText("Finding comparison", { exact: true }).waitFor();
  await page.screenshot({ path: join(output, "06-existing-comparison-view.png"), fullPage: true });
  cases.push({
    case: "GUIDED_REMEDIATION_REAL_COMPARISON_TWO_RESOLVED_HONEST_UNCERTAINTY",
    status: "PASS",
    after: after.result,
    comparison
  });
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByRole("button", { name: "Start guided application mapping" }).click();
  await page.getByLabel("Retained application map").selectOption(acquisition.id);
  await page.getByText("Observation status: COMPLETED", { exact: true }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Authorize native observations" }).isDisabled(), true);
  const foreignOrg = new OrganizationService(f.database).create(
      { name: "Other owned mapping org", slug: "other-mapping" },
      "local-operator"
    ),
    foreign = await page.evaluate(
      async ({ id, org }) =>
        (
          await fetch("/api/authorization-workbench/mapping/" + id, {
            headers: { "x-routecairn-organization-id": org }
          })
        ).status,
      { id: acquisition.id, org: foreignOrg }
    );
  assert.equal(foreign, 404);
  await page.getByLabel("Retained workbench revision").selectOption(afterId);
  await page.getByText(/^Execution outcome: INCONCLUSIVE/).waitFor();
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  const count = f.wire.length;
  f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.input.targetId);
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByRole("alert").filter({ hasText: "WORKBENCH_BINDINGS_CHANGED" }).waitFor();
  assert.equal(f.wire.length, count);
  await page.screenshot({ path: join(output, "07-guided-history-stale-refusal.png"), fullPage: true });
  assert.deepEqual(errors, []);
  cases.push({
    case: "DURABLE_MAP_HISTORY_CSRF_ORGANIZATION_AND_STALE_NO_WIRE",
    status: "PASS",
    foreign,
    requestsUnchanged: true
  });
  f.capture("GUIDED_EDGE_NATIVE_SQLITE_ACCEPTANCE");
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
        preparedObservation: false,
        jsonPolicyImport: false,
        externalTargets: false,
        releaseBuild: false
      },
      null,
      2
    ),
    { flag: "wx" }
  );
}
if (status !== "PASS") throw Error("GUIDED_MAPPING_BROWSER_FAILED:" + failure);
