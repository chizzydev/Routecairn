import { z } from "zod";
import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import assert from "node:assert/strict";
import { roleflowApplicationFixture } from "../helpers/roleflow-application-fixture.js";
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
const application = process.argv[3] === "membership" ? "membership" : "procurement";
const f = await roleflowApplicationFixture(application);
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
  await page.getByLabel("Owned loopback target").selectOption(f.targetId);
  for (const slot of ["primary", "account_a", "account_b"] as const)
    await page.getByLabel(slot + " saved credential").selectOption(f.credentials[slot]);
  await page.getByRole("checkbox", { name: "I confirm these disposable actor, role and tenant bindings." }).check();

  for (const [i, r] of f.mappingInput.routes.slice(0, f.workflow.routeIds.length).entries()) {
    if (i) await page.getByRole("button", { name: "Add permitted route", exact: true }).click();
    await page.getByLabel("Route " + (i + 1) + " label", { exact: true }).fill(r.id);
    await page.getByLabel("Route " + (i + 1) + " kind", { exact: true }).selectOption(r.kind);
    await page.getByLabel("Route " + (i + 1) + " exact URL", { exact: true }).fill(r.url);
    await page.getByLabel("Route " + (i + 1) + " template", { exact: true }).fill(r.pathTemplate);
    await page.getByLabel("Route " + (i + 1) + " identity path", { exact: true }).fill(r.identityPath);
    await page.getByLabel("Route " + (i + 1) + " tenant path", { exact: true }).fill(r.tenantPath!);
    await page.getByLabel("Route " + (i + 1) + " state paths", { exact: true }).fill(r.statePaths!.join(","));
  }
  await page
    .getByRole("checkbox", { name: "I confirm the exact listed GET handlers are authorized and non-mutating." })
    .check();
  await page.getByRole("button", { name: "Review observation requests", exact: true }).click();
  await page.getByText("Observation status: REVIEW_REQUIRED", { exact: true }).waitFor();
  assert.equal(f.wire.length, 0);
  await page.screenshot({ path: join(output, "00-exact-role-state-observation-preview.png"), fullPage: true });
  const acquisition = f.database.db.prepare("SELECT id FROM application_mapping_revisions").get() as { id: string };
  await page.getByRole("checkbox", { name: "I approve only these exact bounded native observation requests." }).check();
  await page.getByRole("button", { name: "Authorize native observations", exact: true }).click();
  await page.getByText("Observation status: COMPLETED", { exact: true }).waitFor({ timeout: 20000 });
  assert.equal(f.wire.length, 4 + 4 * f.workflow.routeIds.length);
  const observed = observedEvidence.parse(
    await page.evaluate(
      async (id) => (await fetch("/api/authorization-workbench/mapping/" + id)).json(),
      acquisition.id
    )
  );
  assert.equal(observed.observations[0]!.cells[0]!.observedMarkers.length, 3);
  await page.screenshot({ path: join(output, "01-native-state-marker-map.png"), fullPage: true });
  cases.push({ case: "GUIDED_ROLE_STATE_MAPPING_NO_WIRE_PREVIEW", status: "PASS", observed });
  await page.getByText("Evidence-grounded security hypotheses", { exact: true }).click();
  await page.getByRole("button", { name: "Generate grounded hypotheses", exact: true }).click();
  const flowUI = page.getByRole("region", { name: "Reviewed role and business-flow differential testing" });
  await flowUI.waitFor();
  await page.getByLabel("Differential step 1", { exact: true }).selectOption("source");
  await page.getByLabel("Differential step 2", { exact: true }).selectOption("operation");
  if (application === "membership") {
    await page.getByLabel("Differential step 2", { exact: true }).selectOption("consent");
    await page.getByRole("button", { name: "Add differential step", exact: true }).click();
    await page.getByLabel("Differential step 3", { exact: true }).selectOption("operation");
  }
  await page.getByRole("button", { name: "Draft reviewed differential workflow", exact: true }).click();
  await page.getByRole("button", { name: "Review flow into existing proof matrix", exact: true }).waitFor();
  const row = f.database.db
    .prepare("SELECT id,snapshot_json FROM application_hypothesis_proposals ORDER BY created_at DESC LIMIT 1")
    .get() as { id: string; snapshot_json: string };
  const snapshot = JSON.parse(row.snapshot_json);
  assert.equal(snapshot.flow.eligibility, "EVIDENCE_READY_FOR_POLICY_REVIEW");
  assert.deepEqual(snapshot.flow.steps[1].dependsOn, ["source"]);
  assert.equal(f.wire.length, 4 + 4 * f.workflow.routeIds.length);
  for (const policy of f.reviewFor({ digest: "draft", flow: { flowId: "draft" } }).expectations) {
    const step = policy.routeId;
    await page
      .getByLabel("Flow " + step + " record.number", { exact: true })
      .fill(String(policy.identity.expectedValue));
    await page.getByLabel("Flow " + step + " record.workspace", { exact: true }).fill("workspace-red");
    for (const state of policy.states)
      await page.getByLabel("Flow " + step + " " + state.path, { exact: true }).fill(String(state.expectedValue));
    for (const actor of ["account-a", "account-b", "anonymous"] as const)
      await page
        .getByLabel("Flow " + step + " " + actor + " decision", { exact: true })
        .selectOption(policy.decisions[actor]);
  }
  await page
    .getByLabel("Flow relationship explanation", { exact: true })
    .fill(
      "The owner declares this purchase request and approval preview describe the same disposable resource; only the approver may inspect the restricted preview."
    );
  await page
    .getByRole("checkbox", { name: "I confirm ownership and these exact cross-step resource relationships." })
    .check();
  await page
    .getByRole("checkbox", { name: "I declare the exact role, tenant and state policies for every step." })
    .check();
  await page.screenshot({ path: join(output, "02-reviewed-flow-dependencies-policy.png"), fullPage: true });
  await page.getByRole("button", { name: "Review flow into existing proof matrix", exact: true }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  assert.equal(f.wire.length, 4 + 4 * f.workflow.routeIds.length);
  cases.push({ case: "IMMUTABLE_ROLEFLOW_REVIEW_NO_EXECUTION", status: "PASS", snapshot });
  const firstText = await page.getByRole("status").filter({ hasText: "READY_READ_ONLY" }).textContent(),
    firstId = firstText!.match(/[a-f0-9-]{36}/)![0];
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix", exact: true }).click();
  await page.getByText(/^Execution outcome: FINDINGS/).waitFor({ timeout: 20000 });
  const before = resultEvidence.parse(
    await page.evaluate(async (id) => (await fetch("/api/authorization-workbench/" + id)).json(), firstId)
  );
  assert.equal(before.result.findings.length, 2);
  assert.equal(before.result.checks.length, 4 * f.workflow.routeIds.length);
  assert.ok(before.result.checks.filter((c) => c.checkId.startsWith("source-")).every((c) => c.outcome === "PASS"));
  assert.equal(f.wire.length, 2 * (4 + 4 * f.workflow.routeIds.length));
  await page.screenshot({ path: join(output, "03-native-role-function-findings.png"), fullPage: true });
  cases.push({ case: "NATIVE_FUNCTION_FINDINGS_WITH_LEGITIMATE_COLLABORATOR", status: "PASS", before });
  await page.getByRole("button", { name: "Open scan and finding evidence" }).click();
  await page.getByRole("button", { name: /Review.*findings/i }).click();
  await page
    .getByRole("heading", { name: /Findings/i })
    .first()
    .waitFor();
  await page.screenshot({ path: join(output, "04-existing-findings-evidence.png"), fullPage: true });
  cases.push({ case: "EXISTING_FINDING_VIEW", status: "PASS" });
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByLabel("Retained workbench revision").selectOption(firstId);
  await page.getByText(/^Execution outcome: FINDINGS/).waitFor();
  f.setFixed();
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  const afterText = await page.getByRole("status").filter({ hasText: "READY_READ_ONLY" }).textContent(),
    afterId = afterText!.match(/[a-f0-9-]{36}/)![0];
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByText(/^Execution outcome: PASS/).waitFor({ timeout: 20000 });
  const after = resultEvidence.parse(
    await page.evaluate(async (id) => (await fetch("/api/authorization-workbench/" + id)).json(), afterId)
  );
  assert.equal(after.result.findings.length, 0);
  assert.equal(after.result.verifiedPass, true);
  assert.equal(after.result.checks.length, 4 * f.workflow.routeIds.length);
  assert.ok(after.result.checks.every((c) => c.outcome === "PASS"));
  await page.getByLabel("Baseline revision").selectOption(firstId);
  await page.getByRole("button", { name: "Compare retained executions" }).click();
  await page.getByText(/Remediation comparison:/).waitFor();
  const comparison = f.database.db
    .prepare("SELECT summary_json FROM scan_comparisons WHERE older_scan_id=? AND newer_scan_id=?")
    .get(before.result.scanId, after.result.scanId) as { summary_json: string };
  assert.equal(JSON.parse(comparison.summary_json).resolved, 2);
  assert.equal(f.wire.length, 3 * (4 + 4 * f.workflow.routeIds.length));
  await page.screenshot({ path: join(output, "05-pinned-step-regression-comparison.png"), fullPage: true });
  cases.push({ case: "PINNED_REMEDIATION_REGRESSION_TYPED_STEP_CHECKS", status: "PASS", after, comparison });
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.targetId);
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByRole("alert").filter({ hasText: "WORKBENCH_HYPOTHESIS_AUTHORITY_CHANGED" }).waitFor();
  const foreignOrg = new OrganizationService(f.database).create(
    { name: "Foreign flow evidence", slug: "foreign-flow" },
    "local-operator"
  );
  const foreign = await page.evaluate(
    async (arg) =>
      (
        await fetch("/api/authorization-workbench/mapping/hypotheses/" + arg.id, {
          headers: { "x-routecairn-organization-id": arg.org }
        })
      ).status,
    { id: row.id, org: foreignOrg }
  );
  assert.equal(foreign, 404);
  assert.equal(f.wire.length, 3 * (4 + 4 * f.workflow.routeIds.length));
  assert.ok(f.wire.every((r) => r.method === "GET"));
  assert.deepEqual(errors, []);
  await page.screenshot({ path: join(output, "06-stale-proof-refusal.png"), fullPage: true });
  cases.push({ case: "STALE_NO_WIRE_NO_MUTATION", status: "PASS", foreign, requests: f.wire.length });
  f.capture("ROLEFLOW_EDGE_NATIVE_SQLITE_ACCEPTANCE");
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
        uploadedOpenapi: false,
        numericIdentityVariant: application === "procurement",
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
if (status !== "PASS") throw Error("ROLEFLOW_BROWSER_FAILED:" + failure);
