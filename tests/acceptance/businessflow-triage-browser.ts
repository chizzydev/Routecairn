import { z } from "zod";
import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import assert from "node:assert/strict";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
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
const f = await businessFlowFixture("orders", "vulnerable", false);
await f.execution.shutdown();
assert.equal(f.wire.length, 0);
assert.equal(existsSync(join(f.root, "EXPECTATIONS.json")), false);
let backend: Awaited<ReturnType<typeof startDashboardServer>> | undefined,
  vite: Awaited<ReturnType<typeof createServer>> | undefined,
  browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined,
  status = "FAILED",
  failure: string | undefined;
const errors: string[] = [];
const cases: Record<string, unknown>[] = [],
  tasks: Record<string, unknown>[] = [];
let taskStart = Date.now(),
  browserVersion: string | undefined;
const task = (name: string) => {
  tasks.push({ task: name, elapsedMs: Date.now() - taskStart, method: "SCRIPTED_CONTROLLED_TASK_NOT_NOVICE_STUDY" });
  taskStart = Date.now();
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
  await page.getByRole("button", { name: "Start guided application mapping" }).click();
  taskStart = Date.now();
  const form = page.getByRole("region", { name: "Guided authenticated application mapping" });
  await form.getByText("Set up an owned local application and actors", { exact: true }).click();
  const setup = page.getByRole("region", { name: "Application onboarding" });
  await setup.getByLabel("Application name", { exact: true }).fill("Owned event-sourced order and invoice workflow");
  await setup.getByLabel("Owned application origin", { exact: true }).fill(f.origin);
  await setup
    .getByLabel("Owner authorization explanation", { exact: true })
    .fill(
      "I own this generated local application and separately authorize only reviewed non-mutating GET observations and proof."
    );
  await setup.getByLabel("Initial permitted GET path", { exact: true }).fill(f.input.routes[0]!.pathTemplate);
  await setup.getByLabel("Evidence fields", { exact: true }).check();
  await setup.getByLabel("Onboarding objectField", { exact: true }).fill("record.id");
  await setup.getByLabel("Onboarding objectTenantField", { exact: true }).fill("record.tenant");
  await setup.getByLabel("Test actors", { exact: true }).check();
  for (const [slot, a] of Object.entries(f.app.actors))
    for (const [field, value] of Object.entries({
      ...a,
      authorizationHeader: "Bearer heldout-ledger-" + slot,
      expiresAt: "2099-01-01T00:00:00Z"
    }))
      await setup.getByLabel(slot + " " + field, { exact: true }).fill(value);
  await setup.getByLabel("Review", { exact: true }).check();
  await setup.getByRole("checkbox", { name: /I own this local application/ }).check();
  await setup.getByRole("button", { name: "Save declarations without sending requests", exact: true }).click();
  await form
    .getByLabel("Owned loopback target", { exact: true })
    .locator("option")
    .filter({ hasText: "Owned event-sourced" })
    .waitFor({ state: "attached" });
  const targetId = (f.database.db.prepare("SELECT id FROM targets").get() as { id: string }).id;
  assert.equal(f.wire.length, 0);
  assert.equal((f.database.db.prepare("SELECT count(*) n FROM credential_profiles").get() as { n: number }).n, 3);
  assert.ok(
    await setup
      .locator("input[type=password]")
      .evaluateAll((nodes) => nodes.every((n) => Reflect.get(n, "value") === ""))
  );
  task("FIRST_RUN_OWNED_TARGET_AND_THREE_ENCRYPTED_ACTORS_NO_TARGET_REQUESTS");
  cases.push({ case: "GUI_FIRST_RUN_DECLARATIONS_AND_CREDENTIAL_CLEARING", status: "PASS" });
  await page.getByRole("checkbox", { name: "I confirm these disposable actor, role and tenant bindings." }).check();

  for (const [i, r] of f.input.routes.slice(0, f.workflow.routeIds.length).entries()) {
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
  assert.equal(observed.observations[0]!.cells[0]!.observedMarkers.length, 4);
  await page.screenshot({ path: join(output, "01-native-state-marker-map.png"), fullPage: true });
  cases.push({ case: "GUIDED_ROLE_STATE_MAPPING_NO_WIRE_PREVIEW", status: "PASS", observed });
  task("REVIEW_AND_ACQUIRE_TWO_EXACT_NATIVE_ACTOR_ROUTE_MAPS");
  await page.getByText("Evidence-grounded security hypotheses", { exact: true }).click();
  await page.getByRole("button", { name: "Generate grounded hypotheses", exact: true }).click();
  const flowUI = page.getByRole("region", { name: "Reviewed role and business-flow differential testing" });
  await flowUI.waitFor();
  await page.getByLabel("Differential step 1", { exact: true }).selectOption("source");
  await page.getByLabel("Differential step 2", { exact: true }).selectOption("consumer");

  await page.getByRole("button", { name: "Draft reviewed differential workflow", exact: true }).click();
  await page.getByRole("button", { name: "Review flow into existing proof matrix", exact: true }).waitFor();
  const relation = page.getByRole("region", { name: "Business relationship witnesses" });
  await relation.getByLabel("Relationship 1 name", { exact: true }).fill("Invoice references approved order");
  await relation.getByLabel("Relationship 1 reference", { exact: true }).selectOption("record.parent");
  await relation.getByLabel("Relationship 1 producerVersion", { exact: true }).selectOption("record.version");
  await relation.getByLabel("Relationship 1 consumerVersion", { exact: true }).selectOption("record.version");
  await relation.getByRole("button", { name: "Build evidence-bound relationship questions", exact: true }).focus();
  await relation
    .getByRole("button", { name: "Build evidence-bound relationship questions", exact: true })
    .press("Enter");
  await page.getByRole("table", { name: "Relationship Invoice references approved order", exact: true }).waitFor();
  assert.equal(f.wire.length, 12);
  task("DRAFT_TYPED_PRODUCER_CONSUMER_WITNESSES_USING_KEYBOARD");
  cases.push({ case: "GUI_TYPED_REFERENCE_VERSION_WITNESSES_NOT_CAUSALITY_OR_POLICY", status: "PASS" });
  const row = f.database.db
    .prepare("SELECT id,snapshot_json FROM application_hypothesis_proposals ORDER BY created_at DESC LIMIT 1")
    .get() as { id: string; snapshot_json: string };
  const snapshot = JSON.parse(row.snapshot_json);
  assert.equal(snapshot.flow.eligibility, "EVIDENCE_READY_FOR_POLICY_REVIEW");
  assert.equal(
    snapshot.relationships.relationships[0].cells.filter(
      (c: { relationshipObserved: boolean }) => c.relationshipObserved
    ).length,
    3
  );
  assert.deepEqual(snapshot.flow.steps[1].dependsOn, ["source"]);
  assert.equal(f.wire.length, 4 + 4 * f.workflow.routeIds.length);
  for (const policy of f.reviewFor({ digest: "draft", flow: { flowId: "draft" } }).expectations) {
    const step = policy.routeId;
    await page.getByLabel("Flow " + step + " record.id", { exact: true }).fill(String(policy.identity.expectedValue));
    await page.getByLabel("Flow " + step + " record.tenant", { exact: true }).fill("north");
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
  cases.push({ case: "NATIVE_LINKED_ENTITY_DEVIATIONS_WITH_POSITIVE_CONTROLS", status: "PASS", before });
  task("REVIEW_OWNER_POLICY_AND_SEPARATELY_AUTHORIZE_NATIVE_PROOF");
  const triage = page.getByRole("region", { name: "Evidence-centered assessment triage" });
  await triage.getByRole("button", { name: "Refresh linked assessment evidence" }).click();
  await triage.getByText(/TRIAGE_VERIFIED_NATIVE_DEVIATIONS/).waitFor();
  await triage.getByText(/Continuous Assurance is NOT TESTED/).waitFor();
  await triage.getByLabel("Triage disposition", { exact: true }).selectOption("NEEDS_OWNER_CONTEXT");
  await triage
    .getByLabel("Triage rationale", { exact: true })
    .fill(
      "Owner context review retains the observed native deviations; this note does not suppress or resolve findings."
    );
  await triage.getByRole("checkbox", { name: /I reviewed this exact evidence/ }).check();
  await triage.getByRole("button", { name: "Record evidence-bound triage note", exact: true }).click();
  await triage.getByText(/Immutable context note retained/).waitFor();
  assert.equal((f.database.db.prepare("SELECT count(*) n FROM application_triage_notes").get() as { n: number }).n, 1);
  assert.equal(f.wire.length, 24);
  task("TRIAGE_EXACT_NATIVE_EVIDENCE_WITHOUT_SUPPRESSING_FINDINGS");
  await page.screenshot({
    path: join(output, "03b-evidence-centered-triage-and-untested-assurance.png"),
    fullPage: true
  });
  cases.push({ case: "GUI_EVIDENCE_BOUND_TRIAGE_NOTE_NO_SCAN_OR_FINDING_SUPPRESSION", status: "PASS" });
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
  await f.fix();
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
  const comparedTriage = page.getByRole("region", { name: "Evidence-centered assessment triage" });
  await comparedTriage.getByRole("button", { name: "Refresh linked assessment evidence" }).click();
  await comparedTriage.getByText(/COMPARABLE_RECORDED_RESULT/).waitFor();
  task("REVIEW_REMEDIATION_COMPARISON_AND_UNTESTED_CONTINUOUS_AUTHORITY");
  cases.push({ case: "GUI_LINKED_REMEDIATION_COMPARISON_WITH_EXPLICIT_ASSURANCE_LIMITS", status: "PASS" });
  await page.screenshot({ path: join(output, "05b-linked-remediation-and-context.png"), fullPage: true });
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(targetId);
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
  task("STALE_AUTHORITY_REFUSAL_AND_ORGANIZATION_ISOLATION");
  status = "PASS";
} catch (e) {
  failure = e instanceof Error ? (e.stack ?? e.message) : String(e);
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
        tasks,
        browserVersion,
        errors,
        targetAndCredentialsCreatedThroughGUI: true,
        platform: process.platform,
        actualNativeWorkers: true,
        actualSQLite: true,
        actualEdge: true,
        sourceMode: true,
        preparedObservation: false,
        uploadedOpenapi: false,
        numericIdentityVariant: true,
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
if (status !== "PASS") throw Error("BUSINESSFLOW_BROWSER_FAILED:" + failure);
