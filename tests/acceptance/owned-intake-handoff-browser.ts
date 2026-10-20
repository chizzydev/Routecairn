import { z } from "zod";
import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { deepBusinessFixture } from "../helpers/deep-businessflow-fixture.js";
import { ownedIntakeExport } from "../helpers/owned-intake-export.js";
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
const f = await deepBusinessFixture(4, "vulnerable", false);
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
    acceptDownloads: true
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

  const intake = page.getByRole("region", { name: "Owned application offline intake" });
  await intake.getByLabel("Minimized owner evidence JSON").fill(JSON.stringify(ownedIntakeExport(f)));
  await intake.getByRole("checkbox").check();
  const intakeUrl = "**/api/authorization-workbench/mapping/intake";
  await page.route(intakeUrl, async (route) => {
    const response = await route.fetch();
    assert.equal(response.status(), 201);
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: "Owned test: acknowledgement deliberately lost after actual commit" })
    });
  });
  await intake.getByRole("button", { name: "Validate and retain offline intake" }).click();
  await intake.getByRole("alert").waitFor();
  await page.unroute(intakeUrl);
  assert.equal((f.database.db.prepare("SELECT count(*) n FROM application_owned_intakes").get() as { n: number }).n, 1);
  assert.equal(f.wire.length, 0);
  await intake.getByRole("button", { name: "Inspect retained offline intakes" }).click();
  await intake.getByLabel("Retained intake receipt").locator("option").nth(1).waitFor({ state: "attached" });
  const retainedIntakeId = await intake
    .getByLabel("Retained intake receipt")
    .locator("option")
    .nth(1)
    .getAttribute("value");
  await intake.getByLabel("Retained intake receipt").selectOption(retainedIntakeId!);
  await intake.getByRole("button", { name: "Open retained intake without replay" }).click();
  await intake.getByText(/Offline intake retained/).waitFor();
  assert.equal((f.database.db.prepare("SELECT count(*) n FROM application_owned_intakes").get() as { n: number }).n, 1);
  cases.push({ case: "COMMITTED_INTAKE_LOST_ACK_READ_RECOVERY_NO_REPLAY", status: "PASS", retainedIntakeId });

  let releaseReceipt: (() => void) | undefined, receiptSeen!: () => void;
  const seen = new Promise<void>((r) => {
      receiptSeen = r;
    }),
    exactReceiptUrl = "**/api/authorization-workbench/mapping/intakes/" + retainedIntakeId;
  await page.route(exactReceiptUrl, async (route) => {
    const response = await route.fetch();
    await new Promise<void>((r) => {
      releaseReceipt = r;
      receiptSeen();
    });
    await route.fulfill({ response });
  });
  let receiptTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    await intake.getByRole("button", { name: "Open retained intake without replay" }).click();
    await Promise.race([
      seen,
      new Promise<never>((_, reject) => {
        receiptTimer = setTimeout(() => reject(Error("ORIGINAL_20S_RECEIPT_RESPONSE_BOUND")), 20000);
      })
    ]);
    clearTimeout(receiptTimer);
    await intake.getByLabel("Exact retained intake ID").fill("22222222-2222-4222-8222-222222222222");
    const completedResponse = page.waitForResponse((r) => r.url().endsWith("/intakes/" + retainedIntakeId), {
      timeout: 20000
    });
    releaseReceipt!();
    await (await completedResponse).finished();
    await page.evaluate(
      () =>
        new Promise<void>((done) => {
          const win = globalThis as unknown as { requestAnimationFrame(callback: () => void): number };
          win.requestAnimationFrame(() => win.requestAnimationFrame(done));
        })
    );
    assert.equal(await intake.getByText(/Offline intake retained/).count(), 0);
    assert.equal(
      await intake.getByRole("button", { name: "Apply reviewed intake routes without execution" }).count(),
      0
    );
  } finally {
    clearTimeout(receiptTimer);
    releaseReceipt?.();
    await page.unroute(exactReceiptUrl);
  }
  await intake.getByLabel("Exact retained intake ID").fill(retainedIntakeId!);
  await intake.getByRole("button", { name: "Open retained intake without replay" }).click();
  await intake.getByText(/Offline intake retained/).waitFor();
  assert.equal(f.wire.length, 0);
  cases.push({ case: "ACTUAL_LATE_RECEIPT_RESPONSE_IGNORED_AFTER_SELECTION_CHANGE", status: "PASS" });

  assert.equal(f.wire.length, 0);
  await intake.getByRole("button", { name: "Apply reviewed intake routes without execution" }).click();
  await page.getByRole("checkbox", { name: "I confirm these disposable actor, role and tenant bindings." }).check();
  cases.push({ case: "GUI_OFFLINE_INTAKE_IMMUTABLE_NO_TRAFFIC", status: "PASS" });
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
  await page.getByLabel("Differential step 1", { exact: true }).selectOption("request");
  await page.getByLabel("Differential step 2", { exact: true }).selectOption("quote");
  for (let i = 2; i < 4; i++) {
    await page.getByRole("button", { name: "Add differential step", exact: true }).click();
    await page.getByLabel("Differential step " + (i + 1), { exact: true }).selectOption(f.workflow.routeIds[i]!);
  }

  await page.getByRole("button", { name: "Draft reviewed differential workflow", exact: true }).click();
  await page.getByRole("button", { name: "Review flow into existing proof matrix", exact: true }).waitFor();
  const relation = page.getByRole("region", { name: "Business relationship witnesses" });
  for (let i = 0; i < 3; i++) {
    if (i) await relation.getByRole("button", { name: "Add relationship", exact: true }).click();
    const n = i + 1;
    await relation.getByLabel("Relationship " + n + " name", { exact: true }).fill("Procurement linked step " + n);
    await relation.getByLabel("Relationship " + n + " producer", { exact: true }).selectOption(f.workflow.routeIds[i]!);
    await relation
      .getByLabel("Relationship " + n + " consumer", { exact: true })
      .selectOption(f.workflow.routeIds[i + 1]!);
    await relation.getByLabel("Relationship " + n + " reference", { exact: true }).selectOption("record.parent");
    await relation.getByLabel("Relationship " + n + " producerVersion", { exact: true }).selectOption("record.version");
    await relation.getByLabel("Relationship " + n + " consumerVersion", { exact: true }).selectOption("record.version");
  }
  await relation.getByRole("button", { name: "Build evidence-bound relationship questions", exact: true }).focus();
  await relation
    .getByRole("button", { name: "Build evidence-bound relationship questions", exact: true })
    .press("Enter");
  await page.getByRole("table", { name: "Relationship Procurement linked step 1", exact: true }).waitFor();
  assert.equal(f.wire.length, 20);
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
  assert.deepEqual(snapshot.flow.steps[1].dependsOn, ["request"]);
  assert.equal(snapshot.relationships.relationships.length, 3);
  assert.equal(snapshot.relationships.eligibility, "EVIDENCE_READY_FOR_POLICY_REVIEW");
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
  assert.ok(before.result.checks.filter((c) => c.checkId.startsWith("request-")).every((c) => c.outcome === "PASS"));
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
  assert.equal(f.wire.length, 40);
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
  const handoff = page.getByRole("region", { name: "Analyst handoff and complete history" });
  await handoff.getByRole("button", { name: "Search retained history" }).focus();
  await handoff.getByRole("button", { name: "Search retained history" }).press("Enter");
  await handoff.getByText(/retained records/).waitFor();
  await handoff.getByLabel("History type").selectOption("comparisons");
  await handoff.getByRole("button", { name: "Search retained history" }).click();
  await handoff.getByText(/1 matching of 1 retained records/).waitFor();
  cases.push({ case: "GUI_SOURCE_BOUND_COMPARISON_HISTORY_SEARCH", status: "PASS" });
  await handoff.getByRole("button", { name: "Prepare redacted analyst handoff" }).click();
  await handoff.getByText(/Case packet/).waitFor();
  await handoff.getByText("Inspect and copy source-bound analyst packet", { exact: true }).click();
  const packet = JSON.parse(await handoff.getByLabel("Redacted analyst packet").inputValue());
  assert.equal(packet.relationships.length, 3);
  assert.equal(packet.comparisonIndex.length, 1);
  assert.equal(packet.intakeProvenance.declaredProvenance, "SELF_MAINTAINED_FIXTURE");
  assert.equal(
    packet.intakeProvenance.digest,
    (f.database.db.prepare("SELECT digest FROM application_owned_intakes").get() as { digest: string }).digest
  );
  assert.equal(packet.causalProof, false);
  assert.equal(packet.comparisons.length, 1);
  assert.equal(packet.proofIndex.length, 2);
  assert.equal(packet.noteIndex.length, 1);
  assert.ok(!JSON.stringify(packet).includes("Bearer"));
  assert.equal(f.wire.length, 60);
  writeFileSync(join(output, "ACTUAL_ANALYST_HANDOFF.json"), JSON.stringify(packet, null, 2), { flag: "wx" });
  await page.screenshot({ path: join(output, "07-four-step-analyst-handoff.png"), fullPage: true });
  cases.push({
    case: "KEYBOARD_HISTORY_AND_REDACTED_FOUR_STEP_HANDOFF",
    status: "PASS",
    packetSha256: packet.packetSha256
  });
  const downloadEvent = page.waitForEvent("download");
  await handoff.getByRole("button", { name: "Download redacted analyst packet", exact: true }).focus();
  await handoff.getByRole("button", { name: "Download redacted analyst packet", exact: true }).press("Enter");
  const download = await downloadEvent,
    destination = join(output, "DOWNLOADED_ANALYST_CASE.json");
  assert.equal(existsSync(destination), false);
  await download.saveAs(destination);
  assert.deepEqual(JSON.parse(readFileSync(destination, "utf8")), packet);
  cases.push({
    case: "ACTUAL_KEYBOARD_CASE_DOWNLOAD_EXACT_SOURCE_BOUND_BYTES",
    status: "PASS",
    suggestedFilename: download.suggestedFilename(),
    retained: destination
  });
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
