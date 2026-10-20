import { z } from "zod";
import { chromium } from "playwright";
import { createServer } from "vite";
import react from "@vitejs/plugin-react";
import { join, resolve } from "node:path";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import assert from "node:assert/strict";
import { schemaApplicationFixture } from "../helpers/schema-application-fixture.js";
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
const f = await schemaApplicationFixture();
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
  await page.getByText("Import local OpenAPI route suggestions", { exact: true }).click();
  await page.getByLabel("Local OpenAPI JSON", { exact: true }).setInputFiles(join(f.root, "OPENAPI.json"));
  await page.getByRole("button", { name: "Inspect schema suggestions", exact: true }).click();
  await page.getByText(/SCHEMA_SUGGESTED_UNVERIFIED · source SHA-256/).waitFor();
  for (const [index, path] of [
    "/v2/records/{number}",
    "/v2/vault/{number}",
    "/v2/self/{number}",
    "/v2/reports/summary"
  ].entries()) {
    const id = "schema-route-" + (index + 1);
    await page.getByLabel("Choose " + path, { exact: true }).check();
    if (index < 3) await page.getByLabel(id + " slot number", { exact: true }).fill("42");
    await page.getByLabel(id + " identity marker", { exact: true }).selectOption("record.number");
    await page.getByLabel(id + " tenant marker", { exact: true }).selectOption("record.workspace");
  }
  assert.equal(await page.getByLabel("Excluded schema operations").locator("li").count(), 4);
  assert.equal(f.wire.length, 0);
  await page.screenshot({ path: join(output, "00-reviewed-openapi-exclusions.png"), fullPage: true });
  await page.getByRole("button", { name: "Use reviewed schema selections", exact: true }).click();
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
  const stored = f.database.db
    .prepare("SELECT input_json FROM application_mapping_revisions WHERE id=?")
    .get(acquisition.id) as { input_json: string };
  assert.ok(stored.input_json);
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
  await page.getByText("Evidence-grounded security hypotheses", { exact: true }).click();
  await page.getByRole("button", { name: "Generate grounded hypotheses", exact: true }).click();
  await page.getByRole("table", { name: "Grounded hypothesis candidates" }).waitFor();
  const pRow = f.database.db
    .prepare("SELECT id,snapshot_json FROM application_hypothesis_proposals ORDER BY created_at DESC LIMIT 1")
    .get() as { id: string; snapshot_json: string };
  const pSnapshot = JSON.parse(pRow.snapshot_json);
  assert.equal(
    pSnapshot.candidates.filter((c: { eligibility: string }) => c.eligibility === "EVIDENCE_READY_FOR_POLICY_REVIEW")
      .length,
    1
  );
  assert.equal(pSnapshot.candidates.filter((c: { eligibility: string }) => c.eligibility === "ABSTAIN").length, 3);
  assert.equal(pSnapshot.findingsInferred, false);
  assert.equal(f.wire.length, 20);
  await page.getByRole("button", { name: "Inspect hypothesis schema-route-1", exact: true }).click();
  await page.screenshot({ path: join(output, "09-grounded-hypothesis-evidence-controls.png"), fullPage: true });
  await page.getByLabel("Expected hypothesis object marker", { exact: true }).fill("42");
  await page.getByLabel("Expected hypothesis tenant marker", { exact: true }).fill("workspace-red");
  await page
    .getByLabel("Hypothesis policy rationale", { exact: true })
    .fill("The owned numeric resource is private to its publisher; other disposable actors must be denied.");
  for (const actor of ["account-a", "account-b", "anonymous"])
    await page.getByLabel("Hypothesis policy " + actor, { exact: true }).selectOption("DENY");
  await page
    .getByRole("checkbox", { name: "I explicitly confirm ownership of this exact non-secret test resource." })
    .check();
  await page
    .getByRole("checkbox", {
      name: "I declare the expected policy; this observation does not establish a vulnerability."
    })
    .check();
  assert.equal(f.wire.length, 20);
  await page.getByRole("button", { name: "Record policy and review bounded matrix", exact: true }).click();
  cases.push({ case: "GROUNDED_PROPOSAL_REVIEW_NO_WIRE_NO_INFERRED_FINDINGS", status: "PASS", proposal: pSnapshot });
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
  assert.equal(
    before.result.checks.filter((c) => c.checkId.startsWith("schema-route-2") && c.outcome !== "PASS").length,
    0
  );
  assert.equal(
    before.result.checks.filter((c) => c.checkId.startsWith("schema-route-3") && c.outcome === "FAIL").length,
    0
  );
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
  await page.getByText(/^Execution outcome: PASS/).waitFor({ timeout: 20000 });
  await page.getByLabel("Baseline revision").selectOption(firstId);
  await page.getByRole("button", { name: "Compare retained executions" }).click();
  await page.getByText(/Remediation comparison:/).waitFor();
  const after = resultEvidence.parse(
    await page.evaluate(async (id) => (await fetch("/api/authorization-workbench/" + id)).json(), afterId)
  );
  assert.equal(after.result.findings.length, 0);
  assert.equal(after.result.verifiedPass, true);
  assert.equal(after.result.checks.length, 4);
  assert.equal(
    after.result.checks.every((c) => c.outcome === "PASS"),
    true
  );
  const comparison = f.database.db
    .prepare("SELECT id,state,summary_json FROM scan_comparisons WHERE older_scan_id=? AND newer_scan_id=?")
    .get(before.result.scanId, after.result.scanId) as { id: string; state: string; summary_json: string };
  assert.equal(JSON.parse(comparison.summary_json).resolved, 2);
  assert.equal(f.wire.length, 36);
  await page.screenshot({ path: join(output, "05-guided-remediation-retained-comparison.png"), fullPage: true });
  await page.getByRole("button", { name: "Open existing comparison evidence" }).click();
  await page.getByText("Finding comparison", { exact: true }).waitFor();
  await page.screenshot({ path: join(output, "06-existing-comparison-view.png"), fullPage: true });
  cases.push({
    case: "HYPOTHESIS_FOUR_CHECK_REMEDIATION_NOT_FULL_APP_ACCEPTANCE",
    status: "PASS",
    after: after.result,
    comparison
  });
  await page.getByRole("button", { name: "Application Authorization", exact: true }).click();
  await page.getByRole("button", { name: "Start guided application mapping" }).click();
  await page.getByLabel("Retained application map").selectOption(acquisition.id);
  await page.getByText("Observation status: COMPLETED", { exact: true }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Authorize native observations" }).isDisabled(), true);
  await page.getByText("A–B. Configure permitted routes and actor identities", { exact: true }).click();
  await page.getByRole("checkbox", { name: "I confirm these disposable actor, role and tenant bindings." }).check();
  await page
    .getByRole("checkbox", { name: "I confirm the exact listed GET handlers are authorized and non-mutating." })
    .check();
  await page.getByRole("button", { name: "Review observation requests", exact: true }).click();
  await page.getByText("Observation status: REVIEW_REQUIRED", { exact: true }).waitFor();
  await page.getByRole("checkbox", { name: "I approve only these exact bounded native observation requests." }).check();
  await page.getByRole("button", { name: "Authorize native observations", exact: true }).click();
  await page.getByText("Observation status: COMPLETED", { exact: true }).waitFor({ timeout: 20000 });
  await page.getByText("Compare retained application maps", { exact: true }).click();
  await page.getByLabel("Baseline application map", { exact: true }).selectOption(acquisition.id);
  await page.getByRole("button", { name: "Compare observed maps", exact: true }).click();
  await page.getByText(/Map comparison: OBSERVED_DIFFERENCES/).waitFor();
  assert.equal(f.wire.length, 56);
  assert.equal(
    f.wire.every((r) => r.method === "GET"),
    true
  );
  await page.screenshot({ path: join(output, "08-immutable-native-map-differences.png"), fullPage: true });
  const mapComparison = f.database.db
    .prepare("SELECT snapshot_json FROM application_map_comparisons ORDER BY created_at DESC LIMIT 1")
    .get() as { snapshot_json: string };
  const mapSnapshot = JSON.parse(mapComparison.snapshot_json);
  assert.equal(
    mapSnapshot.routes
      .flatMap((r: { cells: { accessChange: string }[] }) => r.cells)
      .filter((c: { accessChange: string }) => c.accessChange === "CHANGED_HYPOTHESIS").length,
    2
  );
  cases.push({
    case: "SCHEMA_SECOND_APP_IMMUTABLE_MAP_DIFF",
    status: "PASS",
    snapshot: mapSnapshot,
    unapprovedMutationRequests: 0
  });
  await page.getByText("Evidence-grounded security hypotheses", { exact: true }).click();
  await page.getByRole("button", { name: "Generate grounded hypotheses", exact: true }).click();
  await page.getByRole("table", { name: "Grounded hypothesis candidates" }).waitFor();
  const hardened = f.database.db
    .prepare("SELECT snapshot_json FROM application_hypothesis_proposals ORDER BY created_at DESC LIMIT 1")
    .get() as { snapshot_json: string };
  assert.equal(
    JSON.parse(hardened.snapshot_json).candidates.filter(
      (c: { eligibility: string }) => c.eligibility === "EVIDENCE_READY_FOR_POLICY_REVIEW"
    ).length,
    0
  );
  assert.equal(f.wire.length, 56);
  await page.screenshot({ path: join(output, "10-hardened-map-abstention.png"), fullPage: true });
  cases.push({ case: "HARDENED_MAP_ABSTAINS_WITHOUT_FINDING_OR_AUTOPROOF", status: "PASS" });
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
  await page.getByText(/^Execution outcome: PASS/).waitFor();
  await page.getByRole("button", { name: "Create versioned matrix" }).click();
  await page.getByText(/READY_READ_ONLY · revision/).waitFor();
  const count = f.wire.length;
  f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.targetId);
  await page.getByRole("checkbox", { name: /I authorize these exact bounded/ }).check();
  await page.getByRole("button", { name: "Authorize and run selected matrix" }).click();
  await page.getByRole("alert").filter({ hasText: "WORKBENCH_HYPOTHESIS_AUTHORITY_CHANGED" }).waitFor();
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
        uploadedOpenapi: true,
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
if (status !== "PASS") throw Error("HYPOTHESIS_BROWSER_FAILED:" + failure);
