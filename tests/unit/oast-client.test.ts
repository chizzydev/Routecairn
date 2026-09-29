import { afterEach, describe, expect, it } from "vitest";
import { OastClient } from "../../src/oast/OastClient.js";
import type { ActiveGeneratedStrategy } from "../../src/modules/activeVulnerability/ActiveVulnerabilityStrategies.js";
import type { ActiveOastPlan, ActiveVulnerabilityCasePlan } from "../../src/modules/activeVulnerability/ActiveVulnerabilityTypes.js";
import type { OastLeaseIdentity } from "../../src/oast/OastTypes.js";

const tokenVariable = "ROUTECAIRN_TEST_OAST_CLIENT_TOKEN";
const plan: ActiveOastPlan = { mode: "SELF_HOSTED", apiBaseUrl: "http://127.0.0.1:7777/", apiTokenEnv: tokenVariable, tenantId: "tenant", workerId: "worker", jobId: "job", leaseSeconds: 60, pollIntervalMs: 100, maxPolls: 3, protocols: ["DNS", "HTTP", "HTTPS"] };
const leaseId = "a".repeat(32); const signature = "b".repeat(32);
const lease: OastLeaseIdentity = { leaseId, expiresAt: "2027-01-01T00:00:00.000Z", dnsName: `${leaseId}.${signature}.oast.example.test`, httpUrl: `http://oast.example.test/c/${leaseId}/${signature}`, httpsUrl: `https://oast.example.test/c/${leaseId}/${signature}`, pollUrl: `/v1/leases/${leaseId}/events`, pollToken: "p".repeat(32), bindingFingerprint: "b".repeat(64) };

afterEach(() => { delete process.env[tokenVariable]; });

describe("OAST active strategy materialization", () => {
  it("generates protocol and runtime-specific blind proof fixtures", () => {
    process.env[tokenVariable] = "t".repeat(32);
    const client = new OastClient(plan, 1000);
    expect(client.materialize(strategy("HTTP"), lease, testCase("SSRF")).probe).toBe(lease.httpUrl);
    expect(client.materialize(strategy("HTTPS"), lease, testCase("XXE")).probe).toContain(`SYSTEM "${lease.httpsUrl}"`);
    expect(client.materialize(strategy("DNS"), lease, testCase("COMMAND_INJECTION", { commandDialect: "POSIX_SH" })).probe).toBe(`;nslookup '${lease.dnsName}'`);
    expect(client.materialize(strategy("HTTP"), lease, testCase("COMMAND_INJECTION", { commandDialect: "POWERSHELL" })).probe).toContain("Invoke-WebRequest");
    expect(client.materialize(strategy("HTTPS"), lease, testCase("TEMPLATE_INJECTION", { templateDialect: "JINJA2" })).probe).toContain("cycler.__init__");
    expect(client.materialize(strategy("HTTP"), lease, testCase("TEMPLATE_INJECTION", { templateDialect: "TWIG" })).probe).toContain("filter('system')");
    expect(client.materialize(strategy("DNS"), lease, testCase("TEMPLATE_INJECTION", { templateDialect: "FREEMARKER" })).probe).toContain("freemarker.template.utility.Execute");
  });
});

function strategy(protocol: "DNS" | "HTTP" | "HTTPS"): ActiveGeneratedStrategy { return { id: `oast-${protocol}`, technique: "OAST_CALLBACK", risk: "OUT_OF_BAND_CALLBACK", encoding: "PLAIN", baseline: "fixture", control: "control", probe: "placeholder", oracle: "OAST", samples: 1, oastProtocol: protocol }; }
function testCase(vulnerabilityClass: ActiveVulnerabilityCasePlan["vulnerabilityClass"], proof: Partial<ActiveVulnerabilityCasePlan["proof"]> = {}): ActiveVulnerabilityCasePlan { return { id: "case", label: "case", vulnerabilityClass, actorId: "anonymous", environment: "LOCAL_FIXTURE", request: { url: "http://127.0.0.1/test", method: "GET", headers: {}, injection: { location: "QUERY", name: "value", originalValue: "fixture" }, operatorConfirmedNonMutating: false }, proof: { allowedRedirectOrigins: [], secureStatuses: [], vulnerableStatuses: [], ...proof }, strategy: { profile: "DEEP", techniques: ["OAST_CALLBACK"], encodings: ["PLAIN"], maxStrategies: 1, boundedDelayMs: 400, timingSamples: 2, approvedRisks: ["OUT_OF_BAND_CALLBACK"], sqlDialect: "AUTO", noSqlDialect: "DOCUMENT_GENERIC", unionColumns: 1, unionMarkerColumn: 1 }, comparisonFingerprint: "c".repeat(64), source: "EXPLICIT" }; }
