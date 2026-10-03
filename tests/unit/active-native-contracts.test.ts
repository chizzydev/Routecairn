import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { activeVulnerabilityInputSchema, planActiveVulnerabilityValidation } from "../../src/modules/activeVulnerability/ActiveVulnerabilityPlanner.js";
import { generateActiveFileFixture } from "../../src/modules/activeVulnerability/ActiveFileFixtures.js";

const origin = "http://127.0.0.1:43115";
const context = { target: origin, scope: { ...exampleScope, allowedDomains: ["127.0.0.1"], sameOriginOnly: false, disallowedPaths: [], allowedMethods: ["GET", "POST", "DELETE"] as const } };
const fixture = () => ({ maxRequests: 28, discovery: { enabled: false, maxCandidates: 0 }, cases: [{ id: "native", label: "native", vulnerabilityClass: "OAUTH_VALIDATION", actorId: "anonymous", environment: "LOCAL_FIXTURE", request: { url: `${origin}/start`, method: "GET", injection: { location: "QUERY", name: "state" } }, proof: { oauthExpectedIssuer: "http://127.0.0.1:43116", oauthExpectedClientId: "client", oauthExpectedAccount: "owner", verificationUrl: `${origin}/identity`, cleanupUrl: `${origin}/cleanup`, cleanupMethod: "DELETE", oauthJourney: { discoveryUrl: "http://127.0.0.1:43116/.well-known/openid-configuration", callbackUrl: `${origin}/callback`, identityJsonPath: "account", expiresAt: new Date(Date.now() + 3600000).toISOString(), confirmation: "I_AUTHORIZE_DISPOSABLE_OAUTH_JOURNEYS" } }, strategy: { techniques: ["OAUTH_STATE"], approvedRisks: ["PASSIVE_DIFFERENTIAL", "STATEFUL_CANARY"] } }] });
describe("native active contracts", () => {
  for (const mutation of ["expired", "out-of-scope", "missing-issuer", "unapproved", "ambiguous-callback", "inline-session", "unbound-link"] as const) it(`rejects ${mutation}`, () => {
    const input: any = fixture(); const item = input.cases[0]; const journey = item.proof.oauthJourney;
    if (mutation === "expired") journey.expiresAt = new Date(Date.now() - 1000).toISOString();
    if (mutation === "out-of-scope") journey.discoveryUrl = "https://unapproved.example.test/.well-known/openid-configuration";
    if (mutation === "missing-issuer") delete item.proof.oauthExpectedIssuer;
    if (mutation === "unapproved") item.strategy.approvedRisks = ["PASSIVE_DIFFERENTIAL"];
    if (mutation === "ambiguous-callback") journey.callbackUrl += "?redirect=another";
    if (mutation === "inline-session") journey.sessionHeaders = { Cookie: "session=inline" };
    if (mutation === "unbound-link") { item.strategy.techniques = ["OAUTH_ACCOUNT_LINK"]; journey.foreignAccount = "foreign"; journey.foreignSessionHeaders = { Cookie: "{{SECRET:foreign}}" }; }
    expect(() => planActiveVulnerabilityValidation(activeVulnerabilityInputSchema.parse(input), context)).toThrow();
  });
  it("binds approval endpoints to the comparison fingerprint", () => { const a: any = fixture(); const first = planActiveVulnerabilityValidation(activeVulnerabilityInputSchema.parse(a), context); a.cases[0].proof.oauthJourney.identityJsonPath = "user.account"; const second = planActiveVulnerabilityValidation(activeVulnerabilityInputSchema.parse(a), context); expect(first.cases[0]!.comparisonFingerprint).not.toBe(second.cases[0]!.comparisonFingerprint); expect(Object.isFrozen(first.cases[0]!.proof.oauthJourney)).toBe(true); });
  it("enforces byte, expansion, format and traversal-name bounds at generation", () => {
    for (const args of [["ZIP", "ARCHIVE_CANARY", "0123456789abcdef01234567", "../outside", 4096], ["TAR", "ARCHIVE_DUPLICATE_ENTRY", "0123456789abcdef01234567", "safe.txt", 1024], ["SVG", "ARCHIVE_SYMLINK", "0123456789abcdef01234567", "safe.txt", 4096]] as const) expect(() => generateActiveFileFixture(...args)).toThrow();
  });
});
