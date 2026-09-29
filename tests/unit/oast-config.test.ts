import { afterEach, describe, expect, it } from "vitest";
import { oastServiceConfigSchema, readOastServiceSecrets } from "../../src/oast/OastConfig.js";

const signingVariable = "ROUTECAIRN_TEST_OAST_SIGNING";
const tenantVariable = "ROUTECAIRN_TEST_OAST_TENANTS";

afterEach(() => { delete process.env[signingVariable]; delete process.env[tenantVariable]; });

describe("OAST service configuration", () => {
  it("requires TLS for hosted mode and credential-free public origins", () => {
    expect(() => parse({ mode: "HOSTED", publicHttpsBaseUrl: "https://oast.example.test/" })).toThrow(/HTTPS listener/i);
    expect(() => parse({ mode: "HOSTED", httpsPort: 8443, tlsKeyPath: "key.pem", tlsCertPath: "cert.pem", publicHttpsBaseUrl: "http://oast.example.test/" })).toThrow(/HTTPS public base URL/i);
    expect(() => parse({ mode: "SELF_HOSTED", publicHttpBaseUrl: "http://user:pass@127.0.0.1:7777/" })).toThrow(/credential-free origin/i);
  });

  it("loads separate, bounded tenant tokens only from the environment", () => {
    const config = parse({ mode: "SELF_HOSTED", signingKeyEnv: signingVariable, tenantTokensEnv: tenantVariable });
    process.env[signingVariable] = "s".repeat(32);
    process.env[tenantVariable] = JSON.stringify({ "tenant-a": "a".repeat(24), "tenant-b": "b".repeat(32) });
    const secrets = readOastServiceSecrets(config);
    expect(secrets.signingKey).toHaveLength(32);
    expect(secrets.tenantTokens.get("tenant-a")).toBe("a".repeat(24));
    process.env[tenantVariable] = JSON.stringify({ "tenant-a": "short" });
    expect(() => readOastServiceSecrets(config)).toThrow(/at least 24 characters/i);
  });
});

function parse(overrides: Record<string, unknown>) {
  return oastServiceConfigSchema.parse({ schemaVersion: 1, listenHost: "127.0.0.1", httpPort: 7777, dnsUdpPort: 53535, dnsTcpPort: 53535, baseDomain: "oast.example.test", databasePath: ".routecairn-oast/test.sqlite", maxLeaseSeconds: 300, maxEventsPerLease: 5, maxRequestBytes: 8192, dnsAnswerIpv4: "127.0.0.1", dnsAnswerIpv6: "::1", ...overrides });
}
