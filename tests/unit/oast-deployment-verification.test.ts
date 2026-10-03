import { describe, expect, it } from "vitest";
import { isPublicOastAddress, oastDeploymentVerificationSchema } from "../../src/oast/OastDeploymentVerification.js";
import { answerOastDns, oastDnsQuestion, parseOastDnsQuery } from "../../src/oast/OastDns.js";
import { inspectOastDnsAnswer } from "../../src/oast/OastDnsTransport.js";
import { oastServiceConfigSchema } from "../../src/oast/OastConfig.js";

const plan = { schemaVersion: 1, baseDomain: "callbacks.example.test", apiBaseUrl: "https://callbacks.example.test/", apiTokenEnv: "RC_OAST_TOKEN", tenantId: "tenant", workerId: "worker", jobId: "job", nameservers: ["ns1.callbacks.example.test"], serverAddresses: ["8.8.8.8"], protocols: ["DNS", "HTTPS"], authorization: { ownerApproved: true, baseDomain: "callbacks.example.test", expiresAt: new Date(Date.now() + 60000).toISOString(), referenceSha256: "a".repeat(64) }, deployment: { releaseArtifactSha256: "b".repeat(64), serviceConfigSha256: "c".repeat(64) } };
describe("public OAST evidence gates", () => {
  it.each(["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "203.0.113.10", "198.51.100.1", "192.0.2.1", "224.0.0.1", "::1", "::ffff:8.8.8.8", "2001:db8::1", "fe80::1", "fd00::1"])("rejects non-public deployment address %s", (address) => { expect(isPublicOastAddress(address)).toBe(false); expect(oastDeploymentVerificationSchema.safeParse({ ...plan, serverAddresses: [address] }).success).toBe(false); });
  it("requires current owner scope, HTTPS, unique NS/glue and DNS plus HTTPS", () => {
    expect(oastDeploymentVerificationSchema.safeParse(plan).success).toBe(true);
    for (const value of [{ ...plan, authorization: { ...plan.authorization, ownerApproved: false } }, { ...plan, authorization: { ...plan.authorization, expiresAt: "2020-01-01T00:00:00.000Z" } }, { ...plan, apiBaseUrl: "http://callbacks.example.test/" }, { ...plan, nameservers: ["ns1.outside.test"] }, { ...plan, protocols: ["HTTP"] }, { ...plan, apiBaseUrl: "https://user:password@callbacks.example.test/" }]) expect(oastDeploymentVerificationSchema.safeParse(value).success).toBe(false);
  });
  it("validates packet identity, question binding and authoritative NS records", () => {
    const config = oastServiceConfigSchema.parse({ mode: "SELF_HOSTED", httpPort: 8080, baseDomain: plan.baseDomain, databasePath: ".routecairn-oast-lab/test.sqlite", dnsTcpPort: 5353 });
    const question = oastDnsQuestion(plan.baseDomain, 2), parsed = parseOastDnsQuery(question)!; const answer = answerOastDns(question, parsed, false, config);
    expect(inspectOastDnsAnswer(answer, question)).toMatchObject({ authoritative: true, recursionAvailable: false, nameservers: plan.nameservers, rcode: 0 });
    const mismatched = Buffer.from(answer); mismatched.writeUInt16BE(2, 0); expect(() => inspectOastDnsAnswer(mismatched, question)).toThrow(); expect(() => inspectOastDnsAnswer(answer.subarray(0, -1), question)).toThrow(); expect(() => inspectOastDnsAnswer(Buffer.concat([answer, Buffer.from([0])]), question)).toThrow();
  });
});
