import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { answerOastDns, oastDnsQuestion, parseOastDnsQuery } from "../../src/oast/OastDns.js";
import { oastServiceConfigSchema } from "../../src/oast/OastConfig.js";

const config = oastServiceConfigSchema.parse({ mode: "SELF_HOSTED", httpPort: 8080, baseDomain: "callbacks.example.test", databasePath: ".routecairn-oast-lab/test.sqlite", dnsUdpPort: 5353, dnsTcpPort: 5353 });
describe("bounded authoritative DNS parser", () => {
  it("never throws or returns an unbounded answer on arbitrary input", () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 4200 }), (bytes) => { const message = Buffer.from(bytes), parsed = parseOastDnsQuery(message); if (parsed) { expect(parsed.name.length).toBeLessThanOrEqual(253); expect(answerOastDns(message, parsed, false, config).length).toBeLessThanOrEqual(512); } }), { numRuns: 1000, seed: 4604 });
  });
  it("rejects compression, missing terminators, trailing bytes and response/opcode packets", () => {
    const valid = oastDnsQuestion(config.baseDomain);
    const compressed = Buffer.concat([valid.subarray(0, 12), Buffer.from([0xc0, 12, 0, 1, 0, 1])]);
    expect(parseOastDnsQuery(compressed)).toBeUndefined(); expect(parseOastDnsQuery(valid.subarray(0, -1))).toBeUndefined(); expect(parseOastDnsQuery(Buffer.concat([valid, Buffer.from([0])]))).toBeUndefined();
    for (const flags of [0x8000, 0x0800, 0x0040]) { const message = Buffer.from(valid); message.writeUInt16BE(flags, 2); expect(parseOastDnsQuery(message)).toBeUndefined(); }
  });
  it("accepts well formed EDNS(0) without reflecting arbitrary options", () => {
    const valid = oastDnsQuestion(config.baseDomain); valid.writeUInt16BE(1, 10);
    valid.writeUInt16BE(0x0130, 2); // RD, AD and CD queries from validating resolvers.
    const opt = Buffer.from([0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    expect(parseOastDnsQuery(Buffer.concat([valid, opt]))).toBeDefined(); opt[6] = 1; expect(parseOastDnsQuery(Buffer.concat([valid, opt]))).toBeUndefined();
  });
  it("sets AA, echoes RD, clears RA and truncates large UDP RRsets for TCP retry", () => {
    const longZone = `${"a".repeat(60)}.${"b".repeat(60)}.example.test`; const expanded = { ...config, baseDomain: longZone, dnsNameServers: [`ns1.${longZone}`, `ns2.${longZone}`] };
    const query = oastDnsQuestion(longZone, 2); query.writeUInt16BE(0x0100, 2); const parsed = parseOastDnsQuery(query)!;
    const udp = answerOastDns(query, parsed, false, expanded); expect(udp.readUInt16BE(2) & 0x0780).toBe(0x0700); expect(udp.readUInt16BE(6)).toBe(0);
    const tcp = answerOastDns(query, parsed, false, expanded, true); expect(tcp.readUInt16BE(2) & 0x0780).toBe(0x0500); expect(tcp.readUInt16BE(6)).toBe(2);
  });
});
