import type { OastServiceConfig } from "./OastConfig.js";

export interface OastDnsQuery { name: string; type: number; questionEnd: number; recursionDesired: boolean; }

/** One IN question, optional EDNS(0), no answers or authorities. Never recurse. */
export function parseOastDnsQuery(message: Buffer): OastDnsQuery | undefined {
  if (message.length < 17 || message.length > 4096) return;
  const flags = message.readUInt16BE(2);
  if ((flags & 0xf84f) !== 0 || message.readUInt16BE(4) !== 1 || message.readUInt16BE(6) !== 0 || message.readUInt16BE(8) !== 0 || message.readUInt16BE(10) > 1) return;
  let offset = 12; const labels: string[] = []; let ended = false;
  while (offset < message.length) {
    const size = message[offset++]!;
    if (size === 0) { ended = true; break; }
    if (size > 63 || offset + size > message.length) return;
    const label = message.subarray(offset, offset + size).toString("ascii");
    if (!/^[A-Za-z0-9_-]+$/.test(label)) return;
    labels.push(label); offset += size;
    if (offset - 12 > 254) return;
  }
  if (!ended || labels.length === 0 || offset - 12 > 255 || offset + 4 > message.length || message.readUInt16BE(offset + 2) !== 1) return;
  const questionEnd = offset + 4;
  if (message.readUInt16BE(10) === 0) { if (questionEnd !== message.length) return; }
  else {
    offset = questionEnd;
    if (offset + 11 > message.length || message[offset] !== 0 || message.readUInt16BE(offset + 1) !== 41 || message[offset + 6] !== 0 || message[offset + 5] !== 0) return;
    const length = message.readUInt16BE(offset + 9); offset += 11;
    if (offset + length !== message.length) return;
    const end = offset + length;
    while (offset < end) { if (offset + 4 > end) return; const size = message.readUInt16BE(offset + 2); offset += 4 + size; if (offset > end) return; }
  }
  return { name: labels.join(".").toLowerCase(), type: message.readUInt16BE(questionEnd - 4), questionEnd, recursionDesired: (flags & 0x0100) !== 0 };
}

export function oastDnsIdentity(name: string, zone: string): { leaseId: string; signature: string } | undefined {
  const suffix = `.${zone.toLowerCase()}`; if (!name.endsWith(suffix)) return;
  const match = /^([a-f0-9]{32})\.([a-f0-9]{32})$/.exec(name.slice(0, -suffix.length));
  return match ? { leaseId: match[1]!, signature: match[2]! } : undefined;
}

export function answerOastDns(message: Buffer, parsed: OastDnsQuery, validIdentity: boolean, config: OastServiceConfig, tcp = false): Buffer {
  const zone = config.baseDomain.toLowerCase(), ns = (config.dnsNameServers ?? [`ns1.${zone}`]).map((value) => value.toLowerCase());
  const inside = parsed.name === zone || parsed.name.endsWith(`.${zone}`);
  const exists = inside && (parsed.name === zone || ns.includes(parsed.name) || validIdentity);
  const answers: Buffer[] = [], authorities: Buffer[] = [], additional: Buffer[] = [];
  const soa = () => { const numbers = Buffer.alloc(20); [config.dnsSoaSerial ?? 1, 300, 60, 86400, 30].forEach((number, index) => numbers.writeUInt32BE(number, index * 4)); return record(zone, 6, Buffer.concat([nameBytes(ns[0]!), nameBytes(`hostmaster.${zone}`), numbers])); };
  if (exists) {
    if (parsed.type === 1) answers.push(record(parsed.name, 1, Buffer.from(config.dnsAnswerIpv4.split(".").map(Number))));
    if (parsed.type === 28 && (config.publishIpv6 ?? config.mode === "SELF_HOSTED")) answers.push(record(parsed.name, 28, ipv6Bytes(config.dnsAnswerIpv6)));
    if (parsed.name === zone && parsed.type === 6) answers.push(soa());
    if (parsed.name === zone && parsed.type === 2) for (const server of ns) { answers.push(record(zone, 2, nameBytes(server))); additional.push(record(server, 1, Buffer.from(config.dnsAnswerIpv4.split(".").map(Number)))); if (config.publishIpv6 ?? config.mode === "SELF_HOSTED") additional.push(record(server, 28, ipv6Bytes(config.dnsAnswerIpv6))); }
    if (answers.length === 0) authorities.push(soa());
  } else if (inside) authorities.push(soa());
  const header = Buffer.alloc(12); message.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8000 | (inside ? 0x0400 : 0) | (parsed.recursionDesired ? 0x0100 : 0) | (!inside ? 5 : exists ? 0 : 3), 2);
  header.writeUInt16BE(1, 4); header.writeUInt16BE(answers.length, 6); header.writeUInt16BE(authorities.length, 8); header.writeUInt16BE(additional.length, 10);
  const question = message.subarray(12, parsed.questionEnd);
  const output = Buffer.concat([header, question, ...answers, ...authorities, ...additional]);
  // A conservative 512-byte UDP answer avoids fragmentation and amplification.
  if (!tcp && output.length > 512) { header.writeUInt16BE(header.readUInt16BE(2) | 0x0200, 2); header.fill(0, 6); return Buffer.concat([header, question]); }
  return output;
}

export function oastDnsQuestion(name: string, type = 1, id = 1): Buffer { const header = Buffer.alloc(12); header.writeUInt16BE(id, 0); header.writeUInt16BE(1, 4); const tail = Buffer.alloc(4); tail.writeUInt16BE(type); tail.writeUInt16BE(1, 2); return Buffer.concat([header, nameBytes(name), tail]); }
function nameBytes(name: string): Buffer { return Buffer.concat([...name.split(".").map((label) => Buffer.concat([Buffer.from([Buffer.byteLength(label)]), Buffer.from(label)])), Buffer.from([0])]); }
function record(name: string, type: number, data: Buffer): Buffer { const header = Buffer.alloc(10); header.writeUInt16BE(type); header.writeUInt16BE(1, 2); header.writeUInt32BE(30, 4); header.writeUInt16BE(data.length, 8); return Buffer.concat([nameBytes(name), header, data]); }
function ipv6Bytes(value: string): Buffer { let normalized = value; if (value.includes(".")) { const boundary = value.lastIndexOf(":"), octets = value.slice(boundary + 1).split(".").map(Number); normalized = `${value.slice(0, boundary)}:${((octets[0]! << 8) | octets[1]!).toString(16)}:${((octets[2]! << 8) | octets[3]!).toString(16)}`; } const [left, right = ""] = normalized.split("::"), a = left ? left.split(":") : [], b = right ? right.split(":") : []; const output = Buffer.alloc(16); [...a, ...Array(Math.max(0, 8 - a.length - b.length)).fill("0"), ...b].forEach((part, index) => output.writeUInt16BE(Number.parseInt(part || "0", 16), index * 2)); return output; }
