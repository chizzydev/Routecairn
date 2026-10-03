import { randomBytes } from "node:crypto";
import { createSocket } from "node:dgram";
import { connect, isIP } from "node:net";
import { oastDnsQuestion } from "./OastDns.js";

export interface OastDnsAnswer { authoritative: boolean; recursionAvailable: boolean; truncated: boolean; rcode: number; nameservers: string[]; answerTypes: number[]; }
export function inspectOastDnsAnswer(response: Buffer, question: Buffer): OastDnsAnswer {
  if (response.length < question.length || response.length > 4096 || response.readUInt16BE(0) !== question.readUInt16BE(0) || (response.readUInt16BE(2) & 0xf800) !== 0x8000 || response.readUInt16BE(4) !== 1 || !response.subarray(12, question.length).equals(question.subarray(12))) throw new Error("OAST_DNS_RESPONSE_INVALID");
  const flags = response.readUInt16BE(2), nameservers: string[] = [], answerTypes: number[] = []; let offset = question.length;
  const count = response.readUInt16BE(6) + response.readUInt16BE(8) + response.readUInt16BE(10); if (count > 32) throw new Error("OAST_DNS_RESPONSE_LIMIT");
  for (let i = 0; i < count; i++) { const owner = readName(response, offset); offset = owner.end; if (offset + 10 > response.length) throw new Error("OAST_DNS_RESPONSE_INVALID"); const type = response.readUInt16BE(offset), klass = response.readUInt16BE(offset + 2), length = response.readUInt16BE(offset + 8); offset += 10; if (klass !== 1 || offset + length > response.length) throw new Error("OAST_DNS_RESPONSE_INVALID"); if (i < response.readUInt16BE(6)) { answerTypes.push(type); if (type === 2) { const name = readName(response, offset); if (name.end !== offset + length) throw new Error("OAST_DNS_RESPONSE_INVALID"); nameservers.push(name.name); } } offset += length; }
  if (offset !== response.length) throw new Error("OAST_DNS_RESPONSE_INVALID");
  return { authoritative: (flags & 0x0400) !== 0, recursionAvailable: (flags & 0x0080) !== 0, truncated: (flags & 0x0200) !== 0, rcode: flags & 15, nameservers, answerTypes };
}

export function exchangeOastDns(name: string, serverAddress: string, port = 53, tcp = false, type = 1, timeoutMs = 3000): Promise<OastDnsAnswer> {
  if (!isIP(serverAddress)) throw new Error("OAST_DNS_PINNED_ADDRESS_REQUIRED");
  const question = oastDnsQuestion(name, type, randomBytes(2).readUInt16BE());
  return new Promise((done, reject) => {
    let finished = false; let pending = Buffer.alloc(0);
    const socket = tcp ? connect(port, serverAddress) : createSocket(isIP(serverAddress) === 6 ? "udp6" : "udp4");
    const finish = (error?: Error, response?: Buffer) => { if (finished) return; finished = true; clearTimeout(timer); if (tcp) (socket as ReturnType<typeof connect>).destroy(); else { try { (socket as ReturnType<typeof createSocket>).close(); } catch { /* Already closed. */ } } if (error) reject(error); else { try { done(inspectOastDnsAnswer(response!, question)); } catch { reject(new Error("OAST_DNS_RESPONSE_INVALID")); } } };
    const timer = setTimeout(() => finish(new Error("OAST_DNS_TIMEOUT")), timeoutMs); socket.once("error", () => finish(new Error("OAST_DNS_TRANSPORT_FAILED")));
    if (tcp) { const prefix = Buffer.alloc(2); prefix.writeUInt16BE(question.length); (socket as ReturnType<typeof connect>).once("connect", () => (socket as ReturnType<typeof connect>).write(Buffer.concat([prefix, question]))); socket.on("data", (chunk: Buffer) => { pending = Buffer.concat([pending, chunk]); if (pending.length > 4098 || (pending.length >= 2 && pending.readUInt16BE(0) > 4096)) { finish(new Error("OAST_DNS_RESPONSE_LIMIT")); return; } if (pending.length >= 2 && pending.length >= pending.readUInt16BE(0) + 2) finish(undefined, pending.subarray(2, pending.readUInt16BE(0) + 2)); }); socket.once("end", () => { if (!finished) finish(new Error("OAST_DNS_RESPONSE_INCOMPLETE")); }); }
    else { (socket as ReturnType<typeof createSocket>).on("message", (response, remote) => { if (remote.port === port && remote.address === serverAddress) finish(undefined, response); }); (socket as ReturnType<typeof createSocket>).send(question, port, serverAddress); }
  });
}
function readName(message: Buffer, start: number): { name: string; end: number } { let offset = start, end = 0, jumps = 0; const labels: string[] = []; while (offset < message.length) { const size = message[offset++]!; if (size === 0) return { name: labels.join(".").toLowerCase(), end: end || offset }; if ((size & 0xc0) === 0xc0) { if (offset >= message.length || ++jumps > 16) break; const pointer = ((size & 0x3f) << 8) | message[offset++]!; if (pointer >= offset - 2) break; if (!end) end = offset; offset = pointer; continue; } if (size > 63 || offset + size > message.length) break; const label = message.subarray(offset, offset + size).toString("ascii"); if (!/^[A-Za-z0-9_-]+$/.test(label)) break; labels.push(label); if (labels.join(".").length > 253) break; offset += size; } throw new Error("OAST_DNS_NAME_INVALID"); }
