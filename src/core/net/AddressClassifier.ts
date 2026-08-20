import { isIP } from "node:net";

export function normalizeIpLiteral(hostname: string): string | undefined {
  const unbracketed = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (isIP(unbracketed)) {
    return unbracketed;
  }

  if (/^0x[0-9a-f]+$/i.test(unbracketed)) {
    const parsed = Number.parseInt(unbracketed.slice(2), 16);
    return Number.isFinite(parsed) ? intToIpv4(parsed) : undefined;
  }

  if (/^\d+$/.test(unbracketed)) {
    const parsed = Number.parseInt(unbracketed, 10);
    return Number.isFinite(parsed) ? intToIpv4(parsed) : undefined;
  }

  const parts = unbracketed.split(".");
  if (parts.length === 4 && parts.every((part) => /^0[0-7]+$/.test(part))) {
    return parts.map((part) => Number.parseInt(part, 8)).join(".");
  }

  return undefined;
}

export function isProhibitedAddress(address: string): boolean {
  const normalized = normalizeIpLiteral(address) ?? address;
  if (normalized.includes(":")) {
    const value = normalized.toLowerCase();
    return value === "::1" || value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80:") || value === "::" || value.startsWith("::ffff:127.") || value.startsWith("::ffff:10.") || value.startsWith("::ffff:192.168.");
  }

  const octets = normalized.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false;
  }

  const [first, second] = octets as [number, number, number, number];
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 100 && second >= 64 && second <= 127)
  );
}

function intToIpv4(value: number): string | undefined {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    return undefined;
  }
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}
