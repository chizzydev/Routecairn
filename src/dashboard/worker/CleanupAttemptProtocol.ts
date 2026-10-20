import { createHmac, timingSafeEqual } from "node:crypto";
const canonical = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === "object"
      ? Object.fromEntries(
          Object.entries(value)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => [k, canonical(v)])
        )
      : value;
export const cleanupMac = (secret: string, value: unknown) =>
  createHmac("sha256", secret)
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
export function verifyCleanupMac(secret: string, value: Record<string, unknown>) {
  const { hmac, ...body } = value;
  if (
    typeof hmac !== "string" ||
    !/^[a-f0-9]{64}$/.test(hmac) ||
    !timingSafeEqual(Buffer.from(hmac, "hex"), Buffer.from(cleanupMac(secret, body), "hex"))
  )
    throw Error("RECOVERY_RECEIPT_AUTHENTICATION_FAILED");
}
