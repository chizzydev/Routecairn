import { createHash } from "node:crypto";

/** Preserve the legacy adaptive JSON digest; array order and undefined semantics are intentional. */
export function adaptiveExecutionFingerprint(engineId: string, sourceFingerprint: string, evidenceFingerprint: string, engineConfiguration: unknown, compilerVersion: 1 | 2): string { return adaptiveDigest({ purpose: compilerVersion === 1 ? "adaptive-read-only-execution" : "adaptive-exact-contract-execution", engineId, sourceFingerprint, evidenceFingerprint, engineConfiguration, compilerVersion }); }

export function adaptiveDigest(value: unknown): string { return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex"); }

function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a],[b]) => a.localeCompare(b)).map(([key, child]) => [key, sort(child)])); }
