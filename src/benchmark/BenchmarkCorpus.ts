import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, sign, verify } from "node:crypto";
import { z } from "zod";
import { benchmarkManifestSchema, type BenchmarkManifest } from "./BenchmarkSchemas.js";

const blindCaseSchema = z.object({
  blindId: z.string().regex(/^[a-f0-9]{64}$/),
  category: z.string().min(1).max(120).optional(),
  language: z.string().min(1).max(80).optional(),
  framework: z.string().min(1).max(120).optional(),
  weaknessId: z.string().min(1).max(80).optional(),
  complexity: z.enum(["SINGLE_STEP", "MULTI_STEP", "SECOND_ORDER"])
}).strict();

export const blindBenchmarkPackSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("ROUTECAIRN_BLIND_BENCHMARK_PACK"),
  public: z.object({
    benchmarkId: z.string().min(1).max(200), label: z.string().min(1).max(240), caseCount: z.number().int().positive(),
    corpusVersion: z.string().min(1).max(80).optional(), cases: z.array(blindCaseSchema).min(1).max(5000)
  }).strict(),
  sealedTruth: z.object({
    algorithm: z.literal("AES-256-GCM"), kdf: z.literal("SHA-256"), iv: z.string().min(16).max(64), authTag: z.string().min(16).max(64),
    ciphertext: z.string().min(20), manifestDigest: z.string().regex(/^[a-f0-9]{64}$/), publicDigest: z.string().regex(/^[a-f0-9]{64}$/)
  }).strict()
}).strict();

export type BlindBenchmarkPack = z.infer<typeof blindBenchmarkPackSchema>;

export function sealBenchmarkManifest(rawManifest: unknown, secret: string): BlindBenchmarkPack {
  requireSecret(secret); const parsed = benchmarkManifestSchema.parse(rawManifest);
  const cases = parsed.cases.map((item) => ({ ...item, blindId: createHmac("sha256", secret).update(`${parsed.id}\0${item.id}`).digest("hex") }));
  const manifest = benchmarkManifestSchema.parse({ ...parsed, cases, ...(parsed.corpus ? { corpus: { ...parsed.corpus, blinded: true } } : {}) });
  const publicCases = manifest.cases.map((item) => ({ blindId: item.blindId!, ...(item.category ? { category: item.category } : {}), ...(item.language ? { language: item.language } : {}), ...(item.framework ? { framework: item.framework } : {}), ...(item.weaknessId ? { weaknessId: item.weaknessId } : {}), complexity: item.complexity ?? "SINGLE_STEP" })).sort((left, right) => left.blindId.localeCompare(right.blindId));
  const publicValue = { benchmarkId: manifest.id, label: manifest.label, caseCount: manifest.cases.length, ...(manifest.corpus?.version ? { corpusVersion: manifest.corpus.version } : {}), cases: publicCases };
  const iv = randomBytes(12); const key = keyFor(secret); const cipher = createCipheriv("aes-256-gcm", key, iv); const plaintext = Buffer.from(canonicalJson(manifest));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]); const authTag = cipher.getAuthTag();
  return blindBenchmarkPackSchema.parse({ schemaVersion: 1, kind: "ROUTECAIRN_BLIND_BENCHMARK_PACK", public: publicValue, sealedTruth: { algorithm: "AES-256-GCM", kdf: "SHA-256", iv: iv.toString("base64"), authTag: authTag.toString("base64"), ciphertext: ciphertext.toString("base64"), manifestDigest: digest(manifest), publicDigest: digest(publicValue) } });
}

export function openBenchmarkPack(rawPack: unknown, secret: string): BenchmarkManifest {
  requireSecret(secret); const pack = blindBenchmarkPackSchema.parse(rawPack);
  if (digest(pack.public) !== pack.sealedTruth.publicDigest) throw new Error("BENCHMARK_BLIND_PUBLIC_DIGEST_MISMATCH");
  try {
    const decipher = createDecipheriv("aes-256-gcm", keyFor(secret), Buffer.from(pack.sealedTruth.iv, "base64")); decipher.setAuthTag(Buffer.from(pack.sealedTruth.authTag, "base64"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(pack.sealedTruth.ciphertext, "base64")), decipher.final()]).toString("utf8");
    const manifest = benchmarkManifestSchema.parse(JSON.parse(plaintext));
    if (digest(manifest) !== pack.sealedTruth.manifestDigest) throw new Error("BENCHMARK_BLIND_MANIFEST_DIGEST_MISMATCH");
    if (manifest.id !== pack.public.benchmarkId || manifest.cases.length !== pack.public.caseCount) throw new Error("BENCHMARK_BLIND_PUBLIC_TRUTH_MISMATCH");
    const publicIds = new Set(pack.public.cases.map((item) => item.blindId)); if (manifest.cases.some((item) => !item.blindId || !publicIds.has(item.blindId))) throw new Error("BENCHMARK_BLIND_CASE_MISMATCH");
    return manifest;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("BENCHMARK_")) throw error;
    throw new Error("BENCHMARK_BLIND_DECRYPTION_FAILED");
  }
}

export function signBenchmarkManifest(rawManifest: unknown, privateKeyPem: string, keyId: string): BenchmarkManifest {
  const manifest = benchmarkManifestSchema.parse(rawManifest); if (!manifest.corpus) throw new Error("BENCHMARK_CORPUS_PROVENANCE_REQUIRED");
  const { signature: _signature, ...corpus } = manifest.corpus; const unsigned = { ...manifest, corpus };
  const value = sign(null, Buffer.from(canonicalJson(unsigned)), privateKeyPem).toString("base64");
  return benchmarkManifestSchema.parse({ ...manifest, corpus: { ...manifest.corpus, signature: { algorithm: "Ed25519", keyId, value } } });
}

export function verifyBenchmarkManifest(rawManifest: unknown, publicKeyPem: string, expectedKeyId?: string): BenchmarkManifest {
  const manifest = benchmarkManifestSchema.parse(rawManifest); const signature = manifest.corpus?.signature;
  if (!manifest.corpus || !signature) throw new Error("BENCHMARK_CORPUS_SIGNATURE_REQUIRED");
  if (expectedKeyId && signature.keyId !== expectedKeyId) throw new Error("BENCHMARK_CORPUS_KEY_ID_MISMATCH");
  const { signature: _signature, ...corpus } = manifest.corpus; const unsigned = { ...manifest, corpus };
  if (!verify(null, Buffer.from(canonicalJson(unsigned)), publicKeyPem, Buffer.from(signature.value, "base64"))) throw new Error("BENCHMARK_CORPUS_SIGNATURE_INVALID");
  return manifest;
}

export function canonicalJson(value: unknown): string { return JSON.stringify(sortValue(value)); }
function sortValue(value: unknown): unknown { if (Array.isArray(value)) return value.map(sortValue); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([, entry]) => entry !== undefined).sort(([left], [right]) => left.localeCompare(right)).map(([key, entry]) => [key, sortValue(entry)])); return value; }
function digest(value: unknown): string { return createHash("sha256").update(canonicalJson(value)).digest("hex"); }
function keyFor(secret: string): Buffer { return createHash("sha256").update("routecairn-blind-benchmark-v1\0").update(secret).digest(); }
function requireSecret(secret: string): void { if (Buffer.byteLength(secret, "utf8") < 32) throw new Error("BENCHMARK_BLIND_SECRET_TOO_SHORT"); }
