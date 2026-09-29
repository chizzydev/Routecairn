import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";

export interface WrappedDataKey { provider: "aws-kms"; keyId: string; ciphertext: string; }
export interface EnvelopeCiphertext { version: 1; algorithm: "AES-256-GCM"; key: WrappedDataKey; iv: string; tag: string; ciphertext: string; context: Record<string, string>; }

export class KmsEnvelopeKeyManager {
  private readonly client: KMSClient;
  public constructor(private readonly keyId: string, region?: string, endpoint?: string) {
    if (!keyId.trim()) throw new Error("KMS_KEY_ID_REQUIRED");
    this.client = new KMSClient({ ...(region ? { region } : {}), ...(endpoint ? { endpoint } : {}) });
  }
  public async encrypt(plaintext: Buffer, context: Record<string, string>): Promise<EnvelopeCiphertext> {
    validateContext(context);
    const generated = await this.client.send(new GenerateDataKeyCommand({ KeyId: this.keyId, KeySpec: "AES_256", EncryptionContext: context }));
    if (!generated.Plaintext || !generated.CiphertextBlob) throw new Error("KMS_DATA_KEY_UNAVAILABLE");
    const key = Buffer.from(generated.Plaintext); const iv = randomBytes(12);
    try {
      const cipher = createCipheriv("aes-256-gcm", key, iv); cipher.setAAD(Buffer.from(canonical(context)));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return { version: 1, algorithm: "AES-256-GCM", key: { provider: "aws-kms", keyId: this.keyId, ciphertext: Buffer.from(generated.CiphertextBlob).toString("base64") }, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64"), context };
    } finally { key.fill(0); generated.Plaintext.fill(0); }
  }
  public async decrypt(envelope: EnvelopeCiphertext): Promise<Buffer> {
    if (envelope.version !== 1 || envelope.algorithm !== "AES-256-GCM" || envelope.key.provider !== "aws-kms" || envelope.key.keyId !== this.keyId) throw new Error("KMS_ENVELOPE_INVALID");
    validateContext(envelope.context);
    const decrypted = await this.client.send(new DecryptCommand({ KeyId: this.keyId, CiphertextBlob: Buffer.from(envelope.key.ciphertext, "base64"), EncryptionContext: envelope.context }));
    if (!decrypted.Plaintext) throw new Error("KMS_DECRYPTION_FAILED");
    const key = Buffer.from(decrypted.Plaintext);
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64")); decipher.setAAD(Buffer.from(canonical(envelope.context))); decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
      return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]);
    } finally { key.fill(0); decrypted.Plaintext.fill(0); }
  }
  public shutdown(): void { this.client.destroy(); }
}

export async function decryptKmsConfigurationSecret(input: { keyId: string; ciphertext: Buffer; region?: string; endpoint?: string; context?: Record<string,string> }): Promise<string> {
  if (!input.keyId.trim() || input.ciphertext.length < 32 || input.ciphertext.length > 64 * 1024) throw new Error("KMS_CONFIGURATION_SECRET_INVALID");
  if (input.context) validateContext(input.context);const client=new KMSClient({...(input.region?{region:input.region}:{}),...(input.endpoint?{endpoint:input.endpoint}:{})});
  try{const result=await client.send(new DecryptCommand({KeyId:input.keyId,CiphertextBlob:input.ciphertext,...(input.context?{EncryptionContext:input.context}:{})}));if(!result.Plaintext)throw new Error("KMS_CONFIGURATION_SECRET_UNAVAILABLE");const plaintext=Buffer.from(result.Plaintext);try{return plaintext.toString("utf8");}finally{plaintext.fill(0);result.Plaintext.fill(0);}}
  finally{client.destroy();}
}

function validateContext(context: Record<string, string>): void {
  const entries = Object.entries(context); if (entries.length < 1 || entries.length > 20) throw new Error("KMS_CONTEXT_INVALID");
  for (const [key, value] of entries) if (!/^[a-zA-Z0-9._-]{1,100}$/.test(key) || value.length < 1 || value.length > 500) throw new Error("KMS_CONTEXT_INVALID");
}
function canonical(value: Record<string, string>): string { return JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)))); }
