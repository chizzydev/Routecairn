import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import type { MutationRecoveryBundle } from "./ControlledMutationTypes.js";
import { durableAtomicWrite, GlobalMutationLock } from "./MutationJournal.js";

interface Envelope { version: 1; iv: string; tag: string; ciphertext: string }

export class MutationRecoveryVault {
  private readonly keyPath: string;
  public constructor(private readonly directory: string) { this.keyPath = join(directory, "recovery.key"); }

  public async seal<T extends { caseId: string }>(bundle: T): Promise<string> {
    if (!/^[A-Za-z0-9._-]{1,200}$/.test(bundle.caseId)) throw new Error("RECOVERY_CASE_ID_INVALID");
    const key = await this.key(true);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(`routecairn-mutation-recovery-v1:${bundle.caseId}`));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(bundle), "utf8"), cipher.final()]);
    const envelope: Envelope = { version: 1, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
    const path = join(this.directory, `${bundle.caseId}.recovery.enc`);
    await mkdir(this.directory, { recursive: true });
    await durableAtomicWrite(path, `${JSON.stringify(envelope)}\n`);
    return path;
  }

  public async open<T = MutationRecoveryBundle>(path: string, caseId: string): Promise<T> {
    const envelope = JSON.parse(await readFile(path, "utf8")) as Envelope;
    const decipher = createDecipheriv("aes-256-gcm", await this.key(), Buffer.from(envelope.iv, "base64"));
    decipher.setAAD(Buffer.from(`routecairn-mutation-recovery-v1:${caseId}`));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    const bundle = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8"));
    if (envelope.version !== 1 || bundle.caseId !== caseId) throw new Error("RECOVERY_BINDING_MISMATCH");
    return bundle as T;
  }

  public async remove(path: string): Promise<void> { await unlink(path).catch(() => undefined); }

  private async key(create = false): Promise<Buffer> {
    try {
      return decodeKey(await readFile(this.keyPath, "utf8"));
    } catch (error) {
      if (!isMissing(error)) throw error;
      if (!create) throw new Error("RECOVERY_KEY_MISSING");
    }
    const writer = new GlobalMutationLock(`${this.keyPath}.creation.lock`);
    for (let attempt = 0; ; attempt += 1) {
      try { await writer.acquire("recovery-key-creation", true); break; }
      catch (error) {
        if (!(error instanceof Error) || !error.message.startsWith("MUTATION_LOCK_HELD") || attempt >= 100) throw error;
        await new Promise((done) => setTimeout(done, 20));
      }
    }
    try {
      try { return decodeKey(await readFile(this.keyPath, "utf8")); }
      catch (error) { if (!isMissing(error)) throw error; }
      if ((await readdir(this.directory)).some((name) => name.endsWith(".recovery.enc"))) throw new Error("RECOVERY_KEY_MISSING");
      const key = randomBytes(32);
      await durableAtomicWrite(this.keyPath, `${key.toString("base64")}\n`);
      return key;
    } finally { await writer.release(); }
  }
}

function isMissing(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"; }
function decodeKey(value: string): Buffer {
  const key = Buffer.from(value.trim(), "base64");
  if (key.length !== 32) throw new Error("Mutation recovery key is invalid.");
  return key;
}
