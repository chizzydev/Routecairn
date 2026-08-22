import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdir, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import type { MutationRecoveryBundle } from "./ControlledMutationTypes.js";
import { durableAtomicWrite } from "./MutationJournal.js";

interface Envelope { version: 1; iv: string; tag: string; ciphertext: string }

export class MutationRecoveryVault {
  private readonly keyPath: string;
  public constructor(private readonly directory: string) { this.keyPath = join(directory, "recovery.key"); }

  public async seal(bundle: MutationRecoveryBundle): Promise<string> {
    const key = await this.key();
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

  public async open(path: string, caseId: string): Promise<MutationRecoveryBundle> {
    const envelope = JSON.parse(await readFile(path, "utf8")) as Envelope;
    const decipher = createDecipheriv("aes-256-gcm", await this.key(), Buffer.from(envelope.iv, "base64"));
    decipher.setAAD(Buffer.from(`routecairn-mutation-recovery-v1:${caseId}`));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8")) as MutationRecoveryBundle;
  }

  public async remove(path: string): Promise<void> { await unlink(path).catch(() => undefined); }

  private async key(): Promise<Buffer> {
    try {
      const key = Buffer.from((await readFile(this.keyPath, "utf8")).trim(), "base64");
      if (key.length !== 32) throw new Error("Mutation recovery key is invalid.");
      return key;
    } catch (error) {
      if (!isMissing(error)) throw error;
      const key = randomBytes(32);
      await mkdir(this.directory, { recursive: true });
      try {
        await durableAtomicWrite(this.keyPath, `${key.toString("base64")}\n`);
        return key;
      } catch (writeError) {
        if (!isAlreadyExists(writeError)) throw writeError;
        return Buffer.from((await readFile(this.keyPath, "utf8")).trim(), "base64");
      }
    }
  }
}

function isMissing(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"; }
function isAlreadyExists(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST"; }
