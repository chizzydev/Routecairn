import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto";
import { mkdir, readFile, readdir, unlink, open, lstat } from "node:fs/promises";
import { join } from "node:path";
import type { MutationRecoveryBundle } from "./ControlledMutationTypes.js";
import { durableAtomicWrite, GlobalMutationLock } from "./MutationJournal.js";

interface Envelope { version: 1; iv: string; tag: string; ciphertext: string }

export class MutationRecoveryVault {
  private readonly keyPath: string;
  public constructor(private readonly directory: string, private readonly preserveEvidence = false) { this.keyPath = join(directory, "recovery.key"); }

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
    if (this.preserveEvidence) await this.retainPrevious(path, bundle.caseId);
    await durableAtomicWrite(path, `${JSON.stringify(envelope)}\n`);
    return path;
  }

  public async open<T = MutationRecoveryBundle>(path: string, caseId: string, expectedDigest?: string): Promise<T> {
    const bytes = await readFile(path);
    if (expectedDigest && createHash("sha256").update(bytes).digest("hex") !== expectedDigest) throw Error("RECOVERY_BUNDLE_CHANGED");
    const envelope = JSON.parse(bytes.toString("utf8")) as Envelope;
    const decipher = createDecipheriv("aes-256-gcm", await this.key(), Buffer.from(envelope.iv, "base64"));
    decipher.setAAD(Buffer.from(`routecairn-mutation-recovery-v1:${caseId}`));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    const bundle = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8"));
    if (envelope.version !== 1 || bundle.caseId !== caseId) throw new Error("RECOVERY_BINDING_MISMATCH");
    return bundle as T;
  }

  public async remove(path: string): Promise<void> { if (!this.preserveEvidence) await unlink(path).catch(() => undefined); }

  private async retainPrevious(path: string, caseId: string): Promise<void> {
    // Only an absent original permits skipping archival. Every later failure blocks replacement.
    const initial = await lstat(path, { bigint: true }).catch(error => { if (isMissing(error)) return undefined; throw error; });
    if (!initial) return;
    if (!initial.isFile() || initial.isSymbolicLink() || initial.nlink !== 1n || initial.size > 8n * 1024n * 1024n) throw Error("RECOVERY_RETENTION_SOURCE_REFUSED");
    const handle = await open(path, "r"); let previous: Buffer;
    try {
      const stat = await handle.stat({ bigint: true });
      if (stat.dev !== initial.dev || stat.ino !== initial.ino || stat.nlink !== 1n) throw Error("RECOVERY_RETENTION_SOURCE_CHANGED");
      previous = await handle.readFile();
      const end = await handle.stat({ bigint: true });
      const current = await lstat(path, { bigint: true });
      if ([end, current].some(v => v.dev !== initial.dev || v.ino !== initial.ino || v.size !== initial.size || v.mtimeNs !== initial.mtimeNs || v.ctimeNs !== initial.ctimeNs || v.nlink !== 1n)) throw Error("RECOVERY_RETENTION_SOURCE_CHANGED");
    } finally { await handle.close(); }
    const archive = join(this.directory, "retained-recovery-evidence");
    await mkdir(archive, { recursive: true });
    const parent = await lstat(archive); if (!parent.isDirectory() || parent.isSymbolicLink()) throw Error("RECOVERY_RETENTION_DIRECTORY_REFUSED");
    const name = createHash("sha256").update(caseId).digest("hex") + "." + createHash("sha256").update(previous).digest("hex") + ".enc";
    const destination = join(archive, name);
    const output = await open(destination, "wx", 0o600).catch(error => { if (error && typeof error === "object" && "code" in error && error.code === "EEXIST") return undefined; throw error; });
    if (output) { try { await output.writeFile(previous); await output.sync(); } finally { await output.close(); } }
    else {
      const existing = await lstat(destination);
      if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1 || !(await readFile(destination)).equals(previous)) throw Error("RECOVERY_RETENTION_COLLISION");
    }
  }

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
        if (!(error instanceof Error) || !error.message.startsWith("MUTATION_LOCK_HELD") || attempt >= 500) throw error;
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
