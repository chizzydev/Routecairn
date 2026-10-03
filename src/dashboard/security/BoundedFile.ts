import { closeSync, constants, fstatSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";

/** Validate and read the opened object, avoiding a pathname stat/read race. */
export function readBoundedFileSync(path: string, maximumBytes: number): Buffer {
  validateMaximum(maximumBytes);
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > maximumBytes) throw new Error("Unsafe file or file exceeds read limit.");
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(descriptor, buffer, length, buffer.length - length, length);
      if (!count) break;
      length += count;
    }
    if (length !== stat.size || fstatSync(descriptor).size !== length) throw new Error("File changed during bounded read.");
    return buffer.subarray(0, length);
  } finally { closeSync(descriptor); }
}

export async function readBoundedFile(path: string, maximumBytes: number): Promise<Buffer> {
  validateMaximum(maximumBytes);
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maximumBytes) throw new Error("Unsafe file or file exceeds read limit.");
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length !== stat.size || (await file.stat()).size !== length) throw new Error("File changed during bounded read.");
    return buffer.subarray(0, length);
  } finally { await file.close(); }
}

export function loadOrCreateHexKey(path: string): Buffer {
  mkdirSync(dirname(path), { recursive: true });
  const candidate = randomBytes(32);
  try { writeFileSync(path, candidate.toString("hex"), { flag: "wx", mode: 0o600 }); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  finally { candidate.fill(0); }
  const encoded = readBoundedFileSync(path, 64).toString("ascii");
  if (!/^[a-f0-9]{64}$/u.test(encoded)) throw new Error("Persistent encryption or fingerprint key must be 32 canonical hex bytes.");
  return Buffer.from(encoded, "hex");
}

function validateMaximum(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 128 * 1024 * 1024) throw new Error("Invalid bounded file read limit.");
}
