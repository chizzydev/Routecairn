import argon2 from "argon2";

export const passwordPolicy = {
  minLength: 12,
  maxLength: 256,
  argon2: {
    type: "argon2id",
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  }
} as const;

const trivialPasswords = new Set(["password", "password123", "routecairn", "adminpassword", "letmein123456"]);

export function validatePasswordPolicy(password: string): void {
  if (password.length < passwordPolicy.minLength) throw new Error(`Password must be at least ${passwordPolicy.minLength} characters.`);
  if (password.length > passwordPolicy.maxLength) throw new Error(`Password must be at most ${passwordPolicy.maxLength} characters.`);
  if (trivialPasswords.has(password.trim().toLowerCase())) throw new Error("Password is too common.");
}

export async function hashPassword(password: string): Promise<string> {
  validatePasswordPolicy(password);
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: passwordPolicy.argon2.memoryCost,
    timeCost: passwordPolicy.argon2.timeCost,
    parallelism: passwordPolicy.argon2.parallelism
  });
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  return argon2.verify(hash, password);
}

export function needsPasswordRehash(hash: string): boolean {
  return argon2.needsRehash(hash, {
    memoryCost: passwordPolicy.argon2.memoryCost,
    timeCost: passwordPolicy.argon2.timeCost,
    parallelism: passwordPolicy.argon2.parallelism
  });
}
