import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { canonicalExecutablePlanJson, executablePlanContentDigest, parseExecutablePlanPayload, type BoundExecutablePlan, type ExecutablePlanPayload } from "./ExecutablePlanSnapshot.js";

interface StoredPlanRow {
  schema_version: number;
  target_origin: string;
  content_digest: string;
  plan_binding: string;
  nonce: string;
  ciphertext: string;
  auth_tag: string;
}

export class ExecutablePlanStore {
  private readonly key: Buffer;

  public constructor(private readonly database: DashboardDatabase, keyPath: string) {
    this.key = loadOrCreateKey(keyPath);
  }

  public save(scanId: string, targetOrigin: string, payload: ExecutablePlanPayload): BoundExecutablePlan {
    if (payload.targetOrigin !== targetOrigin) throw new Error("EXECUTABLE_PLAN_TARGET_BINDING_INVALID");
    const serialized = canonicalExecutablePlanJson(payload);
    const contentDigest = executablePlanContentDigest(payload);
    const aad = associatedData(scanId, targetOrigin, contentDigest);
    const binding = createHmac("sha256", this.key).update(aad).update("\n").update(serialized).digest("hex");
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(Buffer.from(aad));
    const ciphertext = Buffer.concat([cipher.update(serialized, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    this.database.db.prepare(`INSERT INTO scan_executable_plans
      (scan_id, schema_version, target_origin, content_digest, plan_binding, nonce, ciphertext, auth_tag, created_at)
      VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)`)
      .run(scanId, targetOrigin, contentDigest, binding, nonce.toString("base64url"), ciphertext.toString("base64url"), authTag.toString("base64url"), nowIso());
    return { payload, contentDigest, binding };
  }

  public load(scanId: string, targetOrigin: string): BoundExecutablePlan {
    const row = this.database.db.prepare("SELECT schema_version, target_origin, content_digest, plan_binding, nonce, ciphertext, auth_tag FROM scan_executable_plans WHERE scan_id = ?").get(scanId) as StoredPlanRow | undefined;
    if (!row) throw new Error("EXECUTABLE_PLAN_SNAPSHOT_MISSING");
    if (row.schema_version !== 1 || row.target_origin !== targetOrigin) throw new Error("EXECUTABLE_PLAN_TARGET_BINDING_INVALID");
    const aad = associatedData(scanId, targetOrigin, row.content_digest);
    let serialized: string;
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.key, Buffer.from(row.nonce, "base64url"));
      decipher.setAAD(Buffer.from(aad));
      decipher.setAuthTag(Buffer.from(row.auth_tag, "base64url"));
      serialized = Buffer.concat([decipher.update(Buffer.from(row.ciphertext, "base64url")), decipher.final()]).toString("utf8");
    } catch {
      throw new Error("EXECUTABLE_PLAN_SNAPSHOT_AUTHENTICATION_FAILED");
    }
    const payload = parseExecutablePlanPayload(JSON.parse(serialized));
    const contentDigest = executablePlanContentDigest(payload);
    const binding = createHmac("sha256", this.key).update(aad).update("\n").update(canonicalExecutablePlanJson(payload)).digest("hex");
    if (!constantEqual(contentDigest, row.content_digest) || !constantEqual(binding, row.plan_binding)) throw new Error("EXECUTABLE_PLAN_SNAPSHOT_CHANGED");
    return { payload, contentDigest, binding };
  }

  public markWorkerVerified(scanId: string, binding: string): void {
    const result = this.database.db.prepare("UPDATE scan_executable_plans SET worker_verified_at = ?, worker_verified_binding = ? WHERE scan_id = ? AND plan_binding = ?").run(nowIso(), binding, scanId, binding);
    if (result.changes !== 1) throw new Error("EXECUTABLE_PLAN_WORKER_BINDING_MISMATCH");
  }
}

function associatedData(scanId: string, targetOrigin: string, contentDigest: string): string {
  return `routecairn-executable-plan-store-v1\n${scanId}\n${targetOrigin}\n${contentDigest}`;
}

function loadOrCreateKey(keyPath: string): Buffer {
  mkdirSync(dirname(keyPath), { recursive: true });
  if (existsSync(keyPath)) {
    const key = Buffer.from(readFileSync(keyPath, "utf8"), "hex");
    if (key.length !== 32) throw new Error("Executable plan encryption key must be 32 bytes.");
    return key;
  }
  const key = randomBytes(32);
  writeFileSync(keyPath, key.toString("hex"), { mode: 0o600 });
  return key;
}

function constantEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
