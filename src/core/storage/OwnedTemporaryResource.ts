import { randomBytes, randomUUID, createHash } from "node:crypto";
import { lstatSync, mkdirSync, realpathSync, readFileSync, writeFileSync, opendirSync } from "node:fs";
import { dirname, join, resolve, parse } from "node:path";

type Identity = { dev: string; ino: string };
function identity(path: string, directory: boolean): Identity {
  const stat = lstatSync(path, { bigint: true });
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1n) || resolve(realpathSync.native(path)).toLowerCase() !== resolve(path).toLowerCase()) throw Error("TEMP_RESOURCE_ALIAS_REFUSED");
  return { dev: String(stat.dev), ino: String(stat.ino) };
}
function same(a: Identity, b: Identity): boolean { return a.dev === b.dev && a.ino === b.ino; }
function ordinaryAncestors(path: string): Array<{ path: string; identity: Identity }> {
  const absolute = resolve(path), root = parse(absolute).root;
  const parts: string[] = []; let current = absolute;
  while (current !== root) { parts.unshift(current); current = dirname(current); }
  const result = [{ path: root, identity: identity(root, true) }];
  for (const part of parts) {
    try { lstatSync(part); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; mkdirSync(part); }
    result.push({ path: part, identity: identity(part, true) });
  }
  return result;
}

/** Retention capability, deliberately providing no deletion or adoption operation.
 * Native identities detect replacement; this is not a kernel handle sandbox against
 * a concurrent malicious writer with the same operating-system privileges. */
export class OwnedTemporaryResource {
  public readonly id = randomUUID();
  public readonly root: string;
  private readonly anchors: Array<{ path: string; identity: Identity }>;
  private readonly marker: string;
  private uncertain = false;
  private readonly children = new Map<string, Identity>();
  private constructor(container: string, public readonly binding: Readonly<Record<string, string>>) {
    this.anchors = ordinaryAncestors(container);
    this.root = join(resolve(container), this.id);
    mkdirSync(this.root);
    this.anchors.push({ path: this.root, identity: identity(this.root, true) });
    this.marker = JSON.stringify({ version: 1, id: this.id, token: randomBytes(32).toString("hex"), binding });
    writeFileSync(join(this.root, "OWNERSHIP.json"), this.marker, { flag: "wx", mode: 0o600 });
    this.children.set("OWNERSHIP.json", identity(join(this.root, "OWNERSHIP.json"), false));
    this.assertOwned();
  }
  public static create(container: string, binding: Readonly<Record<string, string>>): OwnedTemporaryResource { return new OwnedTemporaryResource(container, Object.freeze({ ...binding })); }
  public assertOwned(): void {
    if (this.uncertain) throw Error("TEMP_RESOURCE_PERMANENT_REFUSAL");
    try {
      for (const a of this.anchors) if (!same(a.identity, identity(a.path, true))) throw Error("TEMP_RESOURCE_IDENTITY_CHANGED");
      for (const [name, expected] of this.children) if (!same(expected, identity(join(this.root, name), name !== "OWNERSHIP.json"))) throw Error("TEMP_RESOURCE_IDENTITY_CHANGED");
      if (lstatSync(join(this.root, "OWNERSHIP.json")).size !== Buffer.byteLength(this.marker) || readFileSync(join(this.root, "OWNERSHIP.json"), "utf8") !== this.marker) throw Error("TEMP_RESOURCE_MARKER_CHANGED");
    } catch (error) { this.uncertain = true; throw error; }
  }
  public directory(name: string): string {
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(name)) throw Error("TEMP_RESOURCE_CHILD_INVALID");
    this.assertOwned(); const path = join(this.root, name);
    if (!this.children.has(name)) { mkdirSync(path); this.children.set(name, identity(path, true)); }
    this.assertOwned(); return path;
  }
  public receipt(): Record<string, unknown> {
    return { version: 1, resourceId: this.id, root: this.root, binding: this.binding, anchors: this.anchors, markerSha256: createHash("sha256").update(this.marker).digest("hex"), deletionAuthorized: false };
  }
  public workerProof(): { resourceId: string; markerSha256: string; rootDev: string; rootIno: string; tempDev: string; tempIno: string } {
    const temp = this.directory("tmp"); this.assertOwned();
    const rootIdentity = identity(this.root, true), tempIdentity = identity(temp, true);
    return { resourceId: this.id, markerSha256: createHash("sha256").update(this.marker).digest("hex"), rootDev: rootIdentity.dev, rootIno: rootIdentity.ino, tempDev: tempIdentity.dev, tempIno: tempIdentity.ino };
  }
  public retain(reason: string, limit = 4096): Record<string, unknown> {
    try {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 4096) throw Error("TEMP_RESOURCE_INVENTORY_LIMIT_INVALID");
      this.assertOwned();
      const pending = [this.root]; let entries = 0, bytes = 0;
      while (pending.length) {
        const path = pending.pop()!;
        const directory = opendirSync(path);
        try { for (let entry = directory.readSync(); entry; entry = directory.readSync()) {
          const name = entry.name;
          if (++entries > limit) throw Error("TEMP_RESOURCE_INVENTORY_LIMIT");
          const item = join(path, name), stat = lstatSync(item, { bigint: true });
          if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1n))) throw Error("TEMP_RESOURCE_INVENTORY_ALIAS");
          if (stat.isDirectory()) { identity(item, true); pending.push(item); }
          else bytes += Number(stat.size);
        } } finally { directory.closeSync(); }
      }
      this.assertOwned();
      const result = { ...this.receipt(), state: "RETAINED", reason, entries, bytes, inventoryComplete: true, at: new Date().toISOString() };
      writeFileSync(join(this.root, "retained-" + randomUUID() + ".json"), JSON.stringify(result, null, 2), { flag: "wx", mode: 0o600 });
      return result;
    } catch (error) {
      this.uncertain = true;
      return { ...this.receipt(), state: "UNKNOWN_RETAINED", reason, inventoryComplete: false, error: error instanceof Error ? error.message : "Inventory failed", deletionAuthorized: false };
    }
  }
}
