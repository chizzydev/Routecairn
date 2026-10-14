import { lstatSync, mkdirSync, mkdtempSync, realpathSync, readdirSync, rmSync } from "node:fs";
import { join, resolve, relative, sep } from "node:path";

/** Only freshly generated per-review directories may be removed. Existing owner
 * mutation journals are never selected, followed or cleaned. */
export class TrustedDiscoveryPrivateRoot {
  public readonly path: string;
  private readonly identity: { dev: number; ino: number };
  public constructor(dataDir: string) {
    const root = join(resolve(dataDir), "trusted-discovery-private");
    if (realpathSync(dataDir).toLowerCase() !== resolve(dataDir).toLowerCase() || lstatSync(dataDir).isSymbolicLink())
      throw Error("TRUSTED_DISCOVERY_PRIVATE_ROOT_INVALID");
    mkdirSync(root, { recursive: true, mode: 0o700 });
    this.check(root);
    this.path = mkdtempSync(join(root, "review-"));
    this.identity = lstatSync(this.path);
    mkdirSync(join(this.path, "output"), { mode: 0o700 });
    mkdirSync(join(this.path, "mutations"), { mode: 0o700 });
  }
  public dispose(): void {
    const current = lstatSync(this.path);
    if (current.dev !== this.identity.dev || current.ino !== this.identity.ino)
      throw Error("TRUSTED_DISCOVERY_PRIVATE_ROOT_CHANGED");
    const walk = (path: string): void => {
      this.check(path);
      for (const name of readdirSync(path)) {
        const child = join(path, name),
          rel = relative(this.path, child);
        if (!rel || rel.startsWith(".." + sep)) throw Error("TRUSTED_DISCOVERY_PRIVATE_ROOT_CHANGED");
        this.check(child);
        if (lstatSync(child).isDirectory()) walk(child);
      }
    };
    walk(this.path);
    rmSync(this.path, { recursive: true });
  }
  private check(path: string): void {
    if (lstatSync(path).isSymbolicLink() || realpathSync(path).toLowerCase() !== resolve(path).toLowerCase())
      throw Error("TRUSTED_DISCOVERY_PRIVATE_ROOT_INVALID");
  }
}
