import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

type LockPackage = { version?: string };
type PackageLock = { packages?: Record<string, LockPackage> };

const lock = JSON.parse(readFileSync(resolve("package-lock.json"), "utf8")) as PackageLock;
const packages = lock.packages ?? {};

function versionAtLeast(actual: string | undefined, minimum: string): boolean {
  if (!actual) return false;
  const left = actual.split(".").map((part) => Number.parseInt(part, 10));
  const right = minimum.split(".").map((part) => Number.parseInt(part, 10));
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference > 0;
  }
  return true;
}

describe("dependency security controls", () => {
  it("locks the remediated Vite and Vitest dependency graph", () => {
    expect(versionAtLeast(packages["node_modules/vite"]?.version, "8.3.0")).toBe(true);
    expect(versionAtLeast(packages["node_modules/vitest"]?.version, "4.1.11")).toBe(true);
    expect(versionAtLeast(packages["node_modules/@vitest/mocker"]?.version, "4.1.11")).toBe(true);

    const nanoidVersions = Object.entries(packages)
      .filter(([path]) => /(^|\/)node_modules\/nanoid$/.test(path))
      .map(([, entry]) => entry.version);
    expect(nanoidVersions.length).toBeGreaterThan(0);
    expect(nanoidVersions.every((version) => versionAtLeast(version, "3.3.18"))).toBe(true);
  });

  it("keeps audit, dependency-review, SBOM, and provenance gates wired", () => {
    const packageManifest = readFileSync(resolve("package.json"), "utf8");
    const workflow = readFileSync(resolve(".github/workflows/dependency-security.yml"), "utf8");
    const dependabot = readFileSync(resolve(".github/dependabot.yml"), "utf8");

    expect(packageManifest).toContain('"security:dependencies"');
    expect(workflow).toContain("actions/dependency-review-action@");
    expect(workflow).toContain("security:audit");
    expect(workflow).toContain("security:sbom");
    expect(workflow).toContain("actions/attest@");
    expect(workflow).toContain("sbom-path:");
    expect(workflow).toContain("Required dependency security gate");
    expect(dependabot).toContain("package-ecosystem: npm");
    expect(dependabot).toContain("package-ecosystem: github-actions");
  });
});
