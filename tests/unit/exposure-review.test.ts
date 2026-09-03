import { describe, expect, it } from "vitest";
import { RiskScorer } from "../../src/core/findings/RiskScorer.js";
import { hasBackupResponseEvidence, isBackupPath } from "../../src/modules/exposureReview/BackupExposureDetector.js";
import { isConfigPath } from "../../src/modules/exposureReview/ConfigExposureDetector.js";
import { isDirectoryListing } from "../../src/modules/exposureReview/DirectoryListingDetector.js";
import { SecretPatternDetector } from "../../src/modules/exposureReview/SecretPatternDetector.js";

describe("exposure review", () => {
  it("detects secret-like patterns using names and counts only", () => {
    const detector = new SecretPatternDetector();
    const matches = detector.detect("DATABASE_URL=postgres://user:pass@example/db\nAWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF");

    expect(matches).toEqual(
      expect.arrayContaining([
        { name: "DATABASE_URL", count: 1 },
        { name: "AWS_ACCESS_KEY_ID", count: 1 }
      ])
    );
    expect(JSON.stringify(matches)).not.toContain("postgres://user:pass@example/db");
    expect(JSON.stringify(matches)).not.toContain("AKIA1234567890ABCDEF");
  });

  it("does not confuse a public Supabase anon key with a service-role credential", () => {
    const detector = new SecretPatternDetector();
    const anon = jwtWithRole("anon");
    const serviceRole = jwtWithRole("service_role");

    expect(detector.detect(`API_KEY=${anon}`)).toEqual([]);
    expect(detector.detect(`API_KEY=${serviceRole}`)).toEqual([{ name: "API_KEY", count: 1 }]);
  });

  it("classifies config, backup, and directory listing evidence", () => {
    expect(isConfigPath("/.env")).toBe(true);
    expect(isConfigPath("/config.json")).toBe(true);
    expect(isBackupPath("/backup.tar.gz")).toBe(true);
    expect(isBackupPath("/database.sql")).toBe(true);
    expect(isDirectoryListing("<html><title>Index of /uploads</title><a href=\"../\">Parent Directory</a></html>")).toBe(true);
  });

  it("does not classify normal application assets or product URLs as backups", () => {
    expect(isBackupPath("/_next/static/chunks/a2a33d0bdb0a29a8.js")).toBe(false);
    expect(isBackupPath("/shop/oraimo-smart-clipper-2-goldblade-cordless-hair-clipper")).toBe(false);
    expect(hasBackupResponseEvidence({ pathname: "/backup.zip", contentType: "application/zip", bodyPreview: "PK fake archive" })).toBe(true);
    expect(hasBackupResponseEvidence({ pathname: "/backup.zip", contentType: "text/html", bodyPreview: "<html>not found</html>" })).toBe(false);
  });

  it("scores high-confidence exposure findings higher than informational findings", () => {
    const scorer = new RiskScorer();

    expect(
      scorer.score({
        severity: "High",
        confidence: "High",
        falsePositiveStatus: "likely-valid",
        tags: ["exposure", "secret-like"]
      })
    ).toBeGreaterThan(
      scorer.score({
        severity: "Informational",
        confidence: "High",
        falsePositiveStatus: "likely-valid",
        tags: []
      })
    );
  });
});

function jwtWithRole(role: "anon" | "service_role"): string {
  const encode = (value: object): string => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ role, iss: "supabase" })}.signature-material`;
}
