// @vitest-environment jsdom
import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CredentialHealthTimeline, CredentialImpactPanel, accountPairIdentityWarnings, credentialExpiryLabel, credentialUsable, type CredentialDetailResponse, type CredentialSummary } from "./CredentialLifecycle";

describe("CredentialLifecycle dashboard controls", () => {
  it("renders explicit health, expiry, dependency impact, and safe history", () => {
    const profile = summary("HEALTHY");
    const detail: CredentialDetailResponse = {
      profile,
      dependencies: { targetDefaults: 2, configurationReferences: 3, activeScans: 1, canDelete: false, impactDigest: "a".repeat(64), targetIds: [], configurationIds: [], activeScanIds: [] },
      healthTimeline: [{ id: "event", classification: "INVALID", source: "DASHBOARD_TEST", reasonCode: "AUTHENTICATION_FAILED", safeSummary: "Target rejected the credential.", createdAt: "2026-01-01T00:00:00.000Z" }]
    };
    render(<><CredentialImpactPanel detail={detail} /><CredentialHealthTimeline events={detail.healthTimeline} /></>);
    expect(screen.getByText(/Target defaults: 2/i)).toBeTruthy();
    expect(screen.getByText(/invalidate 1 active scan/i)).toBeTruthy();
    expect(screen.getByText("AUTHENTICATION_FAILED")).toBeTruthy();
    expect(screen.getByText("INVALID")).toBeTruthy();
  });

  it("filters unsafe profiles and warns when Account A/B identity fingerprints collide", () => {
    expect(credentialUsable(summary("HEALTHY"))).toBe(true);
    expect(credentialUsable(summary("EXPIRED"))).toBe(false);
    const a = summary("HEALTHY", "same-principal");
    const b = summary("HEALTHY", "same-principal");
    expect(accountPairIdentityWarnings(a, b)).toHaveLength(2);
    expect(credentialExpiryLabel({ expiresAt: "2026-01-01T00:00:00.000Z" }, Date.parse("2026-01-02T00:00:00.000Z"))).toMatch(/^Expired/);
  });
});

function summary(classification: CredentialSummary["health"]["classification"], fingerprint = "principal-fingerprint"): CredentialSummary {
  return {
    id: crypto.randomUUID(),
    name: "Account A",
    safeAlias: "Account A",
    enabled: classification !== "DISABLED",
    credentialTypeSummary: "authorization-header, identity-verification",
    safeIdentitySummary: { principalId: "account-a" },
    expiresAt: "2027-01-01T00:00:00.000Z",
    secretVersion: 2,
    keyVersion: "1",
    health: { classification, reasonCode: classification, principalFingerprint: fingerprint },
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z"
  };
}
