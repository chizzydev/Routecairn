// @vitest-environment jsdom
import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { EvidenceViewerRegistry, type EvidenceRecord } from "../../apps/dashboard-ui/src/EvidenceViewers.js";

afterEach(cleanup);

describe("semantic evidence viewers", () => {
  it.each([
    ["object-pair", { actor: "Account A", object: "Object B", expected: "Denied", observed: "Allowed", mismatch: true }, "Object ownership relationship"],
    ["field-exposure", { fieldPath: "profile.ssn", fingerprint: "sha256:safe", expected: "hidden", actual: "present" }, "Field exposure"],
    ["authorization-matrix", { rows: [{ actor: "Analyst", role: "user", expected: "Denied", observed: "Allowed" }] }, "Executed authorization matrix"],
    ["equivalent-route", { referenceRoute: "/v1/item", candidateRoute: "/v2/item", referenceResult: 403, candidateResult: 200 }, "Equivalent route comparison"],
    ["collection-authorization", { endpoint: "/items", completeness: "PARTIAL", observedMembership: false }, "Collection authorization"],
    ["bulk-authorization", { safetyMode: "NON_MUTATING", objectSet: ["one", "two"], precondition: "same", postcondition: "same" }, "Bulk authorization"],
    ["file-download", { proofMode: "PREFIX", bytesRead: 1024, signedUrlIssued: true, signedUrlFollowed: false }, "File and download authorization"],
    ["identity-verification", { actor: "Account A", verificationState: "VERIFIED", principalComparison: "different" }, "Verified identity"],
    ["HTTP", { method: "GET", normalizedUrl: "https://app.test/items/:id", status: 200, authorization: "raw-secret-must-not-render" }, "HTTP evidence"]
  ])("renders %s semantically without unrelated raw fields", (type, data, heading) => {
    render(<EvidenceViewerRegistry evidence={evidence(type, data)} />);
    expect(screen.getByText(heading)).toBeTruthy();
    expect(document.body.textContent).not.toContain("raw-secret-must-not-render");
  });

  it("shows completeness and bounded-side-effect limitations", () => {
    const { rerender } = render(<EvidenceViewerRegistry evidence={evidence("collection-listing", { completeness: "PARTIAL" })} />);
    expect(screen.getByText(/absence is not conclusive/i)).toBeTruthy();
    rerender(<EvidenceViewerRegistry evidence={evidence("bulk", { stateFields: ["status"] })} />);
    expect(screen.getByText(/does not prove absence of all possible side effects/i)).toBeTruthy();
  });

  it("uses a safe fallback and image artifact UUID routes", () => {
    const { rerender } = render(<EvidenceViewerRegistry evidence={evidence("future-safe-type", { value: "<script>alert(1)</script>" })} />);
    expect(screen.getByText(/no specialized viewer/i)).toBeTruthy();
    expect(document.querySelector("script")).toBeNull();
    rerender(<EvidenceViewerRegistry evidence={{ ...evidence("browser-screenshot", { pageUrl: "https://app.test" }), artifact_id: "11111111-1111-4111-8111-111111111111" }} />);
    expect(screen.getByRole("img").getAttribute("src")).toBe("/api/artifacts/11111111-1111-4111-8111-111111111111/preview");
    expect(screen.getByText("Browser observation")).toBeTruthy();
    expect(screen.queryByText(/no specialized viewer/i)).toBeNull();
  });

  it("renders safe sensitive-value attestations while ignoring unrecognized raw fields", () => {
    const fingerprint = `hmac-sha256:${"a".repeat(64)}`;
    render(<EvidenceViewerRegistry evidence={evidence("HTTP", {
      method: "GET",
      normalizedUrl: "https://app.test/items/:id",
      status: 200,
      valueAttestations: [{
        schemaVersion: 1,
        location: "header",
        name: "Authorization",
        classification: "bearer-token",
        valueLength: 31,
        fingerprintAlgorithm: "HMAC-SHA-256",
        fingerprintScope: "scan",
        correlationFingerprint: fingerprint,
        observedAt: "2026-08-19T08:00:00.000Z",
        requestId: "11111111-1111-4111-8111-111111111111",
        statusCode: 200,
        responseHash: "b".repeat(64),
        transportOutcome: "transmitted",
        reproductionSteps: ["Send the authorized GET request with the same authentication context."],
        rawValue: "ui-decoy-secret-must-not-render"
      }]
    })} />);

    expect(screen.getByText("Sensitive value presence attestations")).toBeTruthy();
    expect(screen.getByText(fingerprint)).toBeTruthy();
    expect(screen.getByText(/raw values are intentionally excluded/i)).toBeTruthy();
    expect(document.body.textContent).not.toContain("ui-decoy-secret-must-not-render");
  });
});

function evidence(type: string, data: Record<string, unknown>): EvidenceRecord {
  return { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", finding_occurrence_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", evidence_type: type, evidence_level: "normal", safe_summary: "Safe summary", safe_structured_data_json: JSON.stringify(data) };
}
