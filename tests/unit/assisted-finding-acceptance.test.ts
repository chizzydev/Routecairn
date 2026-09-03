import { describe, expect, it } from "vitest";
import { acceptAssistedWorkflowFindings, assistedFindingModules } from "../../src/core/findings/AssistedWorkflowFindingAcceptance.js";
import { collectAssistedCases } from "../../src/modules/assistedReview/AssistedCaseCollector.js";
import { assistedFinding, lifecycleResult } from "../helpers/assisted-review.js";

describe("assisted finding acceptance", () => {
  it.each([...assistedFindingModules])("accepts %s with explicit case/evidence/review links", (module) => {
    const value = acceptAssistedWorkflowFindings({ pluginName: module, findings: [assistedFinding(module)] }).findings![0]!;
    expect(value.workflow).toMatchObject({ workflowId: module, caseId: "logout", assessmentOutcome: "PROVEN", humanReviewState: "REQUIRED", cleanupFailed: false, proofPackRefs: [], comparisonFingerprint: "a".repeat(64) });
    expect(value.workflow!.evidenceRef).toMatch(/^evidence:\/\//);
    expect(value.workflowCase).toBeUndefined();
    expect(value.customerSafeRemediation).toBe("Invalidate old sessions on logout.");
    expect(value.riskScore).toBeGreaterThan(0);
    expect(value.evidence.curlCommand).toBeUndefined();
  });

  it("rejects missing links instead of guessing from free-form notes", () => {
    const finding = assistedFinding(); delete finding.workflowCase;
    finding.evidence.source = "Case logout; cleanup verified";
    expect(() => acceptAssistedWorkflowFindings({ pluginName: "authentication-lifecycle", findings: [finding] })).toThrow("ASSISTED_FINDING_CASE_LINK_REQUIRED");
  });

  it("rejects fallback identities for contract-bound findings", () => {
    const finding = assistedFinding("supabase-authorization");
    delete finding.workflowCase!.comparisonFingerprint;
    expect(() => acceptAssistedWorkflowFindings({ pluginName: "supabase-authorization", findings: [finding] })).toThrow("ASSISTED_FINDING_CONTRACT_FINGERPRINT_REQUIRED");
  });

  it("carries Supabase runtime and catalog fingerprints into assisted review", () => {
    const cases = collectAssistedCases({ pluginName: "supabase-authorization", supabaseAuthorization: {
      observations: [{ caseId: "row", observedDecision: "ACCESS_DENIED", matchedExpectation: true, comparisonFingerprint: "b".repeat(64) }],
      staticRisks: [{ id: "rls", severity: "High", comparisonFingerprint: "c".repeat(64) }]
    } } as any);
    expect(cases).toEqual(expect.arrayContaining([
      expect.objectContaining({ caseId: "row", comparisonFingerprint: "b".repeat(64) }),
      expect.objectContaining({ caseId: "rls", comparisonFingerprint: "c".repeat(64) })
    ]));
  });

  it("redacts raw bodies and cookies, preserves structural evidence, and retains cleanup independently", () => {
    const finding = assistedFinding();
    finding.evidence = { ...finding.evidence, url: "https://app.test/session?token=very-secret", bodyPreview: "private-response", responseHeaders: { "set-cookie": "sid=raw-session", "content-type": "application/json" }, reproductionNotes: ["password=raw-password"] };
    finding.workflowCase!.cleanupOutcome = "CLEANUP_FAILED";
    const value = acceptAssistedWorkflowFindings({ pluginName: "authentication-lifecycle", findings: [finding] }).findings![0]!;
    expect(JSON.stringify(value)).not.toMatch(/very-secret|private-response|raw-session|raw-password/);
    expect(value.workflow).toMatchObject({ assessmentOutcome: "PROVEN", cleanupFailed: true, cleanupOutcome: "CLEANUP_FAILED" });
    expect(value.evidence.bodyHash).toBe("a".repeat(64));
  });

  it.each([["PASS", "PROVEN", "NO_FINDING"], ["FAIL", "PROVEN", "FINDING"], ["BLOCKED_BY_SAFETY", "BLOCKED", "UNRESOLVED"], ["INCONCLUSIVE", "INCONCLUSIVE", "UNRESOLVED"], ["UNKNOWN_NEW_RESULT", "INCONCLUSIVE", "UNRESOLVED"]])("keeps %s distinct", (outcome, assessmentOutcome, conclusion) => {
    expect(collectAssistedCases(lifecycleResult(outcome))[0]).toMatchObject({ assessmentOutcome, conclusion });
  });

  it("does not convert an inconclusive or blocked observation into proof merely because a finding is linked", () => {
    const findings = acceptAssistedWorkflowFindings({ pluginName: "authentication-lifecycle", findings: [assistedFinding()] }).findings;
    expect(collectAssistedCases(lifecycleResult("INCONCLUSIVE", "CLEANUP_REQUIRED"), findings)[0]).toMatchObject({ assessmentOutcome: "INCONCLUSIVE", cleanupFailed: true });
  });
});
