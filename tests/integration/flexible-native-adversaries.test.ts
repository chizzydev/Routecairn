import { it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { actorProofMatches, actorRegistryDigest } from "../../src/core/auth/ActorRegistry.js";
import { assessWorkflow } from "../../src/core/auth/AssessmentCapabilities.js";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
import type { IdentityVerificationResult } from "../../src/reports/ReportTypes.js";
it.each(["principal", "role", "tenant"] as const)(
  "native %s mismatch blocks stronger comparisons",
  async (identityMismatch) => {
    const f = await flexibleFixture(2, {
      identityMismatch,
      ...(identityMismatch === "principal" ? {} : { assurance: identityMismatch === "role" ? "ROLE" : "TENANT" })
    });
    try {
      const { report } = await f.run();
      expect(f.wire.some((w) => w.path === "/object/actor0")).toBe(false);
      expect(
        report.apiGraphql.checks
          .filter((c: { checkId: string }) => c.checkId.startsWith("compare"))
          .every((c: { outcome: string }) => c.outcome === "BLOCKED")
      ).toBe(true);
      expect(report.findings).toEqual([]);
    } finally {
      await f.close();
    }
  }
);
it.each(["ROLE", "TENANT"] as const)(
  "independent %s evidence supports the corresponding reviewed comparison",
  async (assurance) => {
    const f = await flexibleFixture(3, { assurance });
    try {
      const { report } = await f.run();
      expect(f.wire.some((w) => w.path === "/object/actor0" && w.actor === "actor1")).toBe(true);
      expect(report.apiGraphql.checks.find((c: { checkId: string }) => c.checkId === "compare-actor1").outcome).toBe(
        "PASS"
      );
      expect(report.assessmentCapabilities.actors[0][assurance === "ROLE" ? "roleVerified" : "tenantVerified"]).toBe(
        true
      );
    } finally {
      await f.close();
    }
  }
);
it("rejects two credentials for the same verified principal", async () => {
  const f = await flexibleFixture(2, { samePrincipal: true });
  try {
    const { report } = await f.run();
    expect(f.wire.some((w) => w.path === "/object/actor0")).toBe(false);
    expect(
      report.assessmentCapabilities.workflows.find((w: { workflowId: string }) => w.workflowId === "compare").reason
    ).toBe("DISTINCT_NATIVE_PRINCIPALS_REQUIRED");
  } finally {
    await f.close();
  }
});
it("does not replay an earlier native identity proof across execution, actor, registry, source, policy or credential changes", async () => {
  const f = await flexibleFixture(2);
  try {
    const { report } = await f.run(),
      proof = report.identityVerification.actors.actor0 as IdentityVerificationResult;
    expect(actorProofMatches(f.registry, "actor0", proof, ["PRINCIPAL"], proof.identityExecutionId)).toBe(true);
    for (const changed of [
      { ...proof, identityExecutionId: "different-run" },
      { ...proof, actorReference: "actor1" },
      { ...proof, actorRegistryId: "different-registry" },
      { ...proof, actorRegistryFingerprint: "b".repeat(64) },
      { ...proof, actorCredentialBinding: "b".repeat(64) }
    ])
      expect(actorProofMatches(f.registry, "actor0", changed, ["PRINCIPAL"], proof.identityExecutionId)).toBe(false);
    const registry = structuredClone(f.registry);
    registry.workflows.find((w) => w.id === "compare")!.ownerPolicySha256 = "c".repeat(64);
    expect(actorRegistryDigest(registry)).not.toBe(actorRegistryDigest(f.registry));
    expect(
      assessWorkflow(registry, "compare", report.identityVerification.actors, Date.now(), proof.identityExecutionId)
        .status
    ).toBe("NOT_ASSESSED");
    expect(actorProofMatches(f.registry, "actor0", proof, ["PRINCIPAL"])).toBe(false);
  } finally {
    await f.close();
  }
});
it.each([
  "organization",
  "target",
  "ordering",
  "key",
  "credential",
  "reference",
  "mechanism",
  "scope",
  "policy"
] as const)("refuses native %s replay before any target I/O", async (mode) => {
  const f = await flexibleFixture(2);
  try {
    const wrapper = JSON.parse(readFileSync(f.registryPath, "utf8")),
      authorization = JSON.parse(readFileSync(f.authorizationPath, "utf8"));
    switch (mode) {
      case "organization":
        wrapper.registry.organizationId = "foreign-org";
        break;
      case "target":
        wrapper.registry.targetOrigin = "http://127.0.0.1:9";
        break;
      case "ordering":
        wrapper.registry.actors.reverse();
        break;
      case "key":
        wrapper.bindingKey = "A".repeat(43);
        break;
      case "credential": {
        const path = wrapper.profiles.actor0,
          p = JSON.parse(readFileSync(path, "utf8"));
        p.headers.Authorization = "Bearer replaced-private-fixture";
        writeFileSync(path, JSON.stringify(p));
        break;
      }
      case "reference":
        wrapper.registry.actors[0].authentication.credentialRef = "different-reference";
        break;
      case "mechanism":
        wrapper.registry.actors[0].authentication.mechanism = "COOKIE";
        break;
      case "scope":
        authorization.productionCampaign.inScope = [{ origin: f.origin, pathPrefix: "/unapproved" }];
        break;
      case "policy":
        wrapper.registry.workflows.find((w: { id: string }) => w.id === "compare").ownerPolicySha256 = "d".repeat(64);
        break;
    }
    writeFileSync(f.registryPath, JSON.stringify(wrapper));
    writeFileSync(f.authorizationPath, JSON.stringify(authorization));
    await expect(f.run()).rejects.toThrow();
    expect(f.wire).toEqual([]);
  } finally {
    await f.close();
  }
});
it.each(["EXPIRED", "REVOKED", "MISSING"] as const)(
  "unavailable %s credentials block only their workflows, while public coverage continues",
  async (availability) => {
    const f = await flexibleFixture(1);
    try {
      const wrapper = JSON.parse(readFileSync(f.registryPath, "utf8"));
      wrapper.registry.actors[0].authentication.availability = availability;
      delete wrapper.profiles.actor0;
      wrapper.registry.workflows.push({
        id: "public",
        family: "PUBLIC_OBSERVATION",
        actorIds: [],
        reviewed: true,
        applicable: true
      });
      const authorization = JSON.parse(readFileSync(f.authorizationPath, "utf8"));
      authorization.productionCampaign.actorRegistryDigest = actorRegistryDigest(wrapper.registry);
      authorization.productionCampaign.workflowAuthorizations = wrapper.registry.workflows;
      writeFileSync(f.registryPath, JSON.stringify(wrapper));
      writeFileSync(f.authorizationPath, JSON.stringify(authorization));
      const { report, result } = await f.run();
      expect(result.status).toBe("COMPLETED");
      expect(f.wire.some((w) => w.path === "/")).toBe(true);
      expect(f.wire.some((w) => w.actor === "actor0")).toBe(false);
      expect(report.assessmentCapabilities.actors[0].assurance).toBe("REVOKED_OR_INVALID");
      expect(report.assessmentCapabilities.workflows[0].status).toBe("BLOCKED");
    } finally {
      await f.close();
    }
  }
);
it("native session revocation stops later cross-account requests", async () => {
  const f = await flexibleFixture(2, { revokeAfterIdentity: true });
  try {
    const { report } = await f.run();
    expect(f.wire.some((w) => w.path === "/object/actor0")).toBe(false);
    expect(
      report.assessmentCapabilities.actors.every((a: { assurance: string }) => a.assurance === "REVOKED_OR_INVALID")
    ).toBe(true);
    expect(report.findings).toEqual([]);
  } finally {
    await f.close();
  }
});
it.each(["redirect", "networkError"] as const)(
  "%s yields no security pass or unauthorized destination",
  async (mode) => {
    const f = await flexibleFixture(1, { [mode]: true });
    try {
      const { report } = await f.run();
      expect(report.findings).toEqual([]);
      expect(report.apiGraphql.checks[0].outcome).not.toBe("PASS");
      expect(f.wire.every((w) => w.path !== "/foreign")).toBe(true);
    } finally {
      await f.close();
    }
  }
);
it("cancellation retains an explicit partial outcome without a security pass", async () => {
  const f = await flexibleFixture(2);
  try {
    const c = new AbortController();
    c.abort();
    const { result, report } = await f.run(c.signal);
    expect(result.status).toBe("CANCELLED");
    expect(report.execution.partial).toBe(true);
    expect(f.wire).toEqual([]);
    expect(
      report.assessmentCapabilities.workflows.every(
        (w: { status: string }) => !["TESTED", "OBSERVED"].includes(w.status)
      )
    ).toBe(true);
  } finally {
    await f.close();
  }
});
