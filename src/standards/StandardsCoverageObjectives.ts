import type { StandardsCoverageGap, StandardsRequirementCoverage } from "./StandardsCoverageTypes.js";

export function priorityGaps(requirements: readonly StandardsRequirementCoverage[]): StandardsCoverageGap[] {
  const targets = [
    { framework: "OWASP_WSTG" as const, id: "WSTG-v42-CRYP-01", title: "Transport cryptography", priority: "HIGH" as const },
    { framework: "OWASP_WSTG" as const, id: "WSTG-v42-ERRH-01", title: "Error handling", priority: "MEDIUM" as const },
    { framework: "OWASP_WSTG" as const, id: "WSTG-v42-CLNT-01", title: "DOM client-side injection", priority: "HIGH" as const },
    { framework: "OWASP_WSTG" as const, id: "WSTG-v42-INPV-05", title: "Generalized database injection", priority: "HIGH" as const },
    { framework: "OWASP_API_TOP_10" as const, id: "API4:2023", title: "Unrestricted Resource Consumption", priority: "HIGH" as const },
    { framework: "OWASP_API_TOP_10" as const, id: "API6:2023", title: "Sensitive Business Flow Abuse", priority: "HIGH" as const },
    { framework: "OWASP_API_TOP_10" as const, id: "API10:2023", title: "Unsafe Consumption of APIs", priority: "HIGH" as const }
  ];
  return targets.flatMap<StandardsCoverageGap>((target) => {
    const item = requirements.find((entry) => entry.framework === target.framework && entry.id === target.id);
    if (!item) return [{ ...target, status: "NOT_ASSESSED", reason: "No retained executed case mapped directly to this coverage objective." }];
    if (item.directCases === 0) return [{ ...target, status: "SUPPORTING_ONLY", reason: "Only weakness or attack-pattern classification is available; no direct standards verification case was retained." }];
    if (item.findings + item.noFindings === 0) return [{ ...target, status: "INCONCLUSIVE_ONLY", reason: "Mapped cases were observed, blocked, or inconclusive and do not provide a conclusive verification result." }];
    return [];
  });
}
