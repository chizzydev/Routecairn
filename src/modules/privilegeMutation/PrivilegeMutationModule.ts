import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { PrivilegeMutationObservation, PrivilegeMutationReport } from "../../reports/PrivilegeMutationReport.js";
import type { PrivilegeMutationCasePlan } from "./PrivilegeMutationPlanner.js";
import { ControlledMutationExecutor } from "../../core/offensive/ControlledMutationExecutor.js";
import { createHash } from "node:crypto";

export class PrivilegeMutationModule implements RouteCairnPlugin {
  public readonly name = "privilege-mutation-testing";
  public readonly description = "Executes explicitly authorized privilege and mass-assignment mutation cases with verified cleanup.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const plan = context.options.plan.privilegeMutationTesting;
    const report = plan ? await execute(context, plan.cases) : disabledReport();
    return { pluginName: this.name, privilegeMutation: report, notes: report.notes };
  }
}

async function execute(_context: ScanContext, cases: readonly PrivilegeMutationCasePlan[]): Promise<PrivilegeMutationReport> {
  const contracts = new Map((_context.options.controlledMutationContracts ?? []).map((contract) => [contract.caseId, contract]));
  const observations: PrivilegeMutationObservation[] = [];
  for (const item of cases) {
    const contract = contracts.get(item.caseId);
    if (!contract) {
      observations.push({
    caseId: item.caseId,
    category: item.category,
    actorLabel: item.actor.label,
    targetAlias: item.target.alias,
    attackMethod: item.attack.method,
    attackEndpoint: redactEndpoint(item.attack.url),
    authorityField: item.attack.field,
    securityOutcome: "INCONCLUSIVE",
    cleanupOutcome: "NOT_REQUIRED",
    requestTransmitted: false,
    targetIdentityVerified: false,
    originalAuthorityVerified: false,
    authorityChangeVerified: false,
    protectedActionVerified: false,
    comparisonIdentity: "",
    notes: ["Mutation execution requires a dashboard-approved, expiring controlled-mutation contract; no implicit network mutation was generated from the planner summary."],
        result: { caseId: item.caseId, outcome: "INCONCLUSIVE", securityOutcome: "INCONCLUSIVE", cleanupOutcome: "NOT_REQUIRED", journalPath: "", comparisonIdentity: "", notes: [] }
      });
      continue;
    }
    if (!contractMatchesPlan(contract, item)) {
      observations.push({ caseId: item.caseId, category: item.category, actorLabel: item.actor.label, targetAlias: item.target.alias, attackMethod: item.attack.method, attackEndpoint: redactEndpoint(item.attack.url), authorityField: item.attack.field, securityOutcome: "BLOCKED_BY_SAFETY", cleanupOutcome: "NOT_REQUIRED", requestTransmitted: false, targetIdentityVerified: false, originalAuthorityVerified: false, authorityChangeVerified: false, protectedActionVerified: false, comparisonIdentity: "", notes: ["Approved mutation contract did not match the planned semantic case; no request was sent."], result: { caseId: item.caseId, outcome: "BLOCKED_BY_SAFETY", securityOutcome: "BLOCKED_BY_SAFETY", cleanupOutcome: "NOT_REQUIRED", journalPath: "", comparisonIdentity: "", notes: [] } });
      continue;
    }
    const result = await new ControlledMutationExecutor(_context.createControlledMutationHttpClient(), { journalDirectory: _context.options.outputDir }).execute(contract);
    const proven = result.securityOutcome === "EXPLOIT_PROVEN";
    const securityOutcome: PrivilegeMutationObservation["securityOutcome"] = proven ? categoryOutcome(item.category) : result.securityOutcome === "SECURE_FOR_CASE" ? "MUTATION_REJECTED" : result.securityOutcome === "BLOCKED_BY_SAFETY" ? "BLOCKED_BY_SAFETY" : "INCONCLUSIVE";
    observations.push({ caseId: item.caseId, category: item.category, actorLabel: item.actor.label, targetAlias: item.target.alias, attackMethod: item.attack.method, attackEndpoint: redactEndpoint(item.attack.url), authorityField: item.attack.field, securityOutcome, cleanupOutcome: result.cleanupOutcome, requestTransmitted: Boolean(result.attackResponseHash), targetIdentityVerified: result.securityOutcome !== "BLOCKED_BY_SAFETY", originalAuthorityVerified: Boolean(result.preStateHash), authorityChangeVerified: proven, protectedActionVerified: false, comparisonIdentity: result.comparisonIdentity, notes: result.notes, result });
  }
  return { enabled: true, plannedCases: cases.length, executedCases: observations.filter((item) => item.requestTransmitted).length, provenFindings: observations.filter((item) => item.securityOutcome.endsWith("PROVEN")).length, cleanupRequired: observations.filter((item) => item.cleanupOutcome !== "ROLLBACK_VERIFIED" && item.cleanupOutcome !== "NOT_REQUIRED").length, observations, notes: ["Only exact worker-bound contracts were eligible for transmission.", "Cleanup status remains independent from security outcome."] };
}

function disabledReport(): PrivilegeMutationReport { return { enabled: false, plannedCases: 0, executedCases: 0, provenFindings: 0, cleanupRequired: 0, observations: [], notes: ["Privilege mutation testing was not selected."] }; }
function redactEndpoint(value: string): string { const url = new URL(value); return `${url.origin}${url.pathname}`; }
function categoryOutcome(category: PrivilegeMutationCasePlan["category"]): PrivilegeMutationObservation["securityOutcome"] { return category === "PRIVILEGE_ESCALATION" ? "PRIVILEGE_ESCALATION_PROVEN" : category === "MASS_ASSIGNMENT" ? "MASS_ASSIGNMENT_PROVEN" : category === "CROSS_TENANT_REASSIGNMENT" ? "CROSS_TENANT_REASSIGNMENT_PROVEN" : category === "OWNERSHIP_TAKEOVER" ? "OWNERSHIP_TAKEOVER_PROVEN" : "ADMINISTRATIVE_BOUNDARY_BYPASS_PROVEN"; }
function contractMatchesPlan(contract: import("../../core/offensive/ControlledMutationTypes.js").ControlledMutationContract, plan: PrivilegeMutationCasePlan): boolean {
  if (contract.caseId !== plan.caseId || contract.attack.request.url !== plan.attack.url || contract.attack.request.method !== plan.attack.method || contract.rollback.request.url !== plan.rollback.request.url || contract.rollback.request.method !== plan.rollback.request.method) return false;
  try {
    if (typeof contract.attack.request.body !== "string") return false;
    const body = JSON.parse(contract.attack.request.body) as Record<string, unknown>;
    const value = body[plan.attack.field];
    return Object.keys(body).length === 1 && Object.prototype.hasOwnProperty.call(body, plan.attack.field) && createHash("sha256").update(JSON.stringify(value ?? null)).digest("hex") === plan.attack.valueHash;
  } catch { return false; }
}
