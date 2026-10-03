
import type { WorkflowCapability, WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { type WorkflowValidationDiagnostic } from "./WorkflowDiagnostics";



export type BulkDraft = Extract<WorkflowDraft, { workflowId: "bulk-authorization" }>;

export type FileDraft = Extract<WorkflowDraft, { workflowId: "file-authorization" }>;

export type Actor = BulkDraft["config"]["definitions"][number]["actors"][number];

export type BulkBaseline = NonNullable<
  BulkDraft["config"]["definitions"][number]["cases"][number]["objects"][number]["baseline"]
>;

export type BulkPostcondition =
  BulkDraft["config"]["definitions"][number]["cases"][number]["postconditionChecks"][number];

export type EditableActor = {
  id: string;
  relationship: string;
  authProfile?: "account_a" | "account_b" | undefined;
  safeAlias?: string | undefined;
  principalId?: string | undefined;
  tenantId?: string | undefined;
  role?: string | undefined;
  accountState?: string | undefined;
};

export interface SharedProps {
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
}
