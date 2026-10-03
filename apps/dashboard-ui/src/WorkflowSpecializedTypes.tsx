
import type { WorkflowCapability, WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { type WorkflowValidationDiagnostic } from "./WorkflowDiagnostics";




export interface Props {
  workflow: WorkflowDraft;
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  onChange(workflow: WorkflowDraft): void;
}

export type Actor = {
  id: string;
  safeAlias?: string | undefined;
  authProfile?: string | undefined;
  principalId?: string | undefined;
  tenantId?: string | undefined;
  role?: string | undefined;
  accountState?: string | undefined;
  relationship?: string | undefined;
  type?: string | undefined;
};
