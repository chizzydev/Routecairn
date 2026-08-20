import { DashboardApiError } from "./api";
import type { WorkflowDraft, WorkflowId } from "./AuthorizationWorkflowStudio";
import { parseSafeFieldPath } from "../../../src/modules/fieldExposureTesting/SafeFieldPath";

export interface WorkflowValidationDiagnostic {
  workflowId: WorkflowId;
  uiCaseId?: string;
  fieldPath: string;
  code: string;
  safeMessage: string;
  severity: "error" | "warning";
  blocking: boolean;
}

export function mapWorkflowApiError(
  error: DashboardApiError,
  workflows: readonly WorkflowDraft[],
): WorkflowValidationDiagnostic[] {
  if (!error.diagnostics.length) {
    const workflow = workflowFromCoreCode(error.coreCode, workflows);
    return workflow
      ? [
          {
            workflowId: workflow.workflowId,
            fieldPath: "",
            code: error.code,
            safeMessage: safePlannerMessage(error),
            severity: "error",
            blocking: true,
          },
        ]
      : [];
  }
  return error.diagnostics.flatMap((diagnostic) => {
    const workflowIndexAt = diagnostic.path.indexOf("workflows");
    const workflowIndex =
      workflowIndexAt >= 0
        ? Number(diagnostic.path[workflowIndexAt + 1])
        : Number.NaN;
    const workflow = Number.isInteger(workflowIndex)
      ? workflows[workflowIndex]
      : undefined;
    if (!workflow) return [];
    const configAt = diagnostic.path.indexOf("config");
    const configPath = configAt >= 0 ? diagnostic.path.slice(configAt + 1) : [];
    const flatIndex = caseIndexForPath(workflow, configPath);
    return [
      {
        workflowId: workflow.workflowId,
        ...(typeof flatIndex === "number"
          ? { uiCaseId: workflow.uiCaseIds[flatIndex] }
          : {}),
        fieldPath: configPath.join("."),
        code: error.code,
        safeMessage: diagnostic.message,
        severity: "error" as const,
        blocking: true,
      },
    ];
  });
}

export function immediateWorkflowDiagnostics(
  workflow: WorkflowDraft,
): WorkflowValidationDiagnostic[] {
  const diagnostics: WorkflowValidationDiagnostic[] = [];
  const report = (
    fieldPath: string,
    code: string,
    safeMessage: string,
    uiCaseId?: string,
  ) =>
    diagnostics.push({
      workflowId: workflow.workflowId,
      ...(uiCaseId ? { uiCaseId } : {}),
      fieldPath,
      code,
      safeMessage,
      severity: "error",
      blocking: true,
    });
  for (const candidate of safeFieldCandidates(workflow)) {
    if (!candidate.value) continue;
    try {
      parseSafeFieldPath(candidate.value, {
        maxDepth: 8,
        maxArrayIndex: 50,
        code: "WORKFLOW_FIELD_PATH_INVALID",
      });
    } catch {
      diagnostics.push({
        workflowId: workflow.workflowId,
        ...(candidate.uiCaseId ? { uiCaseId: candidate.uiCaseId } : {}),
        fieldPath: candidate.path,
        code: "WORKFLOW_FIELD_PATH_INVALID",
        safeMessage:
          "Use a bounded property path such as object.owner.id. Wildcards, JSONPath, recursive traversal, and prototype keys are not supported.",
        severity: "error",
        blocking: true,
      });
    }
  }
  if (workflow.workflowId === "file-authorization")
    workflow.config.definitions.forEach((definition, definitionIndex) => {
      definition.files.forEach((file, fileIndex) => {
        if (
          /(?:^|[\\/])\.\.(?:[\\/]|$)|[\\*]|(?:range|random|uuid|increment|decrement|generator)/i.test(
            file.fileRef,
          )
        )
          report(
            `definitions.${definitionIndex}.files.${fileIndex}.fileRef`,
            "WORKFLOW_FILE_REFERENCE_UNSAFE",
            "Use one exact file reference. Traversal, wildcards, ranges, and generators are not supported.",
          );
      });
      definition.cases.forEach((item, caseIndex) => {
        const ui = workflow.uiCaseIds[caseIndex];
        if (
          item.expectedFingerprint &&
          !/^[a-f0-9]{16,128}$/i.test(item.expectedFingerprint)
        )
          report(
            `definitions.${definitionIndex}.cases.${caseIndex}.expectedFingerprint`,
            "WORKFLOW_FILE_FINGERPRINT_INVALID",
            "Enter a hexadecimal fingerprint between 16 and 128 characters.",
            ui,
          );
        for (const [key, origins] of [
          ["allowedRedirectOrigins", item.allowedRedirectOrigins],
          ["allowedSignedUrlOrigins", item.allowedSignedUrlOrigins],
        ] as const)
          origins.forEach((origin, originIndex) => {
            try {
              const parsed = new URL(origin);
              if (
                !/^https?:$/.test(parsed.protocol) ||
                parsed.username ||
                parsed.password ||
                parsed.pathname !== "/" ||
                parsed.search ||
                parsed.hash
              )
                throw new Error();
            } catch {
              report(
                `definitions.${definitionIndex}.cases.${caseIndex}.${key}.${originIndex}`,
                "WORKFLOW_FILE_ORIGIN_INVALID",
                "Enter an exact HTTP or HTTPS origin without a path, query, credentials, or fragment.",
                ui,
              );
            }
          });
        if (item.followSignedUrl && item.allowedSignedUrlOrigins.length === 0)
          report(
            `definitions.${definitionIndex}.cases.${caseIndex}.allowedSignedUrlOrigins`,
            "WORKFLOW_FILE_ORIGIN_REQUIRED",
            "Signed URL follow requires at least one exact allowed storage origin.",
            ui,
          );
      });
    });
  return diagnostics;
}

export function diagnosticFieldId(
  workflowId: WorkflowId,
  fieldPath: string,
): string {
  return `workflow-field-${workflowId}-${fieldPath.replace(/[^A-Za-z0-9_-]+/g, "-")}`;
}

function safeFieldCandidates(
  workflow: WorkflowDraft,
): Array<{ path: string; value: string; uiCaseId?: string }> {
  const output: Array<{ path: string; value: string; uiCaseId?: string }> = [];
  const add = (path: string, value: string | undefined, uiCaseId?: string) => {
    if (value !== undefined)
      output.push({ path, value, ...(uiCaseId ? { uiCaseId } : {}) });
  };
  if (workflow.workflowId === "field-exposure")
    workflow.config.cases.forEach((item, caseIndex) => {
      const ui = workflow.uiCaseIds[caseIndex];
      add(
        `cases.${caseIndex}.objectConfirmation.expectedObjectIdField`,
        item.objectConfirmation.expectedObjectIdField,
        ui,
      );
      add(
        `cases.${caseIndex}.objectConfirmation.expectedOwnerField`,
        item.objectConfirmation.expectedOwnerField,
        ui,
      );
      add(
        `cases.${caseIndex}.objectConfirmation.expectedTenantField`,
        item.objectConfirmation.expectedTenantField,
        ui,
      );
      item.fieldExpectations.forEach((field, index) =>
        add(
          `cases.${caseIndex}.fieldExpectations.${index}.path`,
          field.path,
          ui,
        ),
      );
    });
  if (workflow.workflowId === "authorization-matrix")
    workflow.config.matrices.forEach((matrix, matrixIndex) => {
      add(
        `matrices.${matrixIndex}.objectIdentityField`,
        matrix.objectIdentityField,
      );
      add(`matrices.${matrixIndex}.objectStateField`, matrix.objectStateField);
    });
  if (workflow.workflowId === "equivalent-route")
    workflow.config.routeSets.forEach((set, setIndex) => {
      add(`routeSets.${setIndex}.objectIdentityField`, set.objectIdentityField);
      add(`routeSets.${setIndex}.objectStateField`, set.objectStateField);
      set.routes.forEach((route, routeIndex) => {
        add(
          `routeSets.${setIndex}.routes.${routeIndex}.objectIdentityField`,
          route.objectIdentityField,
        );
        add(
          `routeSets.${setIndex}.routes.${routeIndex}.responseEnvelopePath`,
          route.responseEnvelopePath,
        );
        add(
          `routeSets.${setIndex}.routes.${routeIndex}.objectStateField`,
          route.objectStateField,
        );
      });
    });
  if (workflow.workflowId === "collection-authorization")
    workflow.config.collections.forEach((collection, collectionIndex) => {
      for (const [key, value] of Object.entries({
        resultArrayPath: collection.resultArrayPath,
        objectIdPath: collection.objectIdPath,
        objectTenantPath: collection.objectTenantPath,
        objectOwnerPath: collection.objectOwnerPath,
        objectStatePath: collection.objectStatePath,
        objectTypePath: collection.objectTypePath,
      }))
        add(`collections.${collectionIndex}.${key}`, value);
      collection.cases.forEach((item, caseIndex) => {
        const ui = workflow.uiCaseIds[caseIndex];
        if (item.countExpectation)
          add(
            `collections.${collectionIndex}.cases.${caseIndex}.countExpectation.path`,
            item.countExpectation.path,
            ui,
          );
        item.summaryExpectations.forEach((summary, index) =>
          add(
            `collections.${collectionIndex}.cases.${caseIndex}.summaryExpectations.${index}.path`,
            summary.path,
            ui,
          ),
        );
      });
    });
  if (workflow.workflowId === "bulk-authorization")
    workflow.config.definitions.forEach((definition, definitionIndex) =>
      definition.cases.forEach((item, caseIndex) => {
        const ui = workflow.uiCaseIds[caseIndex];
        for (const [key, value] of Object.entries({
          requiredRequestMarkerPath:
            item.safetyContract.requiredRequestMarkerPath,
          requiredResponseMarkerPath:
            item.safetyContract.requiredResponseMarkerPath,
        }))
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.safetyContract.${key}`,
            value,
            ui,
          );
        item.safetyContract.disallowedResponsePaths.forEach((value, index) =>
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.safetyContract.disallowedResponsePaths.${index}`,
            value,
            ui,
          ),
        );
        for (const [key, value] of Object.entries({
          resultArrayPath: item.responseContract.resultArrayPath,
          resultObjectIdPath: item.responseContract.resultObjectIdPath,
          perObjectDecisionPath: item.responseContract.perObjectDecisionPath,
          rejectedArrayPath: item.responseContract.rejectedArrayPath,
          rejectedObjectIdPath: item.responseContract.rejectedObjectIdPath,
          overallDecisionPath: item.responseContract.overallDecisionPath,
          previewCountPath: item.responseContract.previewCountPath,
        }))
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.responseContract.${key}`,
            value,
            ui,
          );
        item.responseContract.metadataPaths.forEach((value, index) =>
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.responseContract.metadataPaths.${index}`,
            value,
            ui,
          ),
        );
        item.objects.forEach((object, objectIndex) => {
          if (!object.baseline) return;
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.objects.${objectIndex}.baseline.objectIdentityField`,
            object.baseline.objectIdentityField,
            ui,
          );
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.objects.${objectIndex}.baseline.objectStateField`,
            object.baseline.objectStateField,
            ui,
          );
        });
        item.postconditionChecks.forEach((check, checkIndex) => {
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.postconditionChecks.${checkIndex}.objectIdentityField`,
            check.objectIdentityField,
            ui,
          );
          add(
            `definitions.${definitionIndex}.cases.${caseIndex}.postconditionChecks.${checkIndex}.objectStateField`,
            check.objectStateField,
            ui,
          );
          check.fields.forEach((field, fieldIndex) =>
            add(
              `definitions.${definitionIndex}.cases.${caseIndex}.postconditionChecks.${checkIndex}.fields.${fieldIndex}.path`,
              field.path,
              ui,
            ),
          );
        });
      }),
    );
  if (workflow.workflowId === "file-authorization")
    workflow.config.definitions.forEach((definition, definitionIndex) =>
      definition.cases.forEach((item, caseIndex) => {
        const ui = workflow.uiCaseIds[caseIndex];
        add(
          `definitions.${definitionIndex}.cases.${caseIndex}.identityField`,
          item.identityField,
          ui,
        );
        add(
          `definitions.${definitionIndex}.cases.${caseIndex}.stateField`,
          item.stateField,
          ui,
        );
        add(
          `definitions.${definitionIndex}.cases.${caseIndex}.signedUrlField`,
          item.signedUrlField,
          ui,
        );
      }),
    );
  return output;
}

function caseIndexForPath(
  workflow: WorkflowDraft,
  path: readonly string[],
): number | undefined {
  const indexAfter = (key: string): number | undefined => {
    const at = path.indexOf(key);
    const value = at >= 0 ? Number(path[at + 1]) : Number.NaN;
    return Number.isInteger(value) ? value : undefined;
  };
  if (
    workflow.workflowId === "object-pair" ||
    workflow.workflowId === "field-exposure"
  )
    return indexAfter("cases");
  const groupKey =
    workflow.workflowId === "authorization-matrix"
      ? "matrices"
      : workflow.workflowId === "equivalent-route"
        ? "routeSets"
        : workflow.workflowId === "collection-authorization"
          ? "collections"
          : "definitions";
  const caseKey =
    workflow.workflowId === "equivalent-route" ? "routes" : "cases";
  const groupIndex = indexAfter(groupKey);
  const localIndex = indexAfter(caseKey);
  if (groupIndex === undefined || localIndex === undefined) return undefined;
  let offset = 0;
  if (workflow.workflowId === "authorization-matrix")
    for (let index = 0; index < groupIndex; index += 1)
      offset += workflow.config.matrices[index]?.cases.length ?? 0;
  if (workflow.workflowId === "equivalent-route")
    for (let index = 0; index < groupIndex; index += 1)
      offset += workflow.config.routeSets[index]?.routes.length ?? 0;
  if (workflow.workflowId === "collection-authorization")
    for (let index = 0; index < groupIndex; index += 1)
      offset += workflow.config.collections[index]?.cases.length ?? 0;
  if (workflow.workflowId === "bulk-authorization")
    for (let index = 0; index < groupIndex; index += 1)
      offset += workflow.config.definitions[index]?.cases.length ?? 0;
  if (workflow.workflowId === "file-authorization")
    for (let index = 0; index < groupIndex; index += 1)
      offset += workflow.config.definitions[index]?.cases.length ?? 0;
  return offset + localIndex;
}

function workflowFromCoreCode(
  code: string | undefined,
  workflows: readonly WorkflowDraft[],
): WorkflowDraft | undefined {
  const prefix = code?.split("_").slice(0, 2).join("_").toLowerCase();
  return workflows.find((workflow) =>
    workflow.workflowId.replace(/-/g, "_").startsWith(prefix ?? ""),
  );
}

function safePlannerMessage(error: DashboardApiError): string {
  if (error.code === "WORKFLOW_ACTOR_MISSING")
    return "The selected actor or authentication context is unavailable for this workflow.";
  if (error.code === "WORKFLOW_IDENTITY_REQUIRED")
    return "Verified identity metadata is required for this workflow.";
  if (error.code === "WORKFLOW_COMPLETENESS_INVALID")
    return "The selected completeness or reference configuration is incompatible.";
  if (error.code === "WORKFLOW_METHOD_UNSAFE")
    return "The selected method or safety contract is not permitted.";
  if (error.code === "WORKFLOW_FILE_ORIGIN_INVALID")
    return "The signed URL or redirect origin is not explicitly approved.";
  return "The authoritative planner rejected this workflow configuration. Review the highlighted workflow fields.";
}
