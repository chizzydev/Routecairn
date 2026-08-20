import React, { useEffect, useMemo, useRef, useState } from "react";
import type { ObjectPairInput } from "../../../src/modules/objectPairTesting/ObjectPairPlanner";
import type { FieldExposureInput } from "../../../src/modules/fieldExposureTesting/FieldExposurePlanner";
import type { AuthorizationMatrixInput } from "../../../src/modules/authorizationMatrix/AuthorizationMatrixPlanner";
import type { EquivalentRouteInput } from "../../../src/modules/equivalentRouteTesting/EquivalentRoutePlanner";
import type { CollectionAuthorizationInput } from "../../../src/modules/collectionAuthorization/CollectionAuthorizationPlanner";
import type { BulkAuthorizationInput } from "../../../src/modules/bulkAuthorization/BulkAuthorizationPlanner";
import type { FileAuthorizationInput } from "../../../src/modules/fileAuthorization/FileAuthorizationPlanner";
import type { AuthorizationWorkflowConfiguration } from "../../../src/dashboard/contracts/ScanStudioSchemas";
import {
  diagnosticFieldId,
  immediateWorkflowDiagnostics,
  type WorkflowValidationDiagnostic,
} from "./WorkflowDiagnostics";
import { SpecializedWorkflowEditor } from "./WorkflowSpecializedEditors";

export type WorkflowId =
  | "object-pair"
  | "field-exposure"
  | "authorization-matrix"
  | "equivalent-route"
  | "collection-authorization"
  | "bulk-authorization"
  | "file-authorization";
export type WorkflowCoreInput =
  | ObjectPairInput
  | FieldExposureInput
  | AuthorizationMatrixInput
  | EquivalentRouteInput
  | CollectionAuthorizationInput
  | BulkAuthorizationInput
  | FileAuthorizationInput;
export type WorkflowDraft =
  | {
      workflowId: "object-pair";
      enabled: boolean;
      editorMode: "guided" | "advanced";
      disabledCaseIds: string[];
      uiCaseIds: string[];
      config: ObjectPairInput;
    }
  | {
      workflowId: "field-exposure";
      enabled: boolean;
      editorMode: "guided" | "advanced";
      disabledCaseIds: string[];
      uiCaseIds: string[];
      config: FieldExposureInput;
    }
  | {
      workflowId: "authorization-matrix";
      enabled: boolean;
      editorMode: "guided" | "advanced";
      disabledCaseIds: string[];
      uiCaseIds: string[];
      config: AuthorizationMatrixInput;
    }
  | {
      workflowId: "equivalent-route";
      enabled: boolean;
      editorMode: "guided" | "advanced";
      disabledCaseIds: string[];
      uiCaseIds: string[];
      config: EquivalentRouteInput;
    }
  | {
      workflowId: "collection-authorization";
      enabled: boolean;
      editorMode: "guided" | "advanced";
      disabledCaseIds: string[];
      uiCaseIds: string[];
      config: CollectionAuthorizationInput;
    }
  | {
      workflowId: "bulk-authorization";
      enabled: boolean;
      editorMode: "guided" | "advanced";
      disabledCaseIds: string[];
      uiCaseIds: string[];
      config: BulkAuthorizationInput;
    }
  | {
      workflowId: "file-authorization";
      enabled: boolean;
      editorMode: "guided" | "advanced";
      disabledCaseIds: string[];
      uiCaseIds: string[];
      config: FileAuthorizationInput;
    };

export interface WorkflowCapability {
  id: WorkflowId;
  displayName: string;
  description: string;
  moduleId: string;
  requiresAccountPair: boolean;
  requiresVerifiedIdentity: boolean;
  safeMethods: string[];
  supportedActors: string[];
  expectationTypes: string[];
  guidedOptions: Record<string, string[]>;
  guidedFieldCoverage: string[];
  advancedOnlyFields: string[];
  limits: Record<string, number>;
  safetyNotes: string[];
}

interface Props {
  workflows: WorkflowDraft[];
  diagnostics?: WorkflowValidationDiagnostic[];
  capabilities: WorkflowCapability[];
  selectedModules: string[];
  target: string;
  principalA: string;
  principalB: string;
  onChange(workflows: WorkflowDraft[]): void;
  onEnableModule(moduleId: string): void;
  onPreview(): Promise<void>;
}

const maxJsonBytes = 256 * 1024;
const prohibitedKey = /^(?:__proto__|prototype|constructor)$/;
const unsafeExactValue =
  /(?:\*|\.\.|\b(?:range|random|generate|increment|uuid)\b|\$\(|<%)/i;

export function AuthorizationWorkflowStudio(props: Props) {
  const [openId, setOpenId] = useState<WorkflowId>();
  const active = props.workflows.find((item) => item.workflowId === openId);
  const capability = props.capabilities.find((item) => item.id === openId);
  const setWorkflow = (next: WorkflowDraft) =>
    props.onChange(
      props.workflows.map((item) =>
        item.workflowId === next.workflowId ? next : item,
      ),
    );
  const enable = (metadata: WorkflowCapability) => {
    const existing = props.workflows.find(
      (item) => item.workflowId === metadata.id,
    );
    if (existing)
      props.onChange(
        props.workflows.map((item) =>
          item.workflowId === metadata.id ? { ...item, enabled: true } : item,
        ),
      );
    else
      props.onChange([
        ...props.workflows,
        createWorkflow(
          metadata.id,
          props.target,
          props.principalA,
          props.principalB,
        ),
      ]);
    setOpenId(metadata.id);
  };
  return (
    <div className="workflow-studio">
      <div className="workflow-catalog" aria-label="Authorization workflows">
        {props.capabilities.map((metadata) => {
          const draft = props.workflows.find(
            (item) => item.workflowId === metadata.id,
          );
          const count = draft ? workflowCaseCount(draft) : 0;
          const diagnostics = draft
            ? [
                ...immediateWorkflowDiagnostics(draft),
                ...(props.diagnostics ?? []).filter(
                  (item) => item.workflowId === draft.workflowId,
                ),
              ]
            : [];
          const moduleEnabled = props.selectedModules.includes(
            metadata.moduleId,
          );
          return (
            <section
              className={`workflow-card ${draft?.enabled ? "enabled" : ""}`}
              key={metadata.id}
            >
              <div>
                <h4>{metadata.displayName}</h4>
                <p>{metadata.description}</p>
              </div>
              <dl>
                <dt>Status</dt>
                <dd>
                  {draft?.enabled
                    ? diagnostics.length
                      ? `Invalid - ${diagnostics.length} issue(s)`
                      : "Configured"
                    : "Not configured"}
                </dd>
                <dt>Cases</dt>
                <dd>{count}</dd>
                <dt>Module</dt>
                <dd>
                  {moduleEnabled
                    ? metadata.moduleId
                    : `${metadata.moduleId} disabled`}
                </dd>
                <dt>Actors</dt>
                <dd>
                  {metadata.requiresAccountPair
                    ? "Account A and B"
                    : "Configured actors"}
                </dd>
              </dl>
              <p className="safety-note">{metadata.safetyNotes[0]}</p>
              <div className="workflow-actions">
                {draft?.enabled ? (
                  <>
                    <button
                      type="button"
                      onClick={() => setOpenId(metadata.id)}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => setWorkflow({ ...draft, enabled: false })}
                    >
                      Disable
                    </button>
                  </>
                ) : (
                  <button type="button" onClick={() => enable(metadata)}>
                    Enable and add first case
                  </button>
                )}
                {draft && (
                  <button
                    type="button"
                    onClick={() => {
                      if (window.confirm(`Clear ${metadata.displayName}?`))
                        props.onChange(
                          props.workflows.filter(
                            (item) => item.workflowId !== metadata.id,
                          ),
                        );
                    }}
                  >
                    Clear
                  </button>
                )}
                {draft?.enabled && !moduleEnabled && (
                  <button
                    type="button"
                    onClick={() => props.onEnableModule(metadata.moduleId)}
                  >
                    Enable required module
                  </button>
                )}
              </div>
            </section>
          );
        })}
      </div>
      {active && capability && (
        <WorkflowEditor
          workflow={active}
          capability={capability}
          diagnostics={[
            ...immediateWorkflowDiagnostics(active),
            ...(props.diagnostics ?? []).filter(
              (item) => item.workflowId === active.workflowId,
            ),
          ]}
          onChange={setWorkflow}
          onClose={() => setOpenId(undefined)}
          onPreview={props.onPreview}
        />
      )}
    </div>
  );
}

function WorkflowEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
  onClose,
  onPreview,
}: {
  workflow: WorkflowDraft;
  capability: WorkflowCapability;
  diagnostics: WorkflowValidationDiagnostic[];
  onChange(value: WorkflowDraft): void;
  onClose(): void;
  onPreview(): Promise<void>;
}) {
  const [json, setJson] = useState(() =>
    JSON.stringify(workflow.config, null, 2),
  );
  const [diagnostic, setDiagnostic] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  useEffect(
    () => setJson(JSON.stringify(workflow.config, null, 2)),
    [workflow.config],
  );
  const updateJson = (value: string) => {
    setJson(value);
    const parsed = parseAdvancedJson(value);
    setDiagnostic(
      parsed.error ??
        "JSON syntax valid. Use Preview / Validate for authoritative schema and planner validation.",
    );
    if (parsed.value) onChange(replaceWorkflowConfig(workflow, parsed.value));
  };
  const exportConfig = () => {
    const body = JSON.stringify(
      {
        schemaVersion: 1,
        workflowId: workflow.workflowId,
        config: workflow.config,
      },
      null,
      2,
    );
    const url = URL.createObjectURL(
      new Blob([body], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${workflow.workflowId}.routecairn.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };
  const importConfig = async (file: File) => {
    if (file.size > maxJsonBytes) {
      setDiagnostic("WORKFLOW_IMPORT_INVALID: file exceeds 256 KiB.");
      return;
    }
    const parsed = parseAdvancedJson(await file.text());
    if (parsed.error || !parsed.value) {
      setDiagnostic(parsed.error ?? "WORKFLOW_IMPORT_INVALID");
      return;
    }
    const envelope = importedConfig(parsed.value, workflow.workflowId);
    if (!envelope) {
      setDiagnostic(
        "WORKFLOW_IMPORT_INVALID: workflow ID does not match this editor.",
      );
      return;
    }
    onChange(replaceWorkflowConfig(workflow, envelope));
    setDiagnostic(
      "Imported configuration. Preview / Validate is required before launch.",
    );
  };
  return (
    <section
      className="workflow-editor"
      aria-label={`${capability.displayName} editor`}
    >
      <header>
        <div>
          <h4>{capability.displayName}</h4>
          <p>{capability.description}</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label={`Close ${capability.displayName} editor`}
        >
          Close
        </button>
      </header>
      <div className="workflow-editor-toolbar">
        <button
          type="button"
          className={workflow.editorMode === "guided" ? "selected" : ""}
          onClick={() => onChange({ ...workflow, editorMode: "guided" })}
        >
          Guided
        </button>
        <button
          type="button"
          className={workflow.editorMode === "advanced" ? "selected" : ""}
          onClick={() => onChange({ ...workflow, editorMode: "advanced" })}
        >
          Advanced JSON
        </button>
        <button type="button" onClick={() => void onPreview()}>
          Preview / Validate
        </button>
        <button type="button" onClick={exportConfig}>
          Export safe JSON
        </button>
        <button type="button" onClick={() => fileRef.current?.click()}>
          Import JSON
        </button>
        <input
          ref={fileRef}
          hidden
          type="file"
          accept="application/json,.json"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void importConfig(file);
            event.currentTarget.value = "";
          }}
        />
      </div>
      <p className="safety-note">
        No discovery or enumeration occurs. Only the exact visible cases are
        sent to the planner and worker.
      </p>
      {diagnostics.length > 0 && (
        <div className="workflow-diagnostic-summary" role="alert">
          <strong>{diagnostics.length} blocking issue(s)</strong>
          {diagnostics.map((item, index) => (
            <button
              type="button"
              key={`${item.fieldPath}-${index}`}
              onClick={() =>
                document
                  .getElementById(
                    diagnosticFieldId(workflow.workflowId, item.fieldPath),
                  )
                  ?.focus()
              }
            >
              {item.safeMessage}
            </button>
          ))}
        </div>
      )}
      {workflow.editorMode === "guided" ? (
        <GuidedWorkflowEditor
          workflow={workflow}
          capability={capability}
          diagnostics={diagnostics}
          onChange={onChange}
        />
      ) : (
        <div className="advanced-json">
          <label>
            Workflow JSON
            <textarea
              spellCheck={false}
              value={json}
              onChange={(event) => updateJson(event.target.value)}
              aria-describedby="workflow-json-diagnostic"
            />
          </label>
          <div>
            <strong>Syntax-highlighted preview</strong>
            <pre className="json-highlight" aria-hidden="true">
              {highlightJson(json)}
            </pre>
          </div>
          <p id="workflow-json-diagnostic" role="status">
            {diagnostic}
          </p>
        </div>
      )}
    </section>
  );
}

function GuidedWorkflowEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: {
  workflow: WorkflowDraft;
  capability: WorkflowCapability;
  diagnostics: WorkflowValidationDiagnostic[];
  onChange(value: WorkflowDraft): void;
}) {
  const cases = workflowCases(workflow);
  const updateConfig = (config: WorkflowCoreInput) =>
    onChange(replaceWorkflowConfig(workflow, config));
  return (
    <div className="guided-workflow">
      <div className="workflow-case-summary">
        <strong>{cases.length} configured case(s)</strong>
        <span>Methods: {capability.safeMethods.join(", ")}</span>
        <span>Planner limit: {JSON.stringify(capability.limits)}</span>
        <span>Exact request count: Unknown until planning</span>
        <button
          type="button"
          onClick={() =>
            onChange(
              duplicateWorkflowCase(workflow, Math.max(0, cases.length - 1)),
            )
          }
        >
          Add case
        </button>
      </div>
      <div className="case-list">
        {cases.map((item, index) => {
          const id = workflow.uiCaseIds[index] ?? createUiCaseId();
          const disabled = workflow.disabledCaseIds.includes(id);
          const deleteReason = workflowCaseDeleteBlockReason(workflow, index);
          return (
            <article
              key={id}
              data-ui-case-id={id}
              className={`case-card ${disabled ? "disabled" : ""}`}
            >
              <header>
                <strong>{caseLabel(item, index)}</strong>
                <span>
                  Case {index + 1} - {disabled ? "Disabled" : "Enabled"}
                </span>
              </header>
              <div className="case-actions">
                <button
                  type="button"
                  onClick={() =>
                    onChange({
                      ...workflow,
                      disabledCaseIds: disabled
                        ? workflow.disabledCaseIds.filter(
                            (itemId) => itemId !== id,
                          )
                        : [...workflow.disabledCaseIds, id],
                    })
                  }
                >
                  {disabled ? "Enable case" : "Disable case"}
                </button>
                <button
                  type="button"
                  onClick={() =>
                    onChange(duplicateWorkflowCase(workflow, index))
                  }
                >
                  Duplicate
                </button>
                <button
                  type="button"
                  disabled={index === 0}
                  onClick={() =>
                    onChange(moveWorkflowCase(workflow, index, -1))
                  }
                  aria-label={`Move case ${index + 1} up`}
                >
                  Up
                </button>
                <button
                  type="button"
                  disabled={index === cases.length - 1}
                  onClick={() => onChange(moveWorkflowCase(workflow, index, 1))}
                  aria-label={`Move case ${index + 1} down`}
                >
                  Down
                </button>
                <button
                  type="button"
                  title={deleteReason}
                  disabled={cases.length === 1 || Boolean(deleteReason)}
                  onClick={() => onChange(deleteWorkflowCase(workflow, index))}
                >
                  Delete
                </button>
                {deleteReason && <small role="status">{deleteReason}</small>}
              </div>
            </article>
          );
        })}
      </div>
      <SpecializedWorkflowEditor
        workflow={workflow}
        capability={capability}
        diagnostics={diagnostics}
        onChange={onChange}
      />
      <details>
        <summary>All configured schema fields</summary>
        <p className="muted">
          This complete shape inspector remains available alongside the
          purpose-built controls.
        </p>
        <StructuredFields
          root={workflow.config}
          value={workflow.config}
          path={[]}
          capability={capability}
          onChange={updateConfig}
        />
      </details>
    </div>
  );
}

function StructuredFields({
  root,
  value,
  path,
  capability,
  onChange,
}: {
  root: WorkflowCoreInput;
  value: unknown;
  path: Array<string | number>;
  capability: WorkflowCapability;
  onChange(value: WorkflowCoreInput): void;
}) {
  if (!value || typeof value !== "object") return null;
  return (
    <div className={path.length ? "structured-group" : "structured-root"}>
      {Object.entries(value).map(([key, child]) => {
        const nextPath = [...path, key];
        if (Array.isArray(child))
          return (
            <fieldset key={key}>
              <legend>{humanize(key)}</legend>
              {child.length === 0 ? (
                <p className="muted">No configured values.</p>
              ) : (
                child.map((entry, index) =>
                  typeof entry === "object" && entry !== null ? (
                    <section
                      className="structured-array-item"
                      key={`${key}-${index}`}
                    >
                      <h5>
                        {humanize(key)} {index + 1}
                      </h5>
                      <StructuredFields
                        root={root}
                        value={entry}
                        path={[...nextPath, index]}
                        capability={capability}
                        onChange={onChange}
                      />
                    </section>
                  ) : (
                    <label key={`${key}-${index}`}>
                      {humanize(key)} {index + 1}
                      <input
                        value={String(entry)}
                        onChange={(event) =>
                          onChange(
                            updateAtPath(
                              root,
                              [...nextPath, index],
                              event.target.value,
                            ),
                          )
                        }
                      />
                    </label>
                  ),
                )
              )}
            </fieldset>
          );
        if (child && typeof child === "object")
          return (
            <fieldset key={key}>
              <legend>{humanize(key)}</legend>
              <StructuredFields
                root={root}
                value={child}
                path={nextPath}
                capability={capability}
                onChange={onChange}
              />
            </fieldset>
          );
        const options = enumOptions(key, capability);
        return (
          <label key={key}>
            {humanize(key)}
            {typeof child === "boolean" ? (
              <input
                type="checkbox"
                checked={child}
                onChange={(event) =>
                  onChange(updateAtPath(root, nextPath, event.target.checked))
                }
              />
            ) : options.length ? (
              <select
                value={String(child)}
                onChange={(event) =>
                  onChange(updateAtPath(root, nextPath, event.target.value))
                }
              >
                {options.map((option) => (
                  <option key={option}>{option}</option>
                ))}
              </select>
            ) : (
              <input
                type={typeof child === "number" ? "number" : "text"}
                value={String(child ?? "")}
                onChange={(event) =>
                  onChange(
                    updateAtPath(
                      root,
                      nextPath,
                      typeof child === "number"
                        ? Number(event.target.value)
                        : event.target.value,
                    ),
                  )
                }
              />
            )}
          </label>
        );
      })}
    </div>
  );
}

function createWorkflow(
  id: WorkflowId,
  target: string,
  principalA: string,
  principalB: string,
): WorkflowDraft {
  const workflow = createWorkflowConfiguration(
    id,
    target,
    principalA,
    principalB,
  );
  return {
    ...workflow,
    uiCaseIds: Array.from({ length: workflowCaseCount(workflow) }, () =>
      createUiCaseId(),
    ),
  } as WorkflowDraft;
}

function createWorkflowConfiguration(
  id: WorkflowId,
  target: string,
  principalA: string,
  principalB: string,
): AuthorizationWorkflowConfiguration {
  const origin = safeOrigin(target);
  const actors = [
    {
      id: "account-a",
      relationship: "OWNER" as const,
      authProfile: "account_a" as const,
      safeAlias: "Account A",
      principalId: principalA || "declare-account-a-principal",
      tenantId: "tenant-a",
      role: "member",
      accountState: "active",
    },
    {
      id: "account-b",
      relationship: "NON_OWNER" as const,
      authProfile: "account_b" as const,
      safeAlias: "Account B",
      principalId: principalB || "declare-account-b-principal",
      tenantId: "tenant-b",
      role: "viewer",
      accountState: "active",
    },
  ];
  switch (id) {
    case "object-pair":
      return {
        workflowId: id,
        enabled: true,
        editorMode: "guided",
        disabledCaseIds: [],
        config: {
          schemaVersion: 1,
          maxPairs: 5,
          principals: {
            accountA: {
              expectedAccountId: principalA || "declare-account-a-principal",
              tenantId: "tenant-a",
              role: "member",
            },
            accountB: {
              expectedAccountId: principalB || "declare-account-b-principal",
              tenantId: "tenant-b",
              role: "viewer",
            },
          },
          cases: [
            {
              id: "object-pair-1",
              objectType: "record",
              expectedVisibility: "PRIVATE_TO_OWNER",
              template: {
                id: "record-read",
                method: "GET",
                url: `${origin}/api/records/{{OBJECT_ID}}`,
                headers: { Accept: "application/json" },
              },
              accountAObject: objectAssertion(
                "exact-object-a",
                "Account A supplied object",
              ),
              accountBObject: objectAssertion(
                "exact-object-b",
                "Account B supplied object",
              ),
            },
          ],
        },
      };
    case "field-exposure":
      return {
        workflowId: id,
        enabled: true,
        editorMode: "guided",
        disabledCaseIds: [],
        config: {
          schemaVersion: 1,
          maxCases: 5,
          maxResponseBytes: 65536,
          maxPreviewLength: 120,
          cases: [
            {
              id: "field-case-1",
              objectType: "record",
              objectId: "exact-object-a",
              declaredOwnerActor: "owner",
              expectedVisibility: "OWNER_ONLY",
              requireVerifiedIdentity: true,
              template: {
                id: "field-read",
                method: "GET",
                url: `${origin}/api/records/{{OBJECT_ID}}`,
                headers: { Accept: "application/json" },
              },
              objectConfirmation: {
                expectedObjectIdField: "id",
                expectedOwnerField: "owner.id",
                expectedTenantField: "tenant.id",
              },
              actors: [
                {
                  id: "owner",
                  type: "OWNER",
                  authProfile: "account_a",
                  safeAlias: "Account A",
                  principalId: principalA || "declare-account-a-principal",
                  tenantId: "tenant-a",
                  role: "member",
                },
                {
                  id: "non-owner",
                  type: "NON_OWNER",
                  authProfile: "account_b",
                  safeAlias: "Account B",
                  principalId: principalB || "declare-account-b-principal",
                  tenantId: "tenant-b",
                  role: "viewer",
                },
              ],
              fieldExpectations: [
                {
                  id: "private-field",
                  path: "privateNote",
                  label: "Private note",
                  sensitivity: "PRIVATE",
                  expectation: "MUST_BE_ABSENT",
                  allowedActors: ["owner"],
                  prohibitedActors: ["non-owner"],
                  allowPreview: false,
                },
              ],
            },
          ],
        },
      };
    case "authorization-matrix":
      return {
        workflowId: id,
        enabled: true,
        editorMode: "guided",
        disabledCaseIds: [],
        config: {
          schemaVersion: 1,
          maxMatrices: 3,
          maxCasesPerMatrix: 20,
          maxResponseBytes: 65536,
          maxPreviewLength: 120,
          matrices: [
            {
              id: "matrix-1",
              name: "Record authorization",
              objectType: "record",
              template: {
                id: "matrix-read",
                method: "GET",
                url: `${origin}/api/records/{{OBJECT_ID}}`,
                headers: { Accept: "application/json" },
              },
              objectIdentityField: "id",
              objectStateField: "state",
              actors,
              cases: [
                {
                  id: "owner-allowed",
                  actorId: "account-a",
                  objectId: "exact-object-a",
                  expectedObjectState: "active",
                  expectedDecision: "MUST_ALLOW",
                  requireVerifiedIdentity: true,
                  expectedTenantId: "tenant-a",
                  expectedRole: "member",
                  expectedAccountState: "active",
                },
              ],
            },
          ],
        },
      };
    case "equivalent-route":
      return {
        workflowId: id,
        enabled: true,
        editorMode: "guided",
        disabledCaseIds: [],
        config: {
          schemaVersion: 1,
          maxRouteSets: 3,
          maxRoutesPerSet: 4,
          maxActorsPerSet: 3,
          maxCells: 20,
          maxResponseBytes: 65536,
          maxPreviewLength: 120,
          routeSets: [
            {
              id: "routes-1",
              name: "Equivalent record routes",
              objectType: "record",
              objectId: "exact-object-a",
              canonicalRouteId: "canonical",
              equivalencePolicy: "SAME_OWNER_BOUNDARY",
              objectIdentityField: "id",
              objectStateField: "state",
              expectedObjectState: "active",
              requireVerifiedIdentity: true,
              actors,
              routes: [
                {
                  id: "canonical",
                  label: "Canonical route",
                  category: "CANONICAL",
                  isCanonical: true,
                  deprecated: false,
                  expectedPublic: false,
                  expectedContentType: "application/json",
                  representationType: "json",
                  template: {
                    id: "canonical-get",
                    method: "GET",
                    url: `${origin}/api/records/{{OBJECT_ID}}`,
                    headers: { Accept: "application/json" },
                  },
                  expectations: {
                    "account-a": "MUST_ALLOW",
                    "account-b": "MUST_DENY",
                  },
                },
                {
                  id: "candidate",
                  label: "Exact candidate route",
                  category: "LEGACY",
                  isCanonical: false,
                  deprecated: false,
                  expectedPublic: false,
                  expectedContentType: "application/json",
                  representationType: "json",
                  referenceRouteId: "canonical",
                  template: {
                    id: "candidate-get",
                    method: "GET",
                    url: `${origin}/legacy/records/{{OBJECT_ID}}`,
                    headers: { Accept: "application/json" },
                  },
                  expectations: {
                    "account-a": "MUST_ALLOW",
                    "account-b": "MUST_DENY",
                  },
                },
              ],
            },
          ],
        },
      };
    case "collection-authorization":
      return {
        workflowId: id,
        enabled: true,
        editorMode: "guided",
        disabledCaseIds: [],
        config: {
          schemaVersion: 1,
          maxCollections: 3,
          maxCasesPerCollection: 10,
          maxKnownObjects: 10,
          maxRequests: 20,
          maxRetainedObservations: 20,
          maxPreviewLength: 120,
          collections: [
            {
              id: "collection-1",
              label: "Exact record listing",
              category: "LIST",
              method: "GET",
              url: `${origin}/api/records`,
              headers: { Accept: "application/json" },
              expectedContentType: "application/json",
              completeness: "FIXED_RESULT_WINDOW",
              resultArrayPath: "items",
              objectIdPath: "id",
              objectTenantPath: "tenant.id",
              objectOwnerPath: "owner.id",
              objectStatePath: "state",
              objectTypePath: "type",
              maxInspectedEntries: 25,
              maxResponseBytes: 65536,
              maxJsonDepth: 8,
              actors,
              knownObjects: [
                {
                  id: "known-object-a",
                  objectId: "exact-object-a",
                  objectType: "record",
                  ownerActorId: "account-a",
                  tenantId: "tenant-a",
                  state: "active",
                  safeAlias: "Known Account A record",
                  expectedPublic: false,
                  expectedShared: false,
                  confirmedSafeToTest: true,
                },
              ],
              cases: [
                {
                  id: "cross-tenant-hidden",
                  actorId: "account-b",
                  knownObjectId: "known-object-a",
                  expectedMembership: "MUST_NOT_CONTAIN",
                  requireVerifiedIdentity: true,
                  expectedActorRelationship: "NON_OWNER",
                  expectedTenantId: "tenant-b",
                  expectedRole: "viewer",
                  expectedAccountState: "active",
                  expectedObjectState: "active",
                  summaryExpectations: [],
                },
              ],
            },
          ],
        },
      };
    case "bulk-authorization":
      return {
        workflowId: id,
        enabled: true,
        editorMode: "guided",
        disabledCaseIds: [],
        config: {
          schemaVersion: 1,
          maxDefinitions: 3,
          maxCasesPerDefinition: 10,
          maxObjectsPerCase: 10,
          maxRequests: 25,
          maxRetainedObservations: 25,
          definitions: [
            {
              id: "bulk-1",
              label: "Exact safe bulk summary",
              actors,
              cases: [
                {
                  id: "bulk-get-1",
                  actorId: "account-b",
                  caseType: "MIXED_OWNERSHIP",
                  requestStyle: "GET_COMMA_QUERY",
                  method: "GET",
                  url: `${origin}/api/records/bulk/summary?ids={{OBJECT_ID_LIST_COMMA}}`,
                  headers: { Accept: "application/json" },
                  objectOrderMatters: true,
                  objects: [
                    {
                      id: "object-a",
                      objectId: "exact-object-a",
                      safeAlias: "Account A record",
                      objectType: "record",
                      expectedDecision: "FILTER_OUT",
                      ownerActorId: "account-a",
                      tenantId: "tenant-a",
                      state: "active",
                      roleVisibility: "member",
                      verificationSource: "DECLARED_ONLY",
                    },
                  ],
                  expectedBatchPolicy: "MUST_FILTER_UNAUTHORIZED_OBJECTS",
                  requireVerifiedIdentity: true,
                  expectedTenantId: "tenant-b",
                  expectedRole: "viewer",
                  expectedAccountState: "active",
                  safetyContract: {
                    operationType: "SELECTION_SUMMARY",
                    operatorConfirmedNonMutating: true,
                    environment: "CONTROLLED_TEST",
                    disallowedResponsePaths: [],
                    disallowedStatusCodes: [201, 202],
                    prohibitAsync: true,
                    prohibitDownloads: true,
                  },
                  responseContract: {
                    type: "SUMMARY_ONLY",
                    resultArrayPath: "items",
                    resultObjectIdPath: "id",
                    metadataPaths: [],
                    maxItems: 50,
                  },
                  postSafetyMode: "GET_ONLY",
                  postconditionChecks: [],
                  maxResponseBytes: 65536,
                  maxJsonDepth: 10,
                  maxPreviewLength: 120,
                },
              ],
            },
          ],
        },
      };
    case "file-authorization":
      return {
        workflowId: id,
        enabled: true,
        editorMode: "guided",
        disabledCaseIds: [],
        config: {
          schemaVersion: 1,
          maxDefinitions: 3,
          maxCasesPerDefinition: 10,
          maxFilesPerDefinition: 20,
          maxRequests: 40,
          maxRetainedObservations: 40,
          definitions: [
            {
              id: "files-1",
              label: "Exact file authorization",
              actors,
              files: [
                {
                  id: "private-file",
                  fileRef: "exact-private-file",
                  safeAlias: "Known private file",
                  fileType: "document",
                  ownerActorId: "account-a",
                  tenantId: "tenant-a",
                  state: "active",
                  expectedPublic: false,
                },
              ],
              cases: [
                {
                  id: "file-metadata-denied",
                  label: "Cross-account metadata denied",
                  category: "FILE_METADATA",
                  actorId: "account-b",
                  fileRefId: "private-file",
                  method: "GET",
                  url: `${origin}/api/files/{{FILE_ID}}`,
                  placeholder: "FILE_ID",
                  headers: { Accept: "application/json" },
                  expectedDecision: "MUST_DENY_METADATA",
                  requireVerifiedIdentity: true,
                  expectedTenantId: "tenant-b",
                  expectedRole: "viewer",
                  expectedAccountState: "active",
                  expectedFileState: "active",
                  identityStrategy: "METADATA_FIELD_MATCH",
                  identityField: "file.id",
                  stateField: "file.state",
                  contentProofMode: "METADATA_ONLY",
                  rangeStart: 0,
                  maxMetadataBytes: 65536,
                  maxProbeBytes: 4096,
                  maxFullStreamBytes: 262144,
                  allowedRedirectOrigins: [],
                  followSignedUrl: false,
                  allowedSignedUrlOrigins: [],
                },
              ],
            },
          ],
        },
      };
  }
}

function objectAssertion(id: string, source: string) {
  return {
    id,
    source,
    confirmedSafeToTest: true as const,
    readOnly: true as const,
    tenantId: id.endsWith("a") ? "tenant-a" : "tenant-b",
    expectedObjectIdField: "id",
    expectedOwnerField: "owner.id",
    expectedTenantField: "tenant.id",
    expectedPrivateHeaders: [],
    expectedSafeMarkers: [],
    expectedPrivateFields: ["privateNote"],
  };
}
function safeOrigin(target: string): string {
  try {
    const value = new URL(target);
    return value.origin;
  } catch {
    return "https://authorized-target.invalid";
  }
}
function workflowCases(workflow: WorkflowDraft): unknown[] {
  switch (workflow.workflowId) {
    case "object-pair":
      return workflow.config.cases;
    case "field-exposure":
      return workflow.config.cases;
    case "authorization-matrix":
      return workflow.config.matrices.flatMap((item) => item.cases);
    case "equivalent-route":
      return workflow.config.routeSets.flatMap((item) => item.routes);
    case "collection-authorization":
      return workflow.config.collections.flatMap((item) => item.cases);
    case "bulk-authorization":
      return workflow.config.definitions.flatMap((item) => item.cases);
    case "file-authorization":
      return workflow.config.definitions.flatMap((item) => item.cases);
  }
}
export function workflowCaseCount(
  workflow: WorkflowDraft | AuthorizationWorkflowConfiguration,
): number {
  switch (workflow.workflowId) {
    case "object-pair":
      return workflow.config.cases.length;
    case "field-exposure":
      return workflow.config.cases.length;
    case "authorization-matrix":
      return workflow.config.matrices.reduce(
        (sum, item) => sum + item.cases.length,
        0,
      );
    case "equivalent-route":
      return workflow.config.routeSets.reduce(
        (sum, item) => sum + item.routes.length,
        0,
      );
    case "collection-authorization":
      return workflow.config.collections.reduce(
        (sum, item) => sum + item.cases.length,
        0,
      );
    case "bulk-authorization":
      return workflow.config.definitions.reduce(
        (sum, item) => sum + item.cases.length,
        0,
      );
    case "file-authorization":
      return workflow.config.definitions.reduce(
        (sum, item) => sum + item.cases.length,
        0,
      );
  }
}
export function workflowEnabledCaseCount(workflow: WorkflowDraft): number {
  return workflowCases(workflow).filter(
    (_, index) =>
      !workflow.disabledCaseIds.includes(workflow.uiCaseIds[index] ?? ""),
  ).length;
}
export function workflowForRequest(
  workflow: WorkflowDraft,
): AuthorizationWorkflowConfiguration {
  let flatIndex = 0;
  const filtered = mutateCaseArrays(workflow, (cases) =>
    cases.filter(
      () =>
        !workflow.disabledCaseIds.includes(
          workflow.uiCaseIds[flatIndex++] ?? "",
        ),
    ),
  );
  const { uiCaseIds: _uiCaseIds, ...requestWorkflow } = filtered;
  return {
    ...requestWorkflow,
    disabledCaseIds: [],
  } as AuthorizationWorkflowConfiguration;
}
function caseKey(value: unknown, index: number): string {
  return value &&
    typeof value === "object" &&
    "id" in value &&
    typeof value.id === "string"
    ? value.id
    : `case-${index}`;
}
function caseLabel(value: unknown, index: number): string {
  if (value && typeof value === "object") {
    if ("label" in value && typeof value.label === "string") return value.label;
    if ("name" in value && typeof value.name === "string") return value.name;
    if ("id" in value && typeof value.id === "string") return value.id;
  }
  return `Case ${index + 1}`;
}
function duplicateWorkflowCase(
  workflow: WorkflowDraft,
  index: number,
): WorkflowDraft {
  const next = mutateCaseAt(workflow, index, (cases, localIndex) => {
    const source = cases[localIndex];
    if (!source) return cases;
    const copy = structuredClone(source);
    if (copy && typeof copy === "object" && "id" in copy)
      copy.id = `${String(copy.id).slice(0, 100)}-copy-${cases.length + 1}`;
    return [
      ...cases.slice(0, localIndex + 1),
      copy,
      ...cases.slice(localIndex + 1),
    ];
  });
  const uiCaseIds = [...workflow.uiCaseIds];
  uiCaseIds.splice(index + 1, 0, createUiCaseId());
  return { ...next, uiCaseIds };
}
function deleteWorkflowCase(
  workflow: WorkflowDraft,
  index: number,
): WorkflowDraft {
  const removedId = workflow.uiCaseIds[index];
  const next = mutateCaseAt(workflow, index, (cases, localIndex) =>
    cases.filter((_, itemIndex) => itemIndex !== localIndex),
  );
  return {
    ...next,
    uiCaseIds: workflow.uiCaseIds.filter((_, itemIndex) => itemIndex !== index),
    disabledCaseIds: workflow.disabledCaseIds.filter((id) => id !== removedId),
  };
}
function moveWorkflowCase(
  workflow: WorkflowDraft,
  index: number,
  direction: -1 | 1,
): WorkflowDraft {
  const next = mutateCaseAt(workflow, index, (cases, localIndex) => {
    const copy = [...cases];
    const target = localIndex + direction;
    if (target < 0 || target >= copy.length) return copy;
    [copy[localIndex], copy[target]] = [copy[target], copy[localIndex]];
    return copy;
  });
  const uiCaseIds = [...workflow.uiCaseIds];
  const target = index + direction;
  if (target >= 0 && target < uiCaseIds.length)
    [uiCaseIds[index], uiCaseIds[target]] = [
      uiCaseIds[target]!,
      uiCaseIds[index]!,
    ];
  return { ...next, uiCaseIds };
}
function mutateCaseAt(
  workflow: WorkflowDraft,
  flatIndex: number,
  mutate: (cases: unknown[], localIndex: number) => unknown[],
): WorkflowDraft {
  let offset = 0;
  let changed = false;
  return mutateCaseArrays(workflow, (cases) => {
    if (changed || flatIndex < offset || flatIndex >= offset + cases.length) {
      offset += cases.length;
      return cases;
    }
    const result = mutate(cases, flatIndex - offset);
    changed = true;
    offset += cases.length;
    return result;
  });
}
function mutateCaseArrays(
  workflow: WorkflowDraft,
  mutate: (cases: unknown[]) => unknown[],
): WorkflowDraft {
  const next: unknown = structuredClone(workflow);
  if (!isJsonObject(next) || !isJsonObject(next.config)) return workflow;
  const arrays = mutableCaseArrays(next.config, workflow.workflowId);
  if (!arrays.length) return workflow;
  for (const entry of arrays) {
    const cases = entry.owner[entry.key];
    if (!Array.isArray(cases)) return workflow;
    const mutated = mutate(cases);
    if (!mutated.every(isJsonValue)) return workflow;
    entry.owner[entry.key] = mutated;
  }
  return next as WorkflowDraft;
}
function mutableCaseArrays(
  config: JsonObject,
  id: WorkflowId,
): Array<{ owner: JsonObject; key: string }> {
  if (id === "object-pair" || id === "field-exposure")
    return [{ owner: config, key: "cases" }];
  const [groupsKey, casesKey] =
    id === "equivalent-route"
      ? ["routeSets", "routes"]
      : id === "authorization-matrix"
        ? ["matrices", "cases"]
        : id === "collection-authorization"
          ? ["collections", "cases"]
          : ["definitions", "cases"];
  const groups = config[groupsKey];
  if (!Array.isArray(groups)) return [];
  return groups.filter(isJsonObject).map((owner) => ({ owner, key: casesKey }));
}
function replaceWorkflowConfig(
  workflow: WorkflowDraft,
  config: unknown,
): WorkflowDraft {
  const next = { ...workflow, config } as WorkflowDraft;
  const count = workflowCases(next).length;
  return {
    ...next,
    uiCaseIds: Array.from(
      { length: count },
      (_, index) => workflow.uiCaseIds[index] ?? createUiCaseId(),
    ),
  };
}
function parseAdvancedJson(value: string): { value?: unknown; error?: string } {
  if (new TextEncoder().encode(value).byteLength > maxJsonBytes)
    return { error: "WORKFLOW_ADVANCED_JSON_INVALID: JSON exceeds 256 KiB." };
  try {
    const parsed: unknown = JSON.parse(value);
    if (hasProhibitedKey(parsed))
      return {
        error:
          "WORKFLOW_ADVANCED_JSON_INVALID: prototype-related keys are forbidden.",
      };
    return { value: parsed };
  } catch (error) {
    return {
      error: `WORKFLOW_ADVANCED_JSON_INVALID: ${error instanceof Error ? error.message : "Invalid JSON."}`,
    };
  }
}
function hasProhibitedKey(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(hasProhibitedKey);
  return Object.entries(value).some(
    ([key, child]) => prohibitedKey.test(key) || hasProhibitedKey(child),
  );
}
function importedConfig(value: unknown, id: WorkflowId): unknown | undefined {
  if (!value || typeof value !== "object") return undefined;
  if ("workflowId" in value) {
    if (value.workflowId !== id || !("config" in value)) return undefined;
    return value.config;
  }
  return value;
}
function humanize(value: string): string {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]/g, " ")
    .replace(/^./, (letter) => letter.toUpperCase());
}
function enumOptions(key: string, capability: WorkflowCapability): string[] {
  if (/expectation|expectedDecision|expectedBatchPolicy/i.test(key))
    return capability.expectationTypes;
  if (key === "method") return capability.safeMethods;
  return enumValues[key] ?? [];
}
const enumValues: Record<string, string[]> = {
  authProfile: ["account_a", "account_b"],
  completeness: [
    "COMPLETE_COLLECTION",
    "FIXED_RESULT_WINDOW",
    "SEARCH_RESULT_SET",
    "SUMMARY_ONLY",
    "UNKNOWN_COMPLETENESS",
  ],
  postSafetyMode: [
    "GET_ONLY",
    "OPERATOR_ATTESTED_DRY_RUN",
    "POSTCONDITION_VERIFIED_DRY_RUN",
  ],
  contentProofMode: [
    "HEADERS_ONLY",
    "METADATA_ONLY",
    "BOUNDED_PREFIX",
    "FULL_STREAM_FINGERPRINT",
    "SIGNED_URL_ONLY",
  ],
  identityStrategy: [
    "METADATA_FIELD_MATCH",
    "OPERATOR_SUPPLIED_FINGERPRINT",
    "SIGNED_URL_FIELD_MATCH",
    "OBSERVE_ONLY",
  ],
  requestStyle: ["GET_REPEATED_QUERY", "GET_COMMA_QUERY", "JSON_POST"],
};
type JsonValue = string | number | boolean | null | JsonObject | JsonValue[];
type JsonObject = { [key: string]: JsonValue };
function isJsonObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function isJsonValue(value: unknown): value is JsonValue {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    (Array.isArray(value) && value.every(isJsonValue)) ||
    (isJsonObject(value) && Object.values(value).every(isJsonValue))
  );
}
function updateAtPath(
  root: WorkflowCoreInput,
  path: Array<string | number>,
  nextValue: unknown,
): WorkflowCoreInput {
  const copy: unknown = structuredClone(root);
  let cursor: unknown = copy;
  for (let index = 0; index < path.length - 1; index += 1) {
    const key = path[index]!;
    if (Array.isArray(cursor) && typeof key === "number") cursor = cursor[key];
    else if (isJsonObject(cursor) && typeof key === "string")
      cursor = cursor[key];
    else return root;
  }
  const last = path[path.length - 1];
  if (Array.isArray(cursor) && typeof last === "number")
    cursor[last] = nextValue as JsonValue;
  else if (isJsonObject(cursor) && typeof last === "string")
    cursor[last] = nextValue as JsonValue;
  else return root;
  return copy as WorkflowCoreInput;
}
export function containsUnsafeGeneratedValue(value: string): boolean {
  return unsafeExactValue.test(value);
}
export function workflowCaseDeleteBlockReason(
  workflow: WorkflowDraft,
  index: number,
): string | undefined {
  const item = workflowCases(workflow)[index];
  if (!item || typeof item !== "object" || !("id" in item)) return undefined;
  const scannerId = String(item.id);
  if (workflow.workflowId === "authorization-matrix") {
    const matrix = workflow.config.matrices.find((candidate) =>
      candidate.cases.some((testCase) => testCase === item),
    );
    if (matrix?.cases.some((testCase) => testCase.referenceCaseId === scannerId))
      return "Another matrix row references this row. Resolve the dependency before deletion.";
  }
  if (workflow.workflowId === "equivalent-route") {
    const set = workflow.config.routeSets.find((candidate) =>
      candidate.routes.some((route) => route === item),
    );
    if (set?.canonicalRouteId === scannerId)
      return "Choose another canonical route before deleting this route.";
    if (set?.routes.some((route) => route.referenceRouteId === scannerId))
      return "Another route references this route. Resolve the dependency before deletion.";
  }
  if (workflow.workflowId === "collection-authorization") {
    const collection = workflow.config.collections.find((candidate) =>
      candidate.cases.some((testCase) => testCase === item),
    );
    if (
      collection?.cases.some(
        (testCase) =>
          testCase.referenceCaseId === scannerId ||
          testCase.countExpectation?.referenceCaseId === scannerId ||
          testCase.summaryExpectations.some(
            (summary) => summary.referenceCaseId === scannerId,
          ),
      )
    )
      return "Another membership case references this case. Resolve the dependency before deletion.";
  }
  return undefined;
}
function createUiCaseId(): string {
  return `ui-case-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}
function highlightJson(value: string): React.ReactNode[] {
  const tokenPattern =
    /("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)/gi;
  const output: React.ReactNode[] = [];
  let offset = 0;
  for (const match of value.matchAll(tokenPattern)) {
    const index = match.index ?? 0;
    if (index > offset) output.push(value.slice(offset, index));
    const token = match[0];
    const className = match[1]
      ? "json-key"
      : match[2]
        ? "json-string"
        : match[3]
          ? "json-literal"
          : "json-number";
    output.push(
      <span className={className} key={`${index}-${token.length}`}>
        {token}
      </span>,
    );
    offset = index + token.length;
  }
  if (offset < value.length) output.push(value.slice(offset));
  return output;
}
