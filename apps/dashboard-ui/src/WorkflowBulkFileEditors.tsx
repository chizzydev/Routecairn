import React, { useEffect, useState } from "react";
import type {
  WorkflowCapability,
  WorkflowDraft,
} from "./AuthorizationWorkflowStudio";
import {
  diagnosticFieldId,
  type WorkflowValidationDiagnostic,
} from "./WorkflowDiagnostics";

import {
  Check,
  DiagnosticStringList,
  Field,
  HeaderEditor,
  Limits,
  NumberField,
  NumberList,
  Optional,
  ScalarEditor,
  Section,
  Select,
  StringList,
  Text,
  defaultBaseline,
  defaultPostcondition,
  human,
  optionalCopy,
  opts,
  proofModeHelp,
  safetyModeHelp,
  setOptional,
  setOptionalScalar,
} from "./WorkflowBulkFileControls";

type BulkDraft = Extract<WorkflowDraft, { workflowId: "bulk-authorization" }>;
type FileDraft = Extract<WorkflowDraft, { workflowId: "file-authorization" }>;
type Actor = BulkDraft["config"]["definitions"][number]["actors"][number];
type BulkBaseline = NonNullable<
  BulkDraft["config"]["definitions"][number]["cases"][number]["objects"][number]["baseline"]
>;
type BulkPostcondition =
  BulkDraft["config"]["definitions"][number]["cases"][number]["postconditionChecks"][number];
type EditableActor = {
  id: string;
  relationship: string;
  authProfile?: "account_a" | "account_b" | undefined;
  safeAlias?: string | undefined;
  principalId?: string | undefined;
  tenantId?: string | undefined;
  role?: string | undefined;
  accountState?: string | undefined;
};

interface SharedProps {
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
}

export function BulkWorkflowEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: SharedProps & {
  workflow: BulkDraft;
  onChange(value: WorkflowDraft): void;
}) {
  const update = (config: BulkDraft["config"]) =>
    onChange({ ...workflow, config });
  return (
    <div className="specialized-editor bulk-editor">
      <p className="domain-help">
        Only exact supplied objects execute. POST is available solely under an
        explicit non-mutating dry-run contract; response-derived IDs and
        executable templates are never accepted.
      </p>
      {workflow.config.definitions.map((definition, definitionIndex) => {
        const setDefinition = (mutate: (value: typeof definition) => void) => {
          const config = structuredClone(workflow.config);
          mutate(config.definitions[definitionIndex]!);
          update(config);
        };
        return (
          <section className="domain-case" key={definition.id}>
            <div className="grid two">
              <Text
                label="Definition ID"
                value={definition.id}
                onChange={(value) =>
                  setDefinition((entry) => {
                    entry.id = value;
                  })
                }
              />
              <Text
                label="Safe label"
                value={definition.label}
                onChange={(value) =>
                  setDefinition((entry) => {
                    entry.label = value;
                  })
                }
              />
            </div>
            <ActorEditor
              actors={definition.actors}
              capability={capability}
              onChange={(actors) =>
                setDefinition((entry) => {
                  entry.actors = actors;
                })
              }
            />
            {definition.cases.map((item, caseIndex) => (
              <BulkCaseEditor
                key={workflow.uiCaseIds[caseIndex] ?? item.id}
                workflow={workflow}
                definitionIndex={definitionIndex}
                caseIndex={caseIndex}
                item={item}
                actors={definition.actors}
                capability={capability}
                diagnostics={diagnostics}
                onChange={(mutate) =>
                  setDefinition((entry) => mutate(entry.cases[caseIndex]!))
                }
              />
            ))}
          </section>
        );
      })}
      <Limits
        values={{
          maxDefinitions: workflow.config.maxDefinitions,
          maxCasesPerDefinition: workflow.config.maxCasesPerDefinition,
          maxObjectsPerCase: workflow.config.maxObjectsPerCase,
          maxRequests: workflow.config.maxRequests,
          maxRetainedObservations: workflow.config.maxRetainedObservations,
        }}
        onChange={(key, value) => update({ ...workflow.config, [key]: value })}
      />
    </div>
  );
}

function BulkCaseEditor({
  workflow,
  definitionIndex,
  caseIndex,
  item,
  actors,
  capability,
  diagnostics,
  onChange,
}: {
  workflow: BulkDraft;
  definitionIndex: number;
  caseIndex: number;
  item: BulkDraft["config"]["definitions"][number]["cases"][number];
  actors: Actor[];
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  onChange(mutate: (value: typeof item) => void): void;
}) {
  const path = (suffix: string) =>
    `definitions.${definitionIndex}.cases.${caseIndex}.${suffix}`;
  const post = item.method === "POST";
  return (
    <section className="workflow-subcase" aria-label={`Bulk case ${item.id}`}>
      <header>
        <div>
          <h5>{item.id}</h5>
          <span className="status-text">
            {post ? "POST dry-run" : "GET-only"}
          </span>
        </div>
      </header>
      <div className="grid three">
        <Text
          label="Case name"
          value={item.id}
          onChange={(value) =>
            onChange((entry) => {
              entry.id = value;
            })
          }
        />
        <Select
          label="Actor"
          value={item.actorId}
          values={actors.map((actor) => actor.id)}
          onChange={(value) =>
            onChange((entry) => {
              entry.actorId = value;
            })
          }
        />
        <Select
          label="Case type"
          value={item.caseType}
          values={opts(capability, "caseType")}
          onChange={(value) =>
            onChange((entry) => {
              entry.caseType = value as typeof entry.caseType;
            })
          }
        />
        <Select
          label="Request style"
          value={item.requestStyle}
          values={opts(capability, "requestStyle")}
          onChange={(value) =>
            onChange((entry) => {
              entry.requestStyle = value as typeof entry.requestStyle;
              entry.method = value === "JSON_POST" ? "POST" : "GET";
              entry.postSafetyMode =
                value === "JSON_POST"
                  ? "OPERATOR_ATTESTED_DRY_RUN"
                  : "GET_ONLY";
              if (value === "JSON_POST") {
                entry.bodyTemplate = {
                  objectIds: "{{OBJECT_IDS_ARRAY}}",
                  dryRun: true,
                };
                entry.safetyContract.requiredRequestMarkerPath ??= "dryRun";
                entry.safetyContract.requiredRequestMarkerValue ??= true;
              } else {
                delete entry.bodyTemplate;
              }
            })
          }
        />
        <Select
          label="Method"
          value={item.method}
          values={post ? ["POST"] : ["GET"]}
          onChange={() => undefined}
        />
        <Field
          workflow={workflow}
          diagnostics={diagnostics}
          fieldPath={path("url")}
          label="Exact endpoint/template"
          value={item.url}
          onChange={(value) =>
            onChange((entry) => {
              entry.url = value;
            })
          }
        />
      </div>
      <p className="safety-note" role="note">
        GET uses only <code>{"{{OBJECT_ID_LIST_REPEATED}}"}</code> or{" "}
        <code>{"{{OBJECT_ID_LIST_COMMA}}"}</code>. JSON POST accepts only the
        fixed <code>{"{{OBJECT_IDS_ARRAY}}"}</code> placeholder.
      </p>
      <HeaderEditor
        headers={item.headers}
        onChange={(headers) =>
          onChange((entry) => {
            entry.headers = headers;
          })
        }
      />
      {post && (
      <JsonBodyEditor
        value={item.bodyTemplate}
        onValid={(bodyTemplate) =>
          onChange((entry) => {
            entry.bodyTemplate = bodyTemplate;
          })
        }
        onInvalid={() =>
          onChange((entry) => {
            entry.bodyTemplate = { invalidGuidedBody: true };
          })
        }
      />
      )}
      <Section
        title="Exact object set"
        help="Every object is supplied before planning. Runtime responses cannot expand this set."
      >
        {item.objects.map((object, objectIndex) => (
          <fieldset key={object.id}>
            <legend>{object.safeAlias ?? object.id}</legend>
            <div className="grid three">
              <Text
                label="Object row ID"
                value={object.id}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.objects[objectIndex]!.id = value;
                  })
                }
              />
              <Text
                label="Exact object ID"
                value={object.objectId}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.objects[objectIndex]!.objectId = value;
                  })
                }
              />
              <Text
                label="Object type"
                value={object.objectType}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.objects[objectIndex]!.objectType = value;
                  })
                }
              />
              <Optional
                label="Safe alias"
                value={object.safeAlias}
                onChange={(value) =>
                  onChange((entry) =>
                    setOptional(
                      entry.objects[objectIndex]!,
                      "safeAlias",
                      value,
                    ),
                  )
                }
              />
              <Select
                label="Expected object decision"
                value={object.expectedDecision}
                values={opts(capability, "objectDecision")}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.objects[objectIndex]!.expectedDecision =
                      value as typeof object.expectedDecision;
                  })
                }
              />
              <Select
                label="Owner actor"
                value={object.ownerActorId ?? ""}
                values={["", ...actors.map((actor) => actor.id)]}
                onChange={(value) =>
                  onChange((entry) =>
                    setOptional(
                      entry.objects[objectIndex]!,
                      "ownerActorId",
                      value,
                    ),
                  )
                }
              />
              <Optional
                label="Tenant"
                value={object.tenantId}
                onChange={(value) =>
                  onChange((entry) =>
                    setOptional(entry.objects[objectIndex]!, "tenantId", value),
                  )
                }
              />
              <Optional
                label="State"
                value={object.state}
                onChange={(value) =>
                  onChange((entry) =>
                    setOptional(entry.objects[objectIndex]!, "state", value),
                  )
                }
              />
              <Optional
                label="Role visibility"
                value={object.roleVisibility}
                onChange={(value) =>
                  onChange((entry) =>
                    setOptional(
                      entry.objects[objectIndex]!,
                      "roleVisibility",
                      value,
                    ),
                  )
                }
              />
              <Select
                label="Verification source"
                value={object.verificationSource}
                values={opts(capability, "verificationSource")}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.objects[objectIndex]!.verificationSource =
                      value as typeof object.verificationSource;
                  })
                }
              />
            </div>
            {object.baseline ? (
              <BaselineEditor
                value={object.baseline}
                actors={actors}
                capability={capability}
                onChange={(baseline) =>
                  onChange((entry) => {
                    entry.objects[objectIndex]!.baseline = baseline;
                  })
                }
                onRemove={() =>
                  onChange((entry) => {
                    delete entry.objects[objectIndex]!.baseline;
                  })
                }
              />
            ) : (
              <button
                type="button"
                onClick={() =>
                  onChange((entry) => {
                    entry.objects[objectIndex]!.baseline = defaultBaseline(
                      entry.objects[objectIndex]!.objectId,
                      entry.actorId,
                    );
                  })
                }
              >
                Add single-object baseline
              </button>
            )}
            <button
              type="button"
              disabled={item.objects.length === 1}
              onClick={() =>
                onChange((entry) => {
                  entry.objects.splice(objectIndex, 1);
                })
              }
            >
              Remove object
            </button>
          </fieldset>
        ))}
        <button
          type="button"
          onClick={() =>
            onChange((entry) => {
              entry.objects.push({
                id: `object-${entry.objects.length + 1}`,
                objectId: `exact-object-${entry.objects.length + 1}`,
                objectType: "record",
                expectedDecision: "OBSERVE_ONLY",
                verificationSource: "DECLARED_ONLY",
              });
            })
          }
        >
          Add exact object
        </button>
      </Section>
      <Section
        title="Authorization expectation"
        help="The batch policy is compared only with the exact object decisions above."
      >
        <div className="grid three">
          <Select
            label="Expected batch policy"
            value={item.expectedBatchPolicy}
            values={capability.expectationTypes}
            onChange={(value) =>
              onChange((entry) => {
                entry.expectedBatchPolicy =
                  value as typeof entry.expectedBatchPolicy;
              })
            }
          />
          <Check
            label="Require verified identity"
            checked={item.requireVerifiedIdentity}
            onChange={(value) =>
              onChange((entry) => {
                entry.requireVerifiedIdentity = value;
              })
            }
          />
          <Check
            label="Object order matters"
            checked={item.objectOrderMatters}
            onChange={(value) =>
              onChange((entry) => {
                entry.objectOrderMatters = value;
              })
            }
          />
          <Optional
            label="Expected tenant"
            value={item.expectedTenantId}
            onChange={(value) =>
              onChange((entry) => setOptional(entry, "expectedTenantId", value))
            }
          />
          <Optional
            label="Expected role"
            value={item.expectedRole}
            onChange={(value) =>
              onChange((entry) => setOptional(entry, "expectedRole", value))
            }
          />
          <Optional
            label="Expected account state"
            value={item.expectedAccountState}
            onChange={(value) =>
              onChange((entry) =>
                setOptional(entry, "expectedAccountState", value),
              )
            }
          />
        </div>
      </Section>
      <SafetyContractEditor
        item={item}
        capability={capability}
        diagnostics={diagnostics}
        workflow={workflow}
        path={path}
        onChange={onChange}
      />
      <ResponseContractEditor
        item={item}
        capability={capability}
        diagnostics={diagnostics}
        workflow={workflow}
        path={path}
        onChange={onChange}
      />
      <Section
        title="Precondition and postcondition verification"
        help="Each configured GET is captured before POST and repeated after POST. Only the listed scalar fields are compared; unchanged fields do not prove the absence of all side effects."
      >
        <Select
          label="Safety mode"
          value={
            item.postSafetyMode ??
            (post ? "OPERATOR_ATTESTED_DRY_RUN" : "GET_ONLY")
          }
          values={
            post
              ? opts(capability, "postSafetyMode").filter(
                  (value) => value !== "GET_ONLY",
                )
              : ["GET_ONLY"]
          }
          onChange={(value) =>
            onChange((entry) => {
              entry.postSafetyMode = value as typeof entry.postSafetyMode;
            })
          }
        />
        <p className="safety-note" role="note">
          {
            safetyModeHelp[
              item.postSafetyMode ??
                (post ? "OPERATOR_ATTESTED_DRY_RUN" : "GET_ONLY")
            ]
          }
        </p>
        {item.postconditionChecks.map((check, checkIndex) => (
          <PostconditionEditor
            key={check.id}
            value={check}
            actors={actors}
            diagnostics={diagnostics}
            workflow={workflow}
            basePath={path(`postconditionChecks.${checkIndex}`)}
            onChange={(value) =>
              onChange((entry) => {
                entry.postconditionChecks[checkIndex] = value;
              })
            }
            onRemove={() =>
              onChange((entry) => {
                entry.postconditionChecks.splice(checkIndex, 1);
              })
            }
          />
        ))}
        <button
          type="button"
          onClick={() =>
            onChange((entry) => {
              entry.postconditionChecks.push(
                defaultPostcondition(
                  entry.objects[0]!.objectId,
                  entry.actorId,
                  entry.postconditionChecks.length,
                ),
              );
              if (entry.method === "POST")
                entry.postSafetyMode = "POSTCONDITION_VERIFIED_DRY_RUN";
            })
          }
        >
          Add pre/postcondition check
        </button>
      </Section>
      <Limits
        values={{
          maxResponseBytes: item.maxResponseBytes,
          maxJsonDepth: item.maxJsonDepth,
          maxPreviewLength: item.maxPreviewLength,
        }}
        onChange={(key, value) =>
          onChange((entry) => {
            entry[
              key as "maxResponseBytes" | "maxJsonDepth" | "maxPreviewLength"
            ] = value;
          })
        }
      />
    </section>
  );
}

function BaselineEditor({
  value,
  actors,
  capability,
  onChange,
  onRemove,
}: {
  value: BulkBaseline;
  actors: Actor[];
  capability: WorkflowCapability;
  onChange(value: BulkBaseline): void;
  onRemove(): void;
}) {
  const set = <K extends keyof typeof value>(key: K, next: (typeof value)[K]) =>
    onChange({ ...value, [key]: next });
  return (
    <fieldset className="nested-builder">
      <legend>Single-object baseline</legend>
      <p>
        This safe GET establishes the exact object’s individual authorization
        result for comparison with the batch operation.
      </p>
      <div className="grid three">
        <Text
          label="Baseline ID"
          value={value.id}
          onChange={(next) => set("id", next)}
        />
        <Select
          label="Source"
          value={value.source}
          values={opts(capability, "baselineSource")}
          onChange={(next) => set("source", next as typeof value.source)}
        />
        <Select
          label="Actor"
          value={value.actorId}
          values={actors.map((actor) => actor.id)}
          onChange={(next) => set("actorId", next)}
        />
        <Text
          label="Exact GET with {{OBJECT_ID}}"
          value={value.url}
          onChange={(next) => set("url", next)}
        />
        <Select
          label="Expected decision"
          value={value.expectedDecision}
          values={opts(capability, "baselineDecision")}
          onChange={(next) =>
            set("expectedDecision", next as typeof value.expectedDecision)
          }
        />
        <Text
          label="Object identity path"
          value={value.objectIdentityField}
          onChange={(next) => set("objectIdentityField", next)}
        />
        <Optional
          label="Object state path"
          value={value.objectStateField}
          onChange={(next) =>
            optionalCopy(value, "objectStateField", next, onChange)
          }
        />
        <Optional
          label="Expected object state"
          value={value.expectedObjectState}
          onChange={(next) =>
            optionalCopy(value, "expectedObjectState", next, onChange)
          }
        />
        <Optional
          label="Expected tenant"
          value={value.expectedTenantId}
          onChange={(next) =>
            optionalCopy(value, "expectedTenantId", next, onChange)
          }
        />
        <Optional
          label="Expected role"
          value={value.expectedRole}
          onChange={(next) =>
            optionalCopy(value, "expectedRole", next, onChange)
          }
        />
        <Check
          label="Require verified identity"
          checked={value.requireVerifiedIdentity}
          onChange={(next) => set("requireVerifiedIdentity", next)}
        />
        <NumberField
          label="Maximum response bytes"
          value={value.maxResponseBytes}
          onChange={(next) => set("maxResponseBytes", next)}
        />
        <NumberField
          label="Maximum JSON depth"
          value={value.maxJsonDepth}
          onChange={(next) => set("maxJsonDepth", next)}
        />
      </div>
      <HeaderEditor
        headers={value.headers}
        onChange={(next) => set("headers", next)}
      />
      <button type="button" onClick={onRemove}>
        Remove baseline
      </button>
    </fieldset>
  );
}

function SafetyContractEditor({
  item,
  capability,
  diagnostics,
  workflow,
  path,
  onChange,
}: {
  item: BulkDraft["config"]["definitions"][number]["cases"][number];
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  workflow: BulkDraft;
  path(suffix: string): string;
  onChange(mutate: (value: typeof item) => void): void;
}) {
  const contract = item.safetyContract;
  return (
    <Section
      title="Non-mutating safety contract"
      help="POST requires a fixed request marker and may additionally require a response marker. Auth material and secrets are prohibited in stored bodies."
    >
      <div className="grid three">
        <Select
          label="Operation"
          value={contract.operationType}
          values={opts(capability, "operation")}
          onChange={(value) =>
            onChange((entry) => {
              entry.safetyContract.operationType =
                value as typeof contract.operationType;
            })
          }
        />
        <Select
          label="Environment"
          value={contract.environment}
          values={opts(capability, "environment")}
          onChange={(value) =>
            onChange((entry) => {
              entry.safetyContract.environment =
                value as typeof contract.environment;
            })
          }
        />
        <Check
          label="Operator confirms non-mutating"
          checked={contract.operatorConfirmedNonMutating}
          onChange={() => undefined}
        />
        <Field
          workflow={workflow}
          diagnostics={diagnostics}
          fieldPath={path("safetyContract.requiredRequestMarkerPath")}
          label="Dry-run request marker path"
          value={contract.requiredRequestMarkerPath ?? ""}
          onChange={(value) =>
            onChange((entry) =>
              setOptional(
                entry.safetyContract,
                "requiredRequestMarkerPath",
                value,
              ),
            )
          }
        />
        <ScalarEditor
          label="Dry-run request marker value"
          value={contract.requiredRequestMarkerValue}
          onChange={(value) =>
            onChange((entry) =>
              setOptionalScalar(
                entry.safetyContract,
                "requiredRequestMarkerValue",
                value,
              ),
            )
          }
        />
        <Field
          workflow={workflow}
          diagnostics={diagnostics}
          fieldPath={path("safetyContract.requiredResponseMarkerPath")}
          label="Response marker path"
          value={contract.requiredResponseMarkerPath ?? ""}
          onChange={(value) =>
            onChange((entry) =>
              setOptional(
                entry.safetyContract,
                "requiredResponseMarkerPath",
                value,
              ),
            )
          }
        />
        <ScalarEditor
          label="Response marker value"
          value={contract.requiredResponseMarkerValue}
          onChange={(value) =>
            onChange((entry) =>
              setOptionalScalar(
                entry.safetyContract,
                "requiredResponseMarkerValue",
                value,
              ),
            )
          }
        />
        <Check
          label="Prohibit asynchronous responses"
          checked={contract.prohibitAsync}
          onChange={(value) =>
            onChange((entry) => {
              entry.safetyContract.prohibitAsync = value;
            })
          }
        />
        <Check
          label="Prohibit downloads"
          checked={contract.prohibitDownloads}
          onChange={(value) =>
            onChange((entry) => {
              entry.safetyContract.prohibitDownloads = value;
            })
          }
        />
      </div>
      <StringList
        label="Disallowed response paths"
        values={contract.disallowedResponsePaths}
        onChange={(value) =>
          onChange((entry) => {
            entry.safetyContract.disallowedResponsePaths = value;
          })
        }
      />
      <NumberList
        label="Disallowed status codes"
        values={contract.disallowedStatusCodes}
        onChange={(value) =>
          onChange((entry) => {
            entry.safetyContract.disallowedStatusCodes = value;
          })
        }
      />
    </Section>
  );
}

function ResponseContractEditor({
  item,
  capability,
  diagnostics,
  workflow,
  path,
  onChange,
}: {
  item: BulkDraft["config"]["definitions"][number]["cases"][number];
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  workflow: BulkDraft;
  path(suffix: string): string;
  onChange(mutate: (value: typeof item) => void): void;
}) {
  const response = item.responseContract;
  const fields = [
    "resultArrayPath",
    "resultObjectIdPath",
    "perObjectDecisionPath",
    "rejectedArrayPath",
    "rejectedObjectIdPath",
    "overallDecisionPath",
    "previewCountPath",
  ] as const;
  return (
    <Section
      title="Response contract"
      help="Only configured response paths are evaluated. RouteCairn does not discover additional objects or fields."
    >
      <Select
        label="Response shape"
        value={response.type}
        values={opts(capability, "responseContract")}
        onChange={(value) =>
          onChange((entry) => {
            entry.responseContract.type = value as typeof response.type;
          })
        }
      />
      <div className="grid three">
        {fields.map((field) => (
          <Field
            key={field}
            workflow={workflow}
            diagnostics={diagnostics}
            fieldPath={path(`responseContract.${field}`)}
            label={human(field)}
            value={response[field] ?? ""}
            onChange={(value) =>
              onChange((entry) =>
                setOptional(entry.responseContract, field, value),
              )
            }
          />
        ))}
        <NumberField
          label="Maximum result items"
          value={response.maxItems}
          onChange={(value) =>
            onChange((entry) => {
              entry.responseContract.maxItems = value;
            })
          }
        />
      </div>
      <StringList
        label="Retained metadata paths"
        values={response.metadataPaths}
        onChange={(value) =>
          onChange((entry) => {
            entry.responseContract.metadataPaths = value;
          })
        }
      />
    </Section>
  );
}

function PostconditionEditor({
  value,
  actors,
  diagnostics,
  workflow,
  basePath,
  onChange,
  onRemove,
}: {
  value: BulkPostcondition;
  actors: Actor[];
  diagnostics: readonly WorkflowValidationDiagnostic[];
  workflow: BulkDraft;
  basePath: string;
  onChange(value: BulkPostcondition): void;
  onRemove(): void;
}) {
  const set = <K extends keyof typeof value>(key: K, next: (typeof value)[K]) =>
    onChange({ ...value, [key]: next });
  return (
    <fieldset className="nested-builder">
      <legend>{value.id}</legend>
      <div className="grid three">
        <Text
          label="Check ID"
          value={value.id}
          onChange={(next) => set("id", next)}
        />
        <Select
          label="Actor"
          value={value.actorId}
          values={actors.map((actor) => actor.id)}
          onChange={(next) => set("actorId", next)}
        />
        <Text
          label="Exact object ID"
          value={value.objectId}
          onChange={(next) => set("objectId", next)}
        />
        <Text
          label="Safe GET with {{OBJECT_ID}}"
          value={value.url}
          onChange={(next) => set("url", next)}
        />
        <Field
          workflow={workflow}
          diagnostics={diagnostics}
          fieldPath={`${basePath}.objectIdentityField`}
          label="Object identity path"
          value={value.objectIdentityField}
          onChange={(next) => set("objectIdentityField", next)}
        />
        <Field
          workflow={workflow}
          diagnostics={diagnostics}
          fieldPath={`${basePath}.objectStateField`}
          label="Object state path"
          value={value.objectStateField ?? ""}
          onChange={(next) =>
            optionalCopy(value, "objectStateField", next, onChange)
          }
        />
        <Check
          label="Require verified identity"
          checked={value.requireVerifiedIdentity}
          onChange={(next) => set("requireVerifiedIdentity", next)}
        />
        <Optional
          label="Expected tenant"
          value={value.expectedTenantId}
          onChange={(next) =>
            optionalCopy(value, "expectedTenantId", next, onChange)
          }
        />
        <Optional
          label="Expected role"
          value={value.expectedRole}
          onChange={(next) =>
            optionalCopy(value, "expectedRole", next, onChange)
          }
        />
      </div>
      <HeaderEditor
        headers={value.headers}
        onChange={(next) => set("headers", next)}
      />
      <div
        className="field-row-table"
        role="table"
        aria-label="State fields compared before and after POST"
      >
        {value.fields.map((field, index) => (
          <div
            className="semantic-row"
            role="row"
            key={`${field.path}-${index}`}
          >
            <Field
              workflow={workflow}
              diagnostics={diagnostics}
              fieldPath={`${basePath}.fields.${index}.path`}
              label="State field path"
              value={field.path}
              onChange={(next) => {
                const copy = structuredClone(value);
                copy.fields[index]!.path = next;
                onChange(copy);
              }}
            />
            <ScalarEditor
              label="Expected precondition value"
              value={field.expectedValue}
              onChange={(next) => {
                const copy = structuredClone(value);
                setOptionalScalar(copy.fields[index]!, "expectedValue", next);
                onChange(copy);
              }}
            />
            <button
              type="button"
              disabled={value.fields.length === 1}
              onClick={() => {
                const copy = structuredClone(value);
                copy.fields.splice(index, 1);
                onChange(copy);
              }}
            >
              Remove field
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        onClick={() =>
          set("fields", [
            ...value.fields,
            { path: `state.field${value.fields.length + 1}` },
          ])
        }
      >
        Add state field
      </button>
      <button type="button" onClick={onRemove}>
        Remove pre/postcondition check
      </button>
    </fieldset>
  );
}

export function FileWorkflowEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: SharedProps & {
  workflow: FileDraft;
  onChange(value: WorkflowDraft): void;
}) {
  const update = (config: FileDraft["config"]) =>
    onChange({ ...workflow, config });
  return (
    <div className="specialized-editor file-editor">
      <p className="domain-help">
        Every request uses an exact known file reference. Bytes are bounded and
        fingerprint-only; RouteCairn never opens, renders, extracts, executes,
        or persists file content.
      </p>
      {workflow.config.definitions.map((definition, definitionIndex) => {
        const setDefinition = (mutate: (value: typeof definition) => void) => {
          const config = structuredClone(workflow.config);
          mutate(config.definitions[definitionIndex]!);
          update(config);
        };
        return (
          <section className="domain-case" key={definition.id}>
            <div className="grid two">
              <Text
                label="Definition ID"
                value={definition.id}
                onChange={(value) =>
                  setDefinition((entry) => {
                    entry.id = value;
                  })
                }
              />
              <Text
                label="Safe label"
                value={definition.label}
                onChange={(value) =>
                  setDefinition((entry) => {
                    entry.label = value;
                  })
                }
              />
            </div>
            <ActorEditor
              actors={definition.actors}
              capability={capability}
              onChange={(actors) =>
                setDefinition((entry) => {
                  entry.actors = actors;
                })
              }
            />
            <Section
              title="Known exact files"
              help="Traversal, wildcards, ranges, generators, and response-derived file keys are rejected."
            >
              {definition.files.map((file, fileIndex) => (
                <fieldset key={file.id}>
                  <legend>{file.safeAlias ?? file.id}</legend>
                  <div className="grid three">
                    <Text
                      label="File row ID"
                      value={file.id}
                      onChange={(value) =>
                        setDefinition((entry) => {
                          entry.files[fileIndex]!.id = value;
                        })
                      }
                    />
                    <Field
                      workflow={workflow}
                      diagnostics={diagnostics}
                      fieldPath={`definitions.${definitionIndex}.files.${fileIndex}.fileRef`}
                      label="Exact file reference"
                      value={file.fileRef}
                      onChange={(value) =>
                        setDefinition((entry) => {
                          entry.files[fileIndex]!.fileRef = value;
                        })
                      }
                    />
                    <Optional
                      label="Safe alias"
                      value={file.safeAlias}
                      onChange={(value) =>
                        setDefinition((entry) =>
                          setOptional(
                            entry.files[fileIndex]!,
                            "safeAlias",
                            value,
                          ),
                        )
                      }
                    />
                    <Optional
                      label="File type"
                      value={file.fileType}
                      onChange={(value) =>
                        setDefinition((entry) =>
                          setOptional(
                            entry.files[fileIndex]!,
                            "fileType",
                            value,
                          ),
                        )
                      }
                    />
                    <Select
                      label="Owner actor"
                      value={file.ownerActorId ?? ""}
                      values={[
                        "",
                        ...definition.actors.map((actor) => actor.id),
                      ]}
                      onChange={(value) =>
                        setDefinition((entry) =>
                          setOptional(
                            entry.files[fileIndex]!,
                            "ownerActorId",
                            value,
                          ),
                        )
                      }
                    />
                    <Optional
                      label="Tenant"
                      value={file.tenantId}
                      onChange={(value) =>
                        setDefinition((entry) =>
                          setOptional(
                            entry.files[fileIndex]!,
                            "tenantId",
                            value,
                          ),
                        )
                      }
                    />
                    <Optional
                      label="File state"
                      value={file.state}
                      onChange={(value) =>
                        setDefinition((entry) =>
                          setOptional(entry.files[fileIndex]!, "state", value),
                        )
                      }
                    />
                    <Check
                      label="Expected public"
                      checked={file.expectedPublic}
                      onChange={(value) =>
                        setDefinition((entry) => {
                          entry.files[fileIndex]!.expectedPublic = value;
                        })
                      }
                    />
                  </div>
                  <button
                    type="button"
                    disabled={definition.files.length === 1}
                    onClick={() =>
                      setDefinition((entry) => {
                        entry.files.splice(fileIndex, 1);
                      })
                    }
                  >
                    Remove file
                  </button>
                </fieldset>
              ))}
              <button
                type="button"
                onClick={() =>
                  setDefinition((entry) =>
                    entry.files.push({
                      id: `file-${entry.files.length + 1}`,
                      fileRef: `exact-file-${entry.files.length + 1}`,
                      safeAlias: `Known file ${entry.files.length + 1}`,
                      expectedPublic: false,
                    }),
                  )
                }
              >
                Add exact file
              </button>
            </Section>
            {definition.cases.map((item, caseIndex) => (
              <FileCaseEditor
                key={workflow.uiCaseIds[caseIndex] ?? item.id}
                workflow={workflow}
                definitionIndex={definitionIndex}
                caseIndex={caseIndex}
                item={item}
                actors={definition.actors}
                files={definition.files}
                capability={capability}
                diagnostics={diagnostics}
                onChange={(mutate) =>
                  setDefinition((entry) => mutate(entry.cases[caseIndex]!))
                }
              />
            ))}
          </section>
        );
      })}
      <Limits
        values={{
          maxDefinitions: workflow.config.maxDefinitions,
          maxCasesPerDefinition: workflow.config.maxCasesPerDefinition,
          maxFilesPerDefinition: workflow.config.maxFilesPerDefinition,
          maxRequests: workflow.config.maxRequests,
          maxRetainedObservations: workflow.config.maxRetainedObservations,
        }}
        onChange={(key, value) => update({ ...workflow.config, [key]: value })}
      />
    </div>
  );
}

function FileCaseEditor({
  workflow,
  definitionIndex,
  caseIndex,
  item,
  actors,
  files,
  capability,
  diagnostics,
  onChange,
}: {
  workflow: FileDraft;
  definitionIndex: number;
  caseIndex: number;
  item: FileDraft["config"]["definitions"][number]["cases"][number];
  actors: FileDraft["config"]["definitions"][number]["actors"];
  files: FileDraft["config"]["definitions"][number]["files"];
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  onChange(mutate: (value: typeof item) => void): void;
}) {
  const base = `definitions.${definitionIndex}.cases.${caseIndex}`;
  const signed =
    item.contentProofMode === "SIGNED_URL_ONLY" ||
    item.category === "SIGNED_URL_ISSUANCE" ||
    item.category === "SIGNED_URL_DOWNLOAD";
  const fingerprint =
    item.identityStrategy === "OPERATOR_SUPPLIED_FINGERPRINT" ||
    item.contentProofMode === "FULL_STREAM_FINGERPRINT" ||
    item.followSignedUrl;
  return (
    <section className="workflow-subcase" aria-label={`File case ${item.id}`}>
      <header>
        <div>
          <h5>{item.label}</h5>
          <span className="status-text">{human(item.contentProofMode)}</span>
        </div>
      </header>
      <div className="grid three">
        <Text
          label="Case ID"
          value={item.id}
          onChange={(value) =>
            onChange((entry) => {
              entry.id = value;
            })
          }
        />
        <Text
          label="Safe label"
          value={item.label}
          onChange={(value) =>
            onChange((entry) => {
              entry.label = value;
            })
          }
        />
        <Select
          label="Category"
          value={item.category}
          values={opts(capability, "category")}
          onChange={(value) =>
            onChange((entry) => {
              entry.category = value as typeof entry.category;
            })
          }
        />
        <Select
          label="Actor"
          value={item.actorId}
          values={actors.map((actor) => actor.id)}
          onChange={(value) =>
            onChange((entry) => {
              entry.actorId = value;
            })
          }
        />
        <Select
          label="Known file"
          value={item.fileRefId}
          values={files.map((file) => file.id)}
          onChange={(value) =>
            onChange((entry) => {
              entry.fileRefId = value;
            })
          }
        />
        <Select
          label="Method"
          value={item.method}
          values={capability.safeMethods}
          onChange={(value) =>
            onChange((entry) => {
              entry.method = value as typeof entry.method;
            })
          }
        />
        <Text
          label={`Exact URL with {{${item.placeholder}}}`}
          value={item.url}
          onChange={(value) =>
            onChange((entry) => {
              entry.url = value;
            })
          }
        />
        <Select
          label="Placeholder"
          value={item.placeholder}
          values={opts(capability, "placeholder")}
          onChange={(value) =>
            onChange((entry) => {
              entry.placeholder = value as typeof entry.placeholder;
            })
          }
        />
        <Select
          label="Expected decision"
          value={item.expectedDecision}
          values={capability.expectationTypes}
          onChange={(value) =>
            onChange((entry) => {
              entry.expectedDecision = value as typeof entry.expectedDecision;
            })
          }
        />
      </div>
      <HeaderEditor
        headers={item.headers}
        onChange={(headers) =>
          onChange((entry) => {
            entry.headers = headers;
          })
        }
      />
      <Section
        title="Identity and policy"
        help="A filename or content type never proves file identity."
      >
        <div className="grid three">
          <Select
            label="Identity strategy"
            value={item.identityStrategy}
            values={opts(capability, "identityStrategy")}
            onChange={(value) =>
              onChange((entry) => {
                entry.identityStrategy = value as typeof entry.identityStrategy;
              })
            }
          />
          {item.identityStrategy === "METADATA_FIELD_MATCH" && (
            <Field
              workflow={workflow}
              diagnostics={diagnostics}
              fieldPath={`${base}.identityField`}
              label="Metadata identity path"
              value={item.identityField ?? ""}
              onChange={(value) =>
                onChange((entry) => setOptional(entry, "identityField", value))
              }
            />
          )}
          <Field
            workflow={workflow}
            diagnostics={diagnostics}
            fieldPath={`${base}.stateField`}
            label="File state path"
            value={item.stateField ?? ""}
            onChange={(value) =>
              onChange((entry) => setOptional(entry, "stateField", value))
            }
          />
          {fingerprint && (
            <Field
              workflow={workflow}
              diagnostics={diagnostics}
              fieldPath={`${base}.expectedFingerprint`}
              label="Expected SHA-256 fingerprint"
              value={item.expectedFingerprint ?? ""}
              onChange={(value) =>
                onChange((entry) =>
                  setOptional(entry, "expectedFingerprint", value),
                )
              }
            />
          )}
          <Check
            label="Require verified identity"
            checked={item.requireVerifiedIdentity}
            onChange={(value) =>
              onChange((entry) => {
                entry.requireVerifiedIdentity = value;
              })
            }
          />
          <Optional
            label="Expected tenant"
            value={item.expectedTenantId}
            onChange={(value) =>
              onChange((entry) => setOptional(entry, "expectedTenantId", value))
            }
          />
          <Optional
            label="Expected role"
            value={item.expectedRole}
            onChange={(value) =>
              onChange((entry) => setOptional(entry, "expectedRole", value))
            }
          />
          <Optional
            label="Expected account state"
            value={item.expectedAccountState}
            onChange={(value) =>
              onChange((entry) =>
                setOptional(entry, "expectedAccountState", value),
              )
            }
          />
          <Optional
            label="Expected file state"
            value={item.expectedFileState}
            onChange={(value) =>
              onChange((entry) =>
                setOptional(entry, "expectedFileState", value),
              )
            }
          />
        </div>
      </Section>
      <Section
        title="File proof mode"
        help="Evidence is bounded and does not overstate what the selected request can prove."
      >
        <Select
          label="Content proof mode"
          value={item.contentProofMode}
          values={opts(capability, "proofMode")}
          onChange={(value) =>
            onChange((entry) => {
              entry.contentProofMode = value as typeof entry.contentProofMode;
              if (value === "BOUNDED_PREFIX" && !entry.rangeLength)
                entry.rangeLength = 4096;
            })
          }
        />
        <p className="proof-explanation" role="note">
          {proofModeHelp[item.contentProofMode]}
        </p>
        <div className="grid three">
          {item.contentProofMode === "BOUNDED_PREFIX" && (
            <>
              <NumberField
                label="Range start"
                value={item.rangeStart}
                min={0}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.rangeStart = value;
                  })
                }
              />
              <NumberField
                label="Prefix byte limit"
                value={item.rangeLength ?? 4096}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.rangeLength = value;
                  })
                }
              />
              <NumberField
                label="Probe byte cap"
                value={item.maxProbeBytes}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.maxProbeBytes = value;
                  })
                }
              />
            </>
          )}
          {item.contentProofMode === "FULL_STREAM_FINGERPRINT" && (
            <NumberField
              label="Full-stream byte cap"
              value={item.maxFullStreamBytes}
              onChange={(value) =>
                onChange((entry) => {
                  entry.maxFullStreamBytes = value;
                })
              }
            />
          )}
          {["HEADERS_ONLY", "METADATA_ONLY", "SIGNED_URL_ONLY"].includes(
            item.contentProofMode,
          ) && (
            <NumberField
              label="Metadata byte cap"
              value={item.maxMetadataBytes}
              onChange={(value) =>
                onChange((entry) => {
                  entry.maxMetadataBytes = value;
                })
              }
            />
          )}
        </div>
      </Section>
      <Section
        title="Redirect policy"
        help="Redirects remain scope checked and may only use exact approved origins."
      >
        <DiagnosticStringList
          workflow={workflow}
          diagnostics={diagnostics}
          basePath={`${base}.allowedRedirectOrigins`}
          label="Allowed redirect origins"
          values={item.allowedRedirectOrigins}
          onChange={(value) =>
            onChange((entry) => {
              entry.allowedRedirectOrigins = value;
            })
          }
        />
      </Section>
      {signed && (
        <Section
          title="Signed URL issuance and follow"
          help="Receiving a signed URL and successfully downloading from it are separate observations."
        >
          <Field
            workflow={workflow}
            diagnostics={diagnostics}
            fieldPath={`${base}.signedUrlField`}
            label="Issuance JSON field"
            value={item.signedUrlField ?? ""}
            onChange={(value) =>
              onChange((entry) => setOptional(entry, "signedUrlField", value))
            }
          />
          <Check
            label="Explicitly follow one signed URL"
            checked={item.followSignedUrl}
            onChange={(value) =>
              onChange((entry) => {
                entry.followSignedUrl = value;
                if (value)
                  entry.identityStrategy = "OPERATOR_SUPPLIED_FINGERPRINT";
              })
            }
          />
          {item.followSignedUrl && (
            <div className="signed-url-warning" role="alert">
              <strong>Signed URL follow enabled.</strong>
              <p>
                Exactly one returned URL may be followed only when its origin
                matches this allowlist and its bounded content matches the
                operator-supplied fingerprint.
              </p>
              <DiagnosticStringList
                workflow={workflow}
                diagnostics={diagnostics}
                basePath={`${base}.allowedSignedUrlOrigins`}
                label="Exact allowed storage origins"
                values={item.allowedSignedUrlOrigins}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.allowedSignedUrlOrigins = value;
                  })
                }
              />
              <NumberField
                label="Signed download byte cap"
                value={item.maxFullStreamBytes}
                onChange={(value) =>
                  onChange((entry) => {
                    entry.maxFullStreamBytes = value;
                  })
                }
              />
            </div>
          )}
        </Section>
      )}
    </section>
  );
}

function JsonBodyEditor({
  value,
  onValid,
  onInvalid,
}: {
  value: unknown;
  onValid(value: unknown): void;
  onInvalid(): void;
}) {
  const [text, setText] = useState(() =>
    JSON.stringify(
      value ?? { objectIds: "{{OBJECT_IDS_ARRAY}}", dryRun: true },
      null,
      2,
    ),
  );
  const [error, setError] = useState("");
  useEffect(() => {
    try {
      if (JSON.stringify(JSON.parse(text)) !== JSON.stringify(value))
        setText(
          JSON.stringify(
            value ?? { objectIds: "{{OBJECT_IDS_ARRAY}}", dryRun: true },
            null,
            2,
          ),
        );
    } catch {
      /* Preserve invalid in-progress text until the operator fixes it. */
    }
  }, [value]);
  const parse = (next: string, format = false) => {
    setText(next);
    if (new TextEncoder().encode(next).byteLength > 65536) {
      setError("Body exceeds the 64 KiB guided editor limit.");
      onInvalid();
      return;
    }
    if (/(?:__proto__|prototype|constructor)/i.test(next)) {
      setError("Prototype keys are not allowed.");
      onInvalid();
      return;
    }
    if (
      /(?:=>|function\s*\(|eval\s*\(|for\s*\(|while\s*\(|\$\(|<%)/i.test(next)
    ) {
      setError("Executable expressions and generators are not allowed.");
      onInvalid();
      return;
    }
    if (
      /(?:authorization|cookie|session|token|secret|password|api[_-]?key)/i.test(
        next,
      )
    ) {
      setError(
        "Secrets and authentication material are prohibited in stored bodies.",
      );
      onInvalid();
      return;
    }
    try {
      const parsed: unknown = JSON.parse(next);
      setError("");
      onValid(parsed);
      if (format) setText(JSON.stringify(parsed, null, 2));
    } catch {
      setError("Enter valid JSON.");
      onInvalid();
    }
  };
  return (
    <fieldset className="json-body-editor">
      <legend>Fixed JSON body</legend>
      <p>
        Use one literal <code>{"{{OBJECT_IDS_ARRAY}}"}</code> value. JavaScript,
        loops, generators, response placeholders, and secrets are prohibited.
      </p>
      <textarea
        aria-label="Fixed JSON body"
        aria-invalid={Boolean(error)}
        value={text}
        onChange={(event) => parse(event.target.value)}
      />
      {error && <small role="alert">{error}</small>}
      <button type="button" onClick={() => parse(text, true)}>
        Format JSON
      </button>
    </fieldset>
  );
}

function ActorEditor<T extends EditableActor>({
  actors,
  capability,
  onChange,
}: {
  actors: T[];
  capability: WorkflowCapability;
  onChange(value: T[]): void;
}) {
  return (
    <Section
      title="Actors"
      help="Actors bind only to the controlled public, Account A, or Account B contexts."
    >
      {actors.map((actor, index) => (
        <fieldset key={`${actor.id}-${index}`}>
          <legend>{actor.safeAlias ?? actor.id}</legend>
          <div className="grid three">
            <Text
              label="Actor ID"
              value={actor.id}
              onChange={(value) =>
                change(index, (entry) => {
                  entry.id = value;
                })
              }
            />
            <Select
              label="Relationship"
              value={actor.relationship}
              values={opts(capability, "relationship")}
              onChange={(value) =>
                change(index, (entry) => {
                  entry.relationship = value;
                })
              }
            />
            <Select
              label="Authentication"
              value={actor.authProfile ?? ""}
              values={["", "account_a", "account_b"]}
              onChange={(value) =>
                change(index, (entry) =>
                  setOptional(entry, "authProfile", value),
                )
              }
            />
            <Optional
              label="Safe alias"
              value={actor.safeAlias}
              onChange={(value) =>
                change(index, (entry) => setOptional(entry, "safeAlias", value))
              }
            />
            <Optional
              label="Principal ID"
              value={actor.principalId}
              onChange={(value) =>
                change(index, (entry) =>
                  setOptional(entry, "principalId", value),
                )
              }
            />
            <Optional
              label="Tenant"
              value={actor.tenantId}
              onChange={(value) =>
                change(index, (entry) => setOptional(entry, "tenantId", value))
              }
            />
            <Optional
              label="Role"
              value={actor.role}
              onChange={(value) =>
                change(index, (entry) => setOptional(entry, "role", value))
              }
            />
            <Optional
              label="Account state"
              value={actor.accountState}
              onChange={(value) =>
                change(index, (entry) =>
                  setOptional(entry, "accountState", value),
                )
              }
            />
          </div>
        </fieldset>
      ))}
      <button
        type="button"
        onClick={() => {
          const next = structuredClone(actors);
          const actor = structuredClone(actors[0]!);
          actor.id = `actor-${actors.length + 1}`;
          actor.relationship = "PUBLIC";
          actor.safeAlias = `Actor ${actors.length + 1}`;
          delete actor.authProfile;
          delete actor.principalId;
          next.push(actor);
          onChange(next);
        }}
      >
        Add actor
      </button>
    </Section>
  );
  function change(index: number, mutate: (value: EditableActor) => void) {
    const next = structuredClone(actors);
    mutate(next[index]!);
    onChange(next);
  }
}
