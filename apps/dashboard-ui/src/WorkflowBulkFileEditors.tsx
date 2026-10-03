
import type { WorkflowCapability, WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { type WorkflowValidationDiagnostic } from "./WorkflowDiagnostics";
import { Check, Field, HeaderEditor, Limits, NumberField, NumberList, Optional, ScalarEditor, Section, Select, StringList, Text, defaultBaseline, defaultPostcondition, human, optionalCopy, opts, safetyModeHelp, setOptional, setOptionalScalar } from "./WorkflowBulkFileControls";
import { type SharedProps, type BulkDraft, type Actor, type BulkBaseline, type BulkPostcondition } from "./WorkflowBulkFileTypes";
import { ActorEditor, JsonBodyEditor } from "./WorkflowBulkFileSharedEditors";

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

export function BulkCaseEditor({
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

export function BaselineEditor({
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

export function SafetyContractEditor({
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

export function ResponseContractEditor({
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

export function PostconditionEditor({
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

export { FileWorkflowEditor } from "./WorkflowFileEditors";
