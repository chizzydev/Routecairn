import React, { useMemo, useState } from "react";
import type {
  WorkflowCapability,
  WorkflowDraft,
} from "./AuthorizationWorkflowStudio";
import {
  diagnosticFieldId,
  type WorkflowValidationDiagnostic,
} from "./WorkflowDiagnostics";
import {
  BulkWorkflowEditor,
  FileWorkflowEditor,
} from "./WorkflowBulkFileEditors";

import {
  ActorList,
  Check,
  FieldText,
  HeaderEditor,
  Limits,
  ObjectAssertion,
  OptionalField,
  Relationship,
  RowActions,
  ScalarValue,
  Section,
  Select,
  StringList,
  Text,
  human,
  move,
  options,
  setOptional,
  uiId,
} from "./WorkflowSpecializedControls";

interface Props {
  workflow: WorkflowDraft;
  capability: WorkflowCapability;
  diagnostics: readonly WorkflowValidationDiagnostic[];
  onChange(workflow: WorkflowDraft): void;
}

type Actor = {
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

export function SpecializedWorkflowEditor(props: Props) {
  switch (props.workflow.workflowId) {
    case "object-pair":
      return <ObjectPairEditor {...props} workflow={props.workflow} />;
    case "field-exposure":
      return <FieldExposureEditor {...props} workflow={props.workflow} />;
    case "authorization-matrix":
      return <MatrixEditor {...props} workflow={props.workflow} />;
    case "equivalent-route":
      return <EquivalentRouteEditor {...props} workflow={props.workflow} />;
    case "collection-authorization":
      return <CollectionEditor {...props} workflow={props.workflow} />;
    case "bulk-authorization":
      return <BulkEditor {...props} workflow={props.workflow} />;
    case "file-authorization":
      return <FileEditor {...props} workflow={props.workflow} />;
  }
}

function ObjectPairEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: Props & {
  workflow: Extract<WorkflowDraft, { workflowId: "object-pair" }>;
}) {
  const update = (config: typeof workflow.config) =>
    onChange({ ...workflow, config });
  const setPrincipal = (
    account: "accountA" | "accountB",
    key: "expectedAccountId" | "tenantId" | "role",
    value: string,
  ) => {
    const config = structuredClone(workflow.config);
    setOptional(config.principals[account], key, value);
    update(config);
  };
  return (
    <div className="specialized-editor object-pair-editor">
      <Section
        title="Principal declarations"
        help="Declared principal, tenant, and role metadata are checked against the verified Account A and Account B contexts."
      >
        <div className="grid two">
          {(["accountA", "accountB"] as const).map((account) => (
            <fieldset key={account}>
              <legend>
                {account === "accountA" ? "Account A" : "Account B"}
              </legend>
              <Text
                label="Expected principal"
                value={
                  workflow.config.principals[account].expectedAccountId ?? ""
                }
                onChange={(value) =>
                  setPrincipal(account, "expectedAccountId", value)
                }
              />
              <Text
                label="Tenant"
                value={workflow.config.principals[account].tenantId ?? ""}
                onChange={(value) => setPrincipal(account, "tenantId", value)}
              />
              <Text
                label="Role"
                value={workflow.config.principals[account].role ?? ""}
                onChange={(value) => setPrincipal(account, "role", value)}
              />
            </fieldset>
          ))}
        </div>
      </Section>
      {workflow.config.cases.map((item, index) => {
        const uiCaseId = workflow.uiCaseIds[index] ?? `case-${index}`;
        const identityValid = Boolean(
          workflow.config.principals.accountA.expectedAccountId &&
            workflow.config.principals.accountB.expectedAccountId &&
            workflow.config.principals.accountA.expectedAccountId !==
              workflow.config.principals.accountB.expectedAccountId,
        );
        const relationshipDecision = objectPairDecision(
          item.expectedVisibility,
          identityValid,
        );
        const setCase = (mutate: (value: typeof item) => void) => {
          const config = structuredClone(workflow.config);
          mutate(config.cases[index]!);
          update(config);
        };
        return (
          <section
            className="domain-case"
            key={uiCaseId}
            aria-label={`Object Pair relationship ${index + 1}`}
          >
            <header>
              <div>
                <h5>{item.id}</h5>
                <span className="status-text">Four fixed requests</span>
              </div>
            </header>
            <div
              className="relationship-grid"
              role="img"
              aria-label={`Account A owns Object A and Account B owns Object B. Baselines test each owner against their object. Cross-owner probes test Account A against Object B and Account B against Object A.`}
            >
              <Relationship
                from="Account A"
                kind="Owner baseline"
                to="Object A"
                decision={relationshipDecision.owner}
              />
              <Relationship
                from="Account B"
                kind="Owner baseline"
                to="Object B"
                decision={relationshipDecision.owner}
              />
              <Relationship
                from="Account A"
                kind="Cross-owner probe"
                to="Object B"
                decision={relationshipDecision.cross}
              />
              <Relationship
                from="Account B"
                kind="Cross-owner probe"
                to="Object A"
                decision={relationshipDecision.cross}
              />
            </div>
            <div className="grid three">
              <FieldText
                workflow={workflow}
                diagnostics={diagnostics}
                path={`cases.${index}.id`}
                label="Case name"
                value={item.id}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.id = value;
                  })
                }
              />
              <Text
                label="Object type"
                value={item.objectType}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.objectType = value;
                  })
                }
              />
              <Select
                label="Visibility policy"
                value={item.expectedVisibility}
                options={options(capability, "expectedVisibility")}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.expectedVisibility =
                      value as typeof entry.expectedVisibility;
                  })
                }
              />
            </div>
            <Section
              title="Exact request template"
              help="The planner substitutes only the declared object and optional tenant placeholders; it never generates identifiers."
            >
              <div className="grid three">
                <Text
                  label="Template ID"
                  value={item.template.id}
                  onChange={(value) =>
                    setCase((entry) => {
                      entry.template.id = value;
                    })
                  }
                />
                <Select
                  label="Method"
                  value={item.template.method}
                  options={capability.safeMethods}
                  onChange={(value) =>
                    setCase((entry) => {
                      entry.template.method = value as "GET" | "HEAD";
                    })
                  }
                />
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`cases.${index}.template.url`}
                  label="Endpoint with {{OBJECT_ID}}"
                  value={item.template.url}
                  onChange={(value) =>
                    setCase((entry) => {
                      entry.template.url = value;
                    })
                  }
                />
              </div>
              <HeaderEditor
                value={item.template.headers}
                onChange={(headers) =>
                  setCase((entry) => {
                    entry.template.headers = headers;
                  })
                }
              />
            </Section>
            <div className="grid two">
              <ObjectAssertion
                title="Account A object"
                value={item.accountAObject}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.accountAObject = value;
                  })
                }
              />
              <ObjectAssertion
                title="Account B object"
                value={item.accountBObject}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.accountBObject = value;
                  })
                }
              />
            </div>
          </section>
        );
      })}
      <Limits
        values={{ maxPairs: workflow.config.maxPairs }}
        onChange={(key, value) => update({ ...workflow.config, [key]: value })}
      />
    </div>
  );
}

function FieldExposureEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: Props & {
  workflow: Extract<WorkflowDraft, { workflowId: "field-exposure" }>;
}) {
  const update = (config: typeof workflow.config) =>
    onChange({ ...workflow, config });
  return (
    <div className="specialized-editor field-exposure-editor">
      <p className="domain-help">
        Configure exact response paths. RouteCairn does not inspect a response
        to discover fields or suggest paths.
      </p>
      {workflow.config.cases.map((item, caseIndex) => {
        const setCase = (mutate: (value: typeof item) => void) => {
          const config = structuredClone(workflow.config);
          mutate(config.cases[caseIndex]!);
          update(config);
        };
        return (
          <section className="domain-case" key={workflow.uiCaseIds[caseIndex]}>
            <div className="grid three">
              <Text
                label="Case name"
                value={item.id}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.id = value;
                  })
                }
              />
              <Text
                label="Exact object ID"
                value={item.objectId}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.objectId = value;
                  })
                }
              />
              <Select
                label="Visibility"
                value={item.expectedVisibility}
                options={options(capability, "visibility")}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.expectedVisibility =
                      value as typeof entry.expectedVisibility;
                  })
                }
              />
              <Text
                label="Object type"
                value={item.objectType}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.objectType = value;
                  })
                }
              />
              <Text
                label="Owner actor ID"
                value={item.declaredOwnerActor}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.declaredOwnerActor = value;
                  })
                }
              />
              <Check
                label="Require verified identity"
                checked={item.requireVerifiedIdentity}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.requireVerifiedIdentity = value;
                  })
                }
              />
            </div>
            <Section
              title="Endpoint and identity"
              help="The object identity field confirms that the response belongs to the exact supplied object."
            >
              <Text
                label="Endpoint with {{OBJECT_ID}}"
                value={item.template.url}
                onChange={(value) =>
                  setCase((entry) => {
                    entry.template.url = value;
                  })
                }
              />
              <div className="grid three">
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`cases.${caseIndex}.objectConfirmation.expectedObjectIdField`}
                  label="Object ID path"
                  value={item.objectConfirmation.expectedObjectIdField}
                  onChange={(value) =>
                    setCase((entry) => {
                      entry.objectConfirmation.expectedObjectIdField = value;
                    })
                  }
                />
                <OptionalField
                  label="Owner path"
                  value={item.objectConfirmation.expectedOwnerField}
                  onChange={(value) =>
                    setCase((entry) =>
                      setOptional(
                        entry.objectConfirmation,
                        "expectedOwnerField",
                        value,
                      ),
                    )
                  }
                />
                <OptionalField
                  label="Tenant path"
                  value={item.objectConfirmation.expectedTenantField}
                  onChange={(value) =>
                    setCase((entry) =>
                      setOptional(
                        entry.objectConfirmation,
                        "expectedTenantField",
                        value,
                      ),
                    )
                  }
                />
              </div>
            </Section>
            <ActorList
              actors={item.actors}
              relationshipKey="type"
              options={options(capability, "actorType")}
              onChange={(actors) =>
                setCase((entry) => {
                  entry.actors = actors as typeof entry.actors;
                })
              }
            />
            <Section
              title="Field expectations"
              help="Each row maps a human-readable expectation directly to the scanner enum shown beneath it."
            >
              <div
                className="field-row-table"
                role="table"
                aria-label="Configured field expectations"
              >
                <div className="semantic-row head" role="row">
                  <span role="columnheader">Field and path</span>
                  <span role="columnheader">Expectation</span>
                  <span role="columnheader">Actor baselines</span>
                  <span role="columnheader">Actions</span>
                </div>
                {item.fieldExpectations.map((field, fieldIndex) => {
                  const path = `cases.${caseIndex}.fieldExpectations.${fieldIndex}.path`;
                  return (
                    <div
                      className="semantic-row"
                      role="row"
                      key={field.id ?? `${field.path}-${fieldIndex}`}
                    >
                      <div>
                        <Text
                          label="Field row ID"
                          value={field.id ?? ""}
                          onChange={(value) =>
                            setCase((entry) =>
                              setOptional(
                                entry.fieldExpectations[fieldIndex]!,
                                "id",
                                value,
                              ),
                            )
                          }
                        />
                        <Text
                          label="Safe note"
                          value={field.label}
                          onChange={(value) =>
                            setCase((entry) => {
                              entry.fieldExpectations[fieldIndex]!.label =
                                value;
                            })
                          }
                        />
                        <FieldText
                          workflow={workflow}
                          diagnostics={diagnostics}
                          path={path}
                          label="Safe field path"
                          value={field.path}
                          onChange={(value) =>
                            setCase((entry) => {
                              entry.fieldExpectations[fieldIndex]!.path = value;
                            })
                          }
                        />
                      </div>
                      <div>
                        <label>
                          Expectation
                          <select
                            value={field.expectation}
                            onChange={(event) =>
                              setCase((entry) => {
                                entry.fieldExpectations[
                                  fieldIndex
                                ]!.expectation = event.target
                                  .value as typeof field.expectation;
                              })
                            }
                          >
                            {capability.expectationTypes.map((value) => (
                              <option key={value} value={value}>
                                {human(value)}
                              </option>
                            ))}
                          </select>
                          <small>{field.expectation}</small>
                        </label>
                        <Select
                          label="Sensitivity"
                          value={field.sensitivity}
                          options={options(capability, "sensitivity")}
                          onChange={(value) =>
                            setCase((entry) => {
                              entry.fieldExpectations[fieldIndex]!.sensitivity =
                                value as typeof field.sensitivity;
                            })
                          }
                        />
                        <Check
                          label="Allow bounded preview"
                          checked={field.allowPreview}
                          onChange={(value) =>
                            setCase((entry) => {
                              entry.fieldExpectations[
                                fieldIndex
                              ]!.allowPreview = value;
                            })
                          }
                        />
                      </div>
                      <div>
                        <StringList
                          label="Allowed actor IDs"
                          values={field.allowedActors}
                          onChange={(values) =>
                            setCase((entry) => {
                              entry.fieldExpectations[
                                fieldIndex
                              ]!.allowedActors = values;
                            })
                          }
                        />
                        <StringList
                          label="Prohibited actor IDs"
                          values={field.prohibitedActors}
                          onChange={(values) =>
                            setCase((entry) => {
                              entry.fieldExpectations[
                                fieldIndex
                              ]!.prohibitedActors = values;
                            })
                          }
                        />
                      </div>
                      <RowActions
                        index={fieldIndex}
                        length={item.fieldExpectations.length}
                        label="field"
                        onDuplicate={() =>
                          setCase((entry) => {
                            const copy = structuredClone(
                              entry.fieldExpectations[fieldIndex]!,
                            );
                            copy.id = `${copy.id ?? "field"}-copy-${entry.fieldExpectations.length + 1}`;
                            entry.fieldExpectations.splice(
                              fieldIndex + 1,
                              0,
                              copy,
                            );
                          })
                        }
                        onDelete={() =>
                          setCase((entry) => {
                            entry.fieldExpectations.splice(fieldIndex, 1);
                          })
                        }
                        onMove={(direction) =>
                          setCase((entry) =>
                            move(
                              entry.fieldExpectations,
                              fieldIndex,
                              direction,
                            ),
                          )
                        }
                      />
                    </div>
                  );
                })}
              </div>
              <button
                type="button"
                onClick={() =>
                  setCase((entry) => {
                    entry.fieldExpectations.push({
                      id: `field-${entry.fieldExpectations.length + 1}`,
                      path: "exactField",
                      label: "Exact configured field",
                      sensitivity: "PRIVATE",
                      expectation: "MUST_BE_ABSENT",
                      allowedActors: [],
                      prohibitedActors: [],
                      allowPreview: false,
                    });
                  })
                }
              >
                Add field
              </button>
            </Section>
          </section>
        );
      })}
      <Limits
        values={{
          maxCases: workflow.config.maxCases,
          maxResponseBytes: workflow.config.maxResponseBytes,
          maxPreviewLength: workflow.config.maxPreviewLength,
        }}
        onChange={(key, value) => update({ ...workflow.config, [key]: value })}
      />
    </div>
  );
}

function MatrixEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: Props & {
  workflow: Extract<WorkflowDraft, { workflowId: "authorization-matrix" }>;
}) {
  const [filters, setFilters] = useState({
    actor: "",
    tenant: "",
    role: "",
    accountState: "",
    objectState: "",
    decision: "",
  });
  const update = (
    config: typeof workflow.config,
    uiCaseIds = workflow.uiCaseIds,
  ) => onChange({ ...workflow, config, uiCaseIds });
  return (
    <div className="specialized-editor matrix-editor">
      <p className="domain-help">
        Add only explicit rows. Filters change visibility and never generate,
        remove, or mutate authorization combinations.
      </p>
      {workflow.config.matrices.map((matrix, matrixIndex) => {
        const offset = workflow.config.matrices
          .slice(0, matrixIndex)
          .reduce((sum, item) => sum + item.cases.length, 0);
        const setMatrix = (
          mutate: (value: typeof matrix) => void,
          ids = workflow.uiCaseIds,
        ) => {
          const config = structuredClone(workflow.config);
          mutate(config.matrices[matrixIndex]!);
          update(config, ids);
        };
        const visible = (row: (typeof matrix.cases)[number]) =>
          (!filters.actor || row.actorId === filters.actor) &&
          (!filters.tenant || row.expectedTenantId === filters.tenant) &&
          (!filters.role || row.expectedRole === filters.role) &&
          (!filters.accountState ||
            row.expectedAccountState === filters.accountState) &&
          (!filters.objectState ||
            row.expectedObjectState === filters.objectState) &&
          (!filters.decision || row.expectedDecision === filters.decision);
        return (
          <section className="domain-case" key={matrix.id}>
            <div className="grid three">
              <Text
                label="Matrix ID"
                value={matrix.id}
                onChange={(value) =>
                  setMatrix((entry) => {
                    entry.id = value;
                  })
                }
              />
              <Text
                label="Matrix name"
                value={matrix.name}
                onChange={(value) =>
                  setMatrix((entry) => {
                    entry.name = value;
                  })
                }
              />
              <Text
                label="Object type"
                value={matrix.objectType}
                onChange={(value) =>
                  setMatrix((entry) => {
                    entry.objectType = value;
                  })
                }
              />
              <Text
                label="Template ID"
                value={matrix.template.id}
                onChange={(value) =>
                  setMatrix((entry) => {
                    entry.template.id = value;
                  })
                }
              />
              <Text
                label="Endpoint with {{OBJECT_ID}}"
                value={matrix.template.url}
                onChange={(value) =>
                  setMatrix((entry) => {
                    entry.template.url = value;
                  })
                }
              />
              <FieldText
                workflow={workflow}
                diagnostics={diagnostics}
                path={`matrices.${matrixIndex}.objectIdentityField`}
                label="Object identity path"
                value={matrix.objectIdentityField}
                onChange={(value) =>
                  setMatrix((entry) => {
                    entry.objectIdentityField = value;
                  })
                }
              />
              <OptionalField
                label="Object state path"
                value={matrix.objectStateField}
                onChange={(value) =>
                  setMatrix((entry) =>
                    setOptional(entry, "objectStateField", value),
                  )
                }
              />
            </div>
            <HeaderEditor
              value={matrix.template.headers}
              onChange={(headers) =>
                setMatrix((entry) => {
                  entry.template.headers = headers;
                })
              }
            />
            <ActorList
              actors={matrix.actors}
              relationshipKey="relationship"
              options={options(capability, "relationship")}
              onChange={(actors) =>
                setMatrix((entry) => {
                  entry.actors = actors as typeof entry.actors;
                })
              }
            />
            <div className="matrix-filters" aria-label="Matrix row filters">
              <Select
                label="Actor filter"
                value={filters.actor}
                options={["", ...matrix.actors.map((actor) => actor.id)]}
                onChange={(actor) => setFilters({ ...filters, actor })}
              />
              <Text
                label="Tenant filter"
                value={filters.tenant}
                onChange={(tenant) => setFilters({ ...filters, tenant })}
              />
              <Text
                label="Role filter"
                value={filters.role}
                onChange={(role) => setFilters({ ...filters, role })}
              />
              <Text
                label="Account state filter"
                value={filters.accountState}
                onChange={(accountState) =>
                  setFilters({ ...filters, accountState })
                }
              />
              <Text
                label="Object state filter"
                value={filters.objectState}
                onChange={(objectState) =>
                  setFilters({ ...filters, objectState })
                }
              />
              <Select
                label="Decision filter"
                value={filters.decision}
                options={["", ...capability.expectationTypes]}
                onChange={(decision) => setFilters({ ...filters, decision })}
              />
            </div>
            <div
              className="matrix-table"
              role="table"
              aria-label="Role and state authorization rows"
            >
              <div className="matrix-row head" role="row">
                <span role="columnheader">Case</span>
                <span role="columnheader">Actor</span>
                <span role="columnheader">Object and state</span>
                <span role="columnheader">Policy context</span>
                <span role="columnheader">Expected decision</span>
                <span role="columnheader">Actions</span>
              </div>
              {matrix.cases.map(
                (row, rowIndex) =>
                  visible(row) && (
                    <div
                      className="matrix-row"
                      role="row"
                      key={workflow.uiCaseIds[offset + rowIndex] ?? row.id}
                    >
                      <div>
                        <Text
                          label="Case name"
                          value={row.id}
                          onChange={(value) =>
                            setMatrix((entry) => {
                              entry.cases[rowIndex]!.id = value;
                            })
                          }
                        />
                        <Select
                          label="Reference case"
                          value={row.referenceCaseId ?? ""}
                          options={[
                            "",
                            ...matrix.cases
                              .filter((_, index) => index !== rowIndex)
                              .map((candidate) => candidate.id),
                          ]}
                          onChange={(value) =>
                            setMatrix((entry) =>
                              setOptional(
                                entry.cases[rowIndex]!,
                                "referenceCaseId",
                                value,
                              ),
                            )
                          }
                        />
                      </div>
                      <Select
                        label="Actor"
                        value={row.actorId}
                        options={matrix.actors.map((actor) => actor.id)}
                        onChange={(value) =>
                          setMatrix((entry) => {
                            entry.cases[rowIndex]!.actorId = value;
                          })
                        }
                      />
                      <div>
                        <Text
                          label="Exact object ID"
                          value={row.objectId}
                          onChange={(value) =>
                            setMatrix((entry) => {
                              entry.cases[rowIndex]!.objectId = value;
                            })
                          }
                        />
                        <OptionalField
                          label="Object state"
                          value={row.expectedObjectState}
                          onChange={(value) =>
                            setMatrix((entry) =>
                              setOptional(
                                entry.cases[rowIndex]!,
                                "expectedObjectState",
                                value,
                              ),
                            )
                          }
                        />
                      </div>
                      <div>
                        <OptionalField
                          label="Tenant"
                          value={row.expectedTenantId}
                          onChange={(value) =>
                            setMatrix((entry) =>
                              setOptional(
                                entry.cases[rowIndex]!,
                                "expectedTenantId",
                                value,
                              ),
                            )
                          }
                        />
                        <OptionalField
                          label="Role"
                          value={row.expectedRole}
                          onChange={(value) =>
                            setMatrix((entry) =>
                              setOptional(
                                entry.cases[rowIndex]!,
                                "expectedRole",
                                value,
                              ),
                            )
                          }
                        />
                        <OptionalField
                          label="Account state"
                          value={row.expectedAccountState}
                          onChange={(value) =>
                            setMatrix((entry) =>
                              setOptional(
                                entry.cases[rowIndex]!,
                                "expectedAccountState",
                                value,
                              ),
                            )
                          }
                        />
                        <Check
                          label="Require verified identity"
                          checked={row.requireVerifiedIdentity}
                          onChange={(value) =>
                            setMatrix((entry) => {
                              entry.cases[rowIndex]!.requireVerifiedIdentity =
                                value;
                            })
                          }
                        />
                      </div>
                      <Select
                        label="Expected decision"
                        value={row.expectedDecision}
                        options={capability.expectationTypes}
                        onChange={(value) =>
                          setMatrix((entry) => {
                            entry.cases[rowIndex]!.expectedDecision =
                              value as typeof row.expectedDecision;
                          })
                        }
                      />
                      <RowActions
                        index={rowIndex}
                        length={matrix.cases.length}
                        label="matrix row"
                        deleteDisabledReason={
                          matrix.cases.some(
                            (candidate) => candidate.referenceCaseId === row.id,
                          )
                            ? "Another matrix row references this row. Resolve the dependency before deletion."
                            : undefined
                        }
                        onDuplicate={() => {
                          const ids = [...workflow.uiCaseIds];
                          ids.splice(offset + rowIndex + 1, 0, uiId());
                          setMatrix((entry) => {
                            const copy = structuredClone(
                              entry.cases[rowIndex]!,
                            );
                            copy.id = `${copy.id}-copy-${entry.cases.length + 1}`;
                            entry.cases.splice(rowIndex + 1, 0, copy);
                          }, ids);
                        }}
                        onDelete={() => {
                          const ids = workflow.uiCaseIds.filter(
                            (_, index) => index !== offset + rowIndex,
                          );
                          setMatrix((entry) => {
                            entry.cases.splice(rowIndex, 1);
                          }, ids);
                        }}
                        onMove={(direction) => {
                          const ids = [...workflow.uiCaseIds];
                          move(ids, offset + rowIndex, direction);
                          setMatrix(
                            (entry) => move(entry.cases, rowIndex, direction),
                            ids,
                          );
                        }}
                      />
                    </div>
                  ),
              )}
            </div>
            <button
              type="button"
              onClick={() => {
                const ids = [...workflow.uiCaseIds];
                ids.splice(offset + matrix.cases.length, 0, uiId());
                setMatrix(
                  (entry) =>
                    entry.cases.push({
                      id: `matrix-row-${entry.cases.length + 1}`,
                      actorId: entry.actors[0]!.id,
                      objectId: "exact-object",
                      expectedDecision: "OBSERVE_ONLY",
                      requireVerifiedIdentity: true,
                    }),
                  ids,
                );
              }}
            >
              Add matrix row
            </button>
          </section>
        );
      })}
      <Limits
        values={{
          maxMatrices: workflow.config.maxMatrices,
          maxCasesPerMatrix: workflow.config.maxCasesPerMatrix,
          maxResponseBytes: workflow.config.maxResponseBytes,
          maxPreviewLength: workflow.config.maxPreviewLength,
        }}
        onChange={(key, value) => update({ ...workflow.config, [key]: value })}
      />
    </div>
  );
}

function EquivalentRouteEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: Props & {
  workflow: Extract<WorkflowDraft, { workflowId: "equivalent-route" }>;
}) {
  const update = (
    config: typeof workflow.config,
    uiCaseIds = workflow.uiCaseIds,
  ) => onChange({ ...workflow, config, uiCaseIds });
  return (
    <div className="specialized-editor equivalent-route-editor">
      <p className="domain-help">
        Only exact operator-supplied routes are compared. Route versions,
        aliases, methods, and administrative paths are never generated.
      </p>
      {workflow.config.routeSets.map((set, setIndex) => {
        const offset = workflow.config.routeSets
          .slice(0, setIndex)
          .reduce((sum, item) => sum + item.routes.length, 0);
        const setSet = (
          mutate: (value: typeof set) => void,
          ids = workflow.uiCaseIds,
        ) => {
          const config = structuredClone(workflow.config);
          mutate(config.routeSets[setIndex]!);
          update(config, ids);
        };
        return (
          <section className="domain-case" key={set.id}>
            <div className="grid three">
              <Text
                label="Route set ID"
                value={set.id}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.id = value;
                  })
                }
              />
              <Text
                label="Route set name"
                value={set.name}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.name = value;
                  })
                }
              />
              <Text
                label="Exact object ID"
                value={set.objectId}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.objectId = value;
                  })
                }
              />
              <Text
                label="Object type"
                value={set.objectType}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.objectType = value;
                  })
                }
              />
              <Select
                label="Canonical route"
                value={set.canonicalRouteId}
                options={set.routes.map((route) => route.id)}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.canonicalRouteId = value;
                    entry.routes.forEach((route) => {
                      route.isCanonical = route.id === value;
                    });
                  })
                }
              />
              <Select
                label="Equivalence policy"
                value={set.equivalencePolicy}
                options={options(capability, "equivalencePolicy")}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.equivalencePolicy =
                      value as typeof entry.equivalencePolicy;
                  })
                }
              />
              <FieldText
                workflow={workflow}
                diagnostics={diagnostics}
                path={`routeSets.${setIndex}.objectIdentityField`}
                label="Object identity path"
                value={set.objectIdentityField}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.objectIdentityField = value;
                  })
                }
              />
              <OptionalField
                label="Object state path"
                value={set.objectStateField}
                onChange={(value) =>
                  setSet((entry) =>
                    setOptional(entry, "objectStateField", value),
                  )
                }
              />
              <OptionalField
                label="Expected object state"
                value={set.expectedObjectState}
                onChange={(value) =>
                  setSet((entry) =>
                    setOptional(entry, "expectedObjectState", value),
                  )
                }
              />
              <Check
                label="Require verified identity"
                checked={set.requireVerifiedIdentity}
                onChange={(value) =>
                  setSet((entry) => {
                    entry.requireVerifiedIdentity = value;
                  })
                }
              />
            </div>
            <ActorList
              actors={set.actors}
              relationshipKey="relationship"
              options={options(capability, "relationship")}
              onChange={(actors) =>
                setSet((entry) => {
                  entry.actors = actors as typeof entry.actors;
                })
              }
            />
            <Section
              title="Exact routes"
              help="Reference selectors use configured safe route labels; changing order never changes the referenced scanner route ID."
            >
              <div className="route-pair-list">
                {set.routes.map((route, routeIndex) => {
                  const deleteReason =
                    set.canonicalRouteId === route.id
                      ? "Choose another canonical route before deleting this route."
                      : set.routes.some(
                            (item) => item.referenceRouteId === route.id,
                          )
                        ? "Another route references this route. Resolve the dependency before deletion."
                        : undefined;
                  return (
                    <article
                      className="route-pair"
                      key={workflow.uiCaseIds[offset + routeIndex] ?? route.id}
                    >
                      <div className="grid three">
                        <Text
                          label="Route name"
                          value={route.label}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.label = value;
                            })
                          }
                        />
                        <Text
                          label="Scanner route ID"
                          value={route.id}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.id = value;
                            })
                          }
                        />
                        <Select
                          label="Category"
                          value={route.category}
                          options={options(capability, "routeCategory")}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.category =
                                value as typeof route.category;
                            })
                          }
                        />
                        <Text
                          label="Template ID"
                          value={route.template.id}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.template.id = value;
                            })
                          }
                        />
                        <Text
                          label="Exact endpoint with {{OBJECT_ID}}"
                          value={route.template.url}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.template.url = value;
                            })
                          }
                        />
                        <Select
                          label="Reference route"
                          value={route.referenceRouteId ?? ""}
                          options={[
                            "",
                            ...set.routes
                              .filter((_, index) => index !== routeIndex)
                              .map((item) => item.id),
                          ]}
                          onChange={(value) =>
                            setSet((entry) =>
                              setOptional(
                                entry.routes[routeIndex]!,
                                "referenceRouteId",
                                value,
                              ),
                            )
                          }
                        />
                        <Select
                          label="Route policy override"
                          value={route.equivalencePolicy ?? ""}
                          options={[
                            "",
                            ...options(capability, "equivalencePolicy"),
                          ]}
                          onChange={(value) =>
                            setSet((entry) => {
                              if (value)
                                entry.routes[routeIndex]!.equivalencePolicy =
                                  value as typeof set.equivalencePolicy;
                              else
                                delete entry.routes[routeIndex]!
                                  .equivalencePolicy;
                            })
                          }
                        />
                        <Check
                          label="Canonical route"
                          checked={route.isCanonical}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.isCanonical = value;
                              if (value)
                                entry.canonicalRouteId =
                                  entry.routes[routeIndex]!.id;
                            })
                          }
                        />
                        <Check
                          label="Deprecated"
                          checked={route.deprecated}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.deprecated = value;
                            })
                          }
                        />
                        <Check
                          label="Expected public"
                          checked={route.expectedPublic}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.expectedPublic = value;
                            })
                          }
                        />
                        <OptionalField
                          label="Response envelope path"
                          value={route.responseEnvelopePath}
                          onChange={(value) =>
                            setSet((entry) =>
                              setOptional(
                                entry.routes[routeIndex]!,
                                "responseEnvelopePath",
                                value,
                              ),
                            )
                          }
                        />
                        <OptionalField
                          label="Route object identity path"
                          value={route.objectIdentityField}
                          onChange={(value) =>
                            setSet((entry) =>
                              setOptional(
                                entry.routes[routeIndex]!,
                                "objectIdentityField",
                                value,
                              ),
                            )
                          }
                        />
                        <OptionalField
                          label="Route object state path"
                          value={route.objectStateField}
                          onChange={(value) =>
                            setSet((entry) =>
                              setOptional(
                                entry.routes[routeIndex]!,
                                "objectStateField",
                                value,
                              ),
                            )
                          }
                        />
                        <Text
                          label="Expected content type"
                          value={route.expectedContentType}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.expectedContentType =
                                value;
                            })
                          }
                        />
                        <Text
                          label="Representation type"
                          value={route.representationType}
                          onChange={(value) =>
                            setSet((entry) => {
                              entry.routes[routeIndex]!.representationType =
                                value;
                            })
                          }
                        />
                      </div>
                      <HeaderEditor
                        value={route.template.headers}
                        onChange={(headers) =>
                          setSet((entry) => {
                            entry.routes[routeIndex]!.template.headers =
                              headers;
                          })
                        }
                      />
                      <fieldset>
                        <legend>Actor decisions</legend>
                        {set.actors.map((actor) => (
                          <Select
                            key={actor.id}
                            label={actor.safeAlias ?? actor.id}
                            value={
                              route.expectations[actor.id] ?? "OBSERVE_ONLY"
                            }
                            options={capability.expectationTypes}
                            onChange={(value) =>
                              setSet((entry) => {
                                entry.routes[routeIndex]!.expectations[
                                  actor.id
                                ] =
                                  value as (typeof route.expectations)[string];
                              })
                            }
                          />
                        ))}
                      </fieldset>
                      <RowActions
                        index={routeIndex}
                        length={set.routes.length}
                        label="route"
                        deleteDisabledReason={deleteReason}
                        onDuplicate={() => {
                          const ids = [...workflow.uiCaseIds];
                          ids.splice(offset + routeIndex + 1, 0, uiId());
                          setSet((entry) => {
                            const copy = structuredClone(
                              entry.routes[routeIndex]!,
                            );
                            copy.id = `${copy.id}-copy-${entry.routes.length + 1}`;
                            copy.label = `${copy.label} copy`;
                            copy.isCanonical = false;
                            entry.routes.splice(routeIndex + 1, 0, copy);
                          }, ids);
                        }}
                        onDelete={() => {
                          const ids = workflow.uiCaseIds.filter(
                            (_, index) => index !== offset + routeIndex,
                          );
                          setSet((entry) => {
                            entry.routes.splice(routeIndex, 1);
                          }, ids);
                        }}
                        onMove={(direction) => {
                          const ids = [...workflow.uiCaseIds];
                          move(ids, offset + routeIndex, direction);
                          setSet(
                            (entry) =>
                              move(entry.routes, routeIndex, direction),
                            ids,
                          );
                        }}
                      />
                    </article>
                  );
                })}
              </div>
              <button
                type="button"
                onClick={() => {
                  const ids = [...workflow.uiCaseIds];
                  ids.splice(offset + set.routes.length, 0, uiId());
                  setSet(
                    (entry) =>
                      entry.routes.push({
                        id: `route-${entry.routes.length + 1}`,
                        label: `Exact route ${entry.routes.length + 1}`,
                        category: "CUSTOM_DECLARED",
                        isCanonical: false,
                        deprecated: false,
                        expectedPublic: false,
                        template: {
                          id: `route-template-${entry.routes.length + 1}`,
                          method: "GET",
                          url: entry.routes[0]!.template.url,
                          headers: {},
                        },
                        expectedContentType: "application/json",
                        representationType: "json",
                        referenceRouteId: entry.canonicalRouteId,
                        expectations: Object.fromEntries(
                          entry.actors.map((actor) => [
                            actor.id,
                            "OBSERVE_ONLY",
                          ]),
                        ),
                      }),
                    ids,
                  );
                }}
              >
                Add exact route
              </button>
            </Section>
          </section>
        );
      })}
      <Limits
        values={{
          maxRouteSets: workflow.config.maxRouteSets,
          maxRoutesPerSet: workflow.config.maxRoutesPerSet,
          maxActorsPerSet: workflow.config.maxActorsPerSet,
          maxCells: workflow.config.maxCells,
          maxResponseBytes: workflow.config.maxResponseBytes,
          maxPreviewLength: workflow.config.maxPreviewLength,
        }}
        onChange={(key, value) => update({ ...workflow.config, [key]: value })}
      />
    </div>
  );
}

const completenessHelp: Record<string, string> = {
  COMPLETE_COLLECTION:
    "Absence may be meaningful only when this exact response is expected to contain the complete authorized collection.",
  FIXED_RESULT_WINDOW:
    "Absence outside this configured result window does not prove authorization denial.",
  SEARCH_RESULT_SET:
    "Interpretation applies only to this exact configured search result set; RouteCairn never mutates the search.",
  SUMMARY_ONLY:
    "Summary responses cannot establish object-level membership absence.",
  UNKNOWN_COMPLETENESS:
    "Absence is observational only and needs manual verification.",
};

function CollectionEditor({
  workflow,
  capability,
  diagnostics,
  onChange,
}: Props & {
  workflow: Extract<WorkflowDraft, { workflowId: "collection-authorization" }>;
}) {
  const update = (
    config: typeof workflow.config,
    uiCaseIds = workflow.uiCaseIds,
  ) => onChange({ ...workflow, config, uiCaseIds });
  return (
    <div className="specialized-editor collection-editor">
      {workflow.config.collections.map((collection, collectionIndex) => {
        const offset = workflow.config.collections
          .slice(0, collectionIndex)
          .reduce((sum, item) => sum + item.cases.length, 0);
        const setCollection = (
          mutate: (value: typeof collection) => void,
          ids = workflow.uiCaseIds,
        ) => {
          const config = structuredClone(workflow.config);
          mutate(config.collections[collectionIndex]!);
          update(config, ids);
        };
        return (
          <section className="domain-case" key={collection.id}>
            <div className="grid three">
              <Text
                label="Collection ID"
                value={collection.id}
                onChange={(value) =>
                  setCollection((entry) => {
                    entry.id = value;
                  })
                }
              />
              <Text
                label="Collection name"
                value={collection.label}
                onChange={(value) =>
                  setCollection((entry) => {
                    entry.label = value;
                  })
                }
              />
              <Select
                label="Endpoint category"
                value={collection.category}
                options={options(capability, "category")}
                onChange={(value) =>
                  setCollection((entry) => {
                    entry.category = value as typeof entry.category;
                  })
                }
              />
              <Text
                label="Exact GET URL"
                value={collection.url}
                onChange={(value) =>
                  setCollection((entry) => {
                    entry.url = value;
                  })
                }
              />
              <Select
                label="Completeness"
                value={collection.completeness}
                options={options(capability, "completeness")}
                onChange={(value) =>
                  setCollection((entry) => {
                    entry.completeness = value as typeof entry.completeness;
                  })
                }
              />
              <Text
                label="Expected content type"
                value={collection.expectedContentType}
                onChange={(value) =>
                  setCollection((entry) => {
                    entry.expectedContentType = value;
                  })
                }
              />
              <label>
                Method
                <input value={collection.method} readOnly />
              </label>
            </div>
            <HeaderEditor
              value={collection.headers}
              onChange={(headers) =>
                setCollection((entry) => {
                  entry.headers = headers;
                })
              }
            />
            <p className="completeness-explanation" role="note">
              <strong>{human(collection.completeness)}:</strong>{" "}
              {completenessHelp[collection.completeness]}
            </p>
            <Section
              title="Response mapping"
              help="All paths use the bounded SafeFieldPath grammar; no runtime schema discovery occurs."
            >
              <div className="grid three">
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`collections.${collectionIndex}.resultArrayPath`}
                  label="Result array path"
                  value={collection.resultArrayPath ?? ""}
                  onChange={(value) =>
                    setCollection((entry) =>
                      setOptional(entry, "resultArrayPath", value),
                    )
                  }
                />
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`collections.${collectionIndex}.objectIdPath`}
                  label="Object ID path"
                  value={collection.objectIdPath ?? ""}
                  onChange={(value) =>
                    setCollection((entry) =>
                      setOptional(entry, "objectIdPath", value),
                    )
                  }
                />
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`collections.${collectionIndex}.objectOwnerPath`}
                  label="Owner path"
                  value={collection.objectOwnerPath ?? ""}
                  onChange={(value) =>
                    setCollection((entry) =>
                      setOptional(entry, "objectOwnerPath", value),
                    )
                  }
                />
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`collections.${collectionIndex}.objectTenantPath`}
                  label="Tenant path"
                  value={collection.objectTenantPath ?? ""}
                  onChange={(value) =>
                    setCollection((entry) =>
                      setOptional(entry, "objectTenantPath", value),
                    )
                  }
                />
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`collections.${collectionIndex}.objectTypePath`}
                  label="Type path"
                  value={collection.objectTypePath ?? ""}
                  onChange={(value) =>
                    setCollection((entry) =>
                      setOptional(entry, "objectTypePath", value),
                    )
                  }
                />
                <FieldText
                  workflow={workflow}
                  diagnostics={diagnostics}
                  path={`collections.${collectionIndex}.objectStatePath`}
                  label="State path"
                  value={collection.objectStatePath ?? ""}
                  onChange={(value) =>
                    setCollection((entry) =>
                      setOptional(entry, "objectStatePath", value),
                    )
                  }
                />
                <label>
                  Maximum inspected entries
                  <input
                    type="number"
                    min="1"
                    value={collection.maxInspectedEntries}
                    onChange={(event) =>
                      setCollection((entry) => {
                        entry.maxInspectedEntries = Number(event.target.value);
                      })
                    }
                  />
                </label>
                <label>
                  Maximum response bytes
                  <input
                    type="number"
                    min="1"
                    value={collection.maxResponseBytes}
                    onChange={(event) =>
                      setCollection((entry) => {
                        entry.maxResponseBytes = Number(event.target.value);
                      })
                    }
                  />
                </label>
                <label>
                  Maximum JSON depth
                  <input
                    type="number"
                    min="1"
                    value={collection.maxJsonDepth}
                    onChange={(event) =>
                      setCollection((entry) => {
                        entry.maxJsonDepth = Number(event.target.value);
                      })
                    }
                  />
                </label>
              </div>
            </Section>
            <ActorList
              actors={collection.actors}
              relationshipKey="relationship"
              options={options(capability, "relationship")}
              onChange={(actors) =>
                setCollection((entry) => {
                  entry.actors = actors as typeof entry.actors;
                })
              }
            />
            <Section
              title="Known exact objects"
              help="Known objects are operator supplied and confirmed safe. Returned IDs never become new cases."
            >
              {collection.knownObjects.map((object, objectIndex) => (
                <fieldset key={object.id}>
                  <legend>{object.safeAlias ?? object.id}</legend>
                  <div className="grid three">
                    <Text
                      label="Known object row ID"
                      value={object.id}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.knownObjects[objectIndex]!.id = value;
                        })
                      }
                    />
                    <Text
                      label="Safe object name"
                      value={object.safeAlias ?? ""}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.knownObjects[objectIndex]!,
                            "safeAlias",
                            value,
                          ),
                        )
                      }
                    />
                    <Text
                      label="Exact object ID"
                      value={object.objectId}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.knownObjects[objectIndex]!.objectId = value;
                        })
                      }
                    />
                    <Text
                      label="Object type"
                      value={object.objectType}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.knownObjects[objectIndex]!.objectType = value;
                        })
                      }
                    />
                    <Select
                      label="Owner actor"
                      value={object.ownerActorId ?? ""}
                      options={[
                        "",
                        ...collection.actors.map((actor) => actor.id),
                      ]}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.knownObjects[objectIndex]!,
                            "ownerActorId",
                            value,
                          ),
                        )
                      }
                    />
                    <OptionalField
                      label="Tenant"
                      value={object.tenantId}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.knownObjects[objectIndex]!,
                            "tenantId",
                            value,
                          ),
                        )
                      }
                    />
                    <OptionalField
                      label="State"
                      value={object.state}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.knownObjects[objectIndex]!,
                            "state",
                            value,
                          ),
                        )
                      }
                    />
                    <Check
                      label="Expected public"
                      checked={object.expectedPublic}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.knownObjects[objectIndex]!.expectedPublic =
                            value;
                        })
                      }
                    />
                    <Check
                      label="Expected shared"
                      checked={object.expectedShared}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.knownObjects[objectIndex]!.expectedShared =
                            value;
                        })
                      }
                    />
                    <Check
                      label="Confirmed safe to test"
                      checked={object.confirmedSafeToTest}
                      onChange={() => undefined}
                    />
                  </div>
                  <button
                    type="button"
                    disabled={collection.knownObjects.length === 1}
                    onClick={() =>
                      setCollection((entry) => {
                        entry.knownObjects.splice(objectIndex, 1);
                      })
                    }
                  >
                    Remove known object
                  </button>
                </fieldset>
              ))}
              <button
                type="button"
                onClick={() =>
                  setCollection((entry) =>
                    entry.knownObjects.push({
                      id: `known-${entry.knownObjects.length + 1}`,
                      objectId: "exact-object",
                      objectType: "record",
                      safeAlias: `Known object ${entry.knownObjects.length + 1}`,
                      expectedPublic: false,
                      expectedShared: false,
                      confirmedSafeToTest: true,
                    }),
                  )
                }
              >
                Add known object
              </button>
            </Section>
            <Section
              title="Membership and reference cases"
              help="Reference selectors bind to exact configured case IDs. Deleting a referenced case is blocked by the planner and guided dependency checks."
            >
              {collection.cases.map((item, caseIndex) => (
                <fieldset key={workflow.uiCaseIds[offset + caseIndex]}>
                  <legend>{item.id}</legend>
                  <div className="grid three">
                    <Text
                      label="Case name"
                      value={item.id}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.cases[caseIndex]!.id = value;
                        })
                      }
                    />
                    <Select
                      label="Actor"
                      value={item.actorId}
                      options={collection.actors.map((actor) => actor.id)}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.cases[caseIndex]!.actorId = value;
                        })
                      }
                    />
                    <Select
                      label="Known object"
                      value={item.knownObjectId ?? ""}
                      options={[
                        "",
                        ...collection.knownObjects.map((object) => object.id),
                      ]}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.cases[caseIndex]!,
                            "knownObjectId",
                            value,
                          ),
                        )
                      }
                    />
                    <Select
                      label="Membership expectation"
                      value={item.expectedMembership}
                      options={capability.expectationTypes}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.cases[caseIndex]!.expectedMembership =
                            value as typeof item.expectedMembership;
                        })
                      }
                    />
                    <Select
                      label="Reference case"
                      value={item.referenceCaseId ?? ""}
                      options={[
                        "",
                        ...collection.cases
                          .filter((_, index) => index !== caseIndex)
                          .map((candidate) => candidate.id),
                      ]}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.cases[caseIndex]!,
                            "referenceCaseId",
                            value,
                          ),
                        )
                      }
                    />
                    <Check
                      label="Require verified identity"
                      checked={item.requireVerifiedIdentity}
                      onChange={(value) =>
                        setCollection((entry) => {
                          entry.cases[caseIndex]!.requireVerifiedIdentity =
                            value;
                        })
                      }
                    />
                    <Select
                      label="Expected actor relationship"
                      value={item.expectedActorRelationship ?? ""}
                      options={["", ...options(capability, "relationship")]}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.cases[caseIndex]!,
                            "expectedActorRelationship",
                            value,
                          ),
                        )
                      }
                    />
                    <OptionalField
                      label="Expected tenant"
                      value={item.expectedTenantId}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.cases[caseIndex]!,
                            "expectedTenantId",
                            value,
                          ),
                        )
                      }
                    />
                    <OptionalField
                      label="Expected role"
                      value={item.expectedRole}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.cases[caseIndex]!,
                            "expectedRole",
                            value,
                          ),
                        )
                      }
                    />
                    <OptionalField
                      label="Expected account state"
                      value={item.expectedAccountState}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.cases[caseIndex]!,
                            "expectedAccountState",
                            value,
                          ),
                        )
                      }
                    />
                    <OptionalField
                      label="Expected object state"
                      value={item.expectedObjectState}
                      onChange={(value) =>
                        setCollection((entry) =>
                          setOptional(
                            entry.cases[caseIndex]!,
                            "expectedObjectState",
                            value,
                          ),
                        )
                      }
                    />
                  </div>
                  {item.countExpectation ? (
                    <fieldset>
                      <legend>Count sensitivity</legend>
                      <FieldText
                        workflow={workflow}
                        diagnostics={diagnostics}
                        path={`collections.${collectionIndex}.cases.${caseIndex}.countExpectation.path`}
                        label="Count path"
                        value={item.countExpectation.path}
                        onChange={(value) =>
                          setCollection((entry) => {
                            entry.cases[caseIndex]!.countExpectation!.path =
                              value;
                          })
                        }
                      />
                      <Select
                        label="Count expectation"
                        value={item.countExpectation.expectation}
                        options={options(capability, "countExpectation")}
                        onChange={(value) =>
                          setCollection((entry) => {
                            entry.cases[
                              caseIndex
                            ]!.countExpectation!.expectation =
                              value as typeof item.countExpectation.expectation;
                          })
                        }
                      />
                      <label>
                        Expected count <small>optional</small>
                        <input
                          type="number"
                          min="0"
                          value={item.countExpectation.expectedCount ?? ""}
                          onChange={(event) =>
                            setCollection((entry) => {
                              const target =
                                entry.cases[caseIndex]!.countExpectation!;
                              if (event.target.value)
                                target.expectedCount = Number(
                                  event.target.value,
                                );
                              else delete target.expectedCount;
                            })
                          }
                        />
                      </label>
                      <Select
                        label="Count reference case"
                        value={item.countExpectation.referenceCaseId ?? ""}
                        options={[
                          "",
                          ...collection.cases
                            .filter((_, index) => index !== caseIndex)
                            .map((candidate) => candidate.id),
                        ]}
                        onChange={(value) =>
                          setCollection((entry) =>
                            setOptional(
                              entry.cases[caseIndex]!.countExpectation!,
                              "referenceCaseId",
                              value,
                            ),
                          )
                        }
                      />
                      <Check
                        label="Count is security-sensitive"
                        checked={item.countExpectation.securitySensitive}
                        onChange={(value) =>
                          setCollection((entry) => {
                            entry.cases[
                              caseIndex
                            ]!.countExpectation!.securitySensitive = value;
                          })
                        }
                      />
                      <Check
                        label="Count is volatile"
                        checked={item.countExpectation.volatile}
                        onChange={(value) =>
                          setCollection((entry) => {
                            entry.cases[caseIndex]!.countExpectation!.volatile =
                              value;
                          })
                        }
                      />
                      <button
                        type="button"
                        onClick={() =>
                          setCollection((entry) => {
                            delete entry.cases[caseIndex]!.countExpectation;
                          })
                        }
                      >
                        Remove count expectation
                      </button>
                    </fieldset>
                  ) : (
                    <button
                      type="button"
                      onClick={() =>
                        setCollection((entry) => {
                          entry.cases[caseIndex]!.countExpectation = {
                            path: "count",
                            expectation: "OBSERVE_ONLY",
                            securitySensitive: false,
                            volatile: true,
                          };
                        })
                      }
                    >
                      Add count expectation
                    </button>
                  )}
                  <div className="summary-expectations">
                    {item.summaryExpectations.map((summary, summaryIndex) => (
                      <div
                        className="semantic-row"
                        key={`${summary.path}-${summaryIndex}`}
                      >
                        <FieldText
                          workflow={workflow}
                          diagnostics={diagnostics}
                          path={`collections.${collectionIndex}.cases.${caseIndex}.summaryExpectations.${summaryIndex}.path`}
                          label="Summary path"
                          value={summary.path}
                          onChange={(value) =>
                            setCollection((entry) => {
                              entry.cases[caseIndex]!.summaryExpectations[
                                summaryIndex
                              ]!.path = value;
                            })
                          }
                        />
                        <Select
                          label="Summary expectation"
                          value={summary.expectation}
                          options={options(capability, "summaryExpectation")}
                          onChange={(value) =>
                            setCollection((entry) => {
                              entry.cases[caseIndex]!.summaryExpectations[
                                summaryIndex
                              ]!.expectation =
                                value as typeof summary.expectation;
                            })
                          }
                        />
                        <ScalarValue
                          label="Expected summary value"
                          value={summary.expectedValue}
                          onChange={(value) =>
                            setCollection((entry) => {
                              const target =
                                entry.cases[caseIndex]!.summaryExpectations[
                                  summaryIndex
                                ]!;
                              if (value === undefined)
                                delete target.expectedValue;
                              else target.expectedValue = value;
                            })
                          }
                        />
                        <Select
                          label="Summary reference case"
                          value={summary.referenceCaseId ?? ""}
                          options={[
                            "",
                            ...collection.cases
                              .filter((_, index) => index !== caseIndex)
                              .map((candidate) => candidate.id),
                          ]}
                          onChange={(value) =>
                            setCollection((entry) =>
                              setOptional(
                                entry.cases[caseIndex]!.summaryExpectations[
                                  summaryIndex
                                ]!,
                                "referenceCaseId",
                                value,
                              ),
                            )
                          }
                        />
                        <Check
                          label="Summary is security-sensitive"
                          checked={summary.securitySensitive}
                          onChange={(value) =>
                            setCollection((entry) => {
                              entry.cases[caseIndex]!.summaryExpectations[
                                summaryIndex
                              ]!.securitySensitive = value;
                            })
                          }
                        />
                        <Check
                          label="Summary is volatile"
                          checked={summary.volatile}
                          onChange={(value) =>
                            setCollection((entry) => {
                              entry.cases[caseIndex]!.summaryExpectations[
                                summaryIndex
                              ]!.volatile = value;
                            })
                          }
                        />
                        <button
                          type="button"
                          onClick={() =>
                            setCollection((entry) => {
                              entry.cases[
                                caseIndex
                              ]!.summaryExpectations.splice(summaryIndex, 1);
                            })
                          }
                        >
                          Remove summary expectation
                        </button>
                      </div>
                    ))}
                    <button
                      type="button"
                      onClick={() =>
                        setCollection((entry) => {
                          entry.cases[caseIndex]!.summaryExpectations.push({
                            path: "summary.value",
                            expectation: "OBSERVE_ONLY",
                            securitySensitive: false,
                            volatile: true,
                          });
                        })
                      }
                    >
                      Add summary expectation
                    </button>
                  </div>
                </fieldset>
              ))}
            </Section>
          </section>
        );
      })}
      <Limits
        values={{
          maxCollections: workflow.config.maxCollections,
          maxCasesPerCollection: workflow.config.maxCasesPerCollection,
          maxKnownObjects: workflow.config.maxKnownObjects,
          maxRequests: workflow.config.maxRequests,
          maxRetainedObservations: workflow.config.maxRetainedObservations,
          maxPreviewLength: workflow.config.maxPreviewLength,
        }}
        onChange={(key, value) => update({ ...workflow.config, [key]: value })}
      />
    </div>
  );
}
function BulkEditor(
  props: Props & {
    workflow: Extract<WorkflowDraft, { workflowId: "bulk-authorization" }>;
  },
) {
  return <BulkWorkflowEditor {...props} />;
}
function FileEditor(
  props: Props & {
    workflow: Extract<WorkflowDraft, { workflowId: "file-authorization" }>;
  },
) {
  return <FileWorkflowEditor {...props} />;
}

function objectPairDecision(
  visibility: Extract<
    WorkflowDraft,
    { workflowId: "object-pair" }
  >["config"]["cases"][number]["expectedVisibility"],
  identityValid: boolean,
): { owner: string; cross: string } {
  if (!identityValid)
    return {
      owner: "Verification unavailable",
      cross: "Verification unavailable",
    };
  if (visibility === "PRIVATE_TO_OWNER")
    return { owner: "Expected allowed", cross: "Expected denied" };
  if (visibility === "PUBLIC")
    return { owner: "Expected allowed", cross: "Expected allowed" };
  if (visibility === "UNKNOWN_REQUIRES_REVIEW")
    return {
      owner: "Needs manual verification",
      cross: "Needs manual verification",
    };
  return {
    owner: "Expected allowed",
    cross: "Policy-dependent; needs manual verification",
  };
}
