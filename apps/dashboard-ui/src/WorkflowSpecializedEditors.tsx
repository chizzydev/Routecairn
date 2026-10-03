import { useState } from "react";
import type { WorkflowDraft } from "./AuthorizationWorkflowStudio";

import { BulkWorkflowEditor, FileWorkflowEditor } from "./WorkflowBulkFileEditors";
import { ActorList, Check, FieldText, HeaderEditor, Limits, ObjectAssertion, OptionalField, Relationship, RowActions, Section, Select, StringList, Text, human, move, options, setOptional, uiId } from "./WorkflowSpecializedControls";
import { type Props } from "./WorkflowSpecializedTypes";
import { EquivalentRouteEditor } from "./WorkflowEquivalentRouteEditor";
import { CollectionEditor } from "./WorkflowCollectionEditor";

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

export function ObjectPairEditor({
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

export function FieldExposureEditor({
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

export function MatrixEditor({
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

export function BulkEditor(
  props: Props & {
    workflow: Extract<WorkflowDraft, { workflowId: "bulk-authorization" }>;
  },
) {
  return <BulkWorkflowEditor {...props} />;
}

export function FileEditor(
  props: Props & {
    workflow: Extract<WorkflowDraft, { workflowId: "file-authorization" }>;
  },
) {
  return <FileWorkflowEditor {...props} />;
}

export function objectPairDecision(
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
