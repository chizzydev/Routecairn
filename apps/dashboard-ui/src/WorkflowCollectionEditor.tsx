
import type { WorkflowDraft } from "./AuthorizationWorkflowStudio";


import { ActorList, Check, FieldText, HeaderEditor, Limits, OptionalField, ScalarValue, Section, Select, Text, human, options, setOptional } from "./WorkflowSpecializedControls";
import { type Props } from "./WorkflowSpecializedTypes";

export const completenessHelp: Record<string, string> = {
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

export function CollectionEditor({
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
