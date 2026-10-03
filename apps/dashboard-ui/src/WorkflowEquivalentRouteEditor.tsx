
import type { WorkflowDraft } from "./AuthorizationWorkflowStudio";


import { ActorList, Check, FieldText, HeaderEditor, Limits, OptionalField, RowActions, Section, Select, Text, move, options, setOptional, uiId } from "./WorkflowSpecializedControls";
import { type Props } from "./WorkflowSpecializedTypes";

export function EquivalentRouteEditor({
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
