
import type { WorkflowCapability, WorkflowDraft } from "./AuthorizationWorkflowStudio";
import { type WorkflowValidationDiagnostic } from "./WorkflowDiagnostics";
import { Check, DiagnosticStringList, Field, HeaderEditor, Limits, NumberField, Optional, Section, Select, Text, human, opts, proofModeHelp, setOptional } from "./WorkflowBulkFileControls";
import { type SharedProps, type FileDraft } from "./WorkflowBulkFileTypes";
import { ActorEditor } from "./WorkflowBulkFileSharedEditors";

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

export function FileCaseEditor({
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
