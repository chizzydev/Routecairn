import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { ApplicationMappingInput } from "../contracts/ApplicationMappingContracts.js";
import { schemaImportSchema } from "../contracts/ApplicationSchemaContracts.js";
import { parseApplicationSchema, concreteSchemaPath } from "./ApplicationSchemaParser.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
function schemaTarget(db: DashboardDatabase, org: string, id: string) {
  const row = db.db
    .prepare("SELECT * FROM targets WHERE id=? AND organization_id=? AND archived_at IS NULL")
    .get(id, org) as Record<string, unknown> | undefined;
  if (
    !row ||
    row.classification !== "LOCAL" ||
    row.authorization_type !== "OWNED" ||
    new URL(String(row.base_origin)).hostname !== "127.0.0.1"
  )
    throw Error("WORKBENCH_SCHEMA_OWNED_TARGET_REQUIRED");
  return row;
}
export class ApplicationSchemaService {
  constructor(private readonly db: DashboardDatabase) {}
  public create(org: string, value: unknown, actor: string) {
    const input = schemaImportSchema.parse(value),
      target = schemaTarget(this.db, org, input.targetId),
      summary = parseApplicationSchema(input.document),
      contextDigest = adaptiveDigest(target),
      digest = adaptiveDigest({ targetId: input.targetId, contextDigest, summary }),
      id = randomUUID(),
      createdAt = new Date().toISOString();
    this.db.db
      .prepare("INSERT INTO application_schema_revisions VALUES(?,?,?,?,?,?,?,?)")
      .run(id, org, input.targetId, contextDigest, digest, JSON.stringify(summary), actor, createdAt);
    return { revisionId: id, targetId: input.targetId, digest, createdAt, ...summary };
  }
  public result(org: string, id: string) {
    const row = this.db.db
      .prepare("SELECT * FROM application_schema_revisions WHERE id=? AND organization_id=?")
      .get(id, org) as Record<string, string> | undefined;
    if (!row) throw Error("WORKBENCH_SCHEMA_NOT_FOUND");
    const summary = JSON.parse(row.summary_json!) as ReturnType<typeof parseApplicationSchema>;
    if (adaptiveDigest({ targetId: row.target_id, contextDigest: row.context_digest, summary }) !== row.digest)
      throw Error("WORKBENCH_SCHEMA_CUSTODY_INVALID");
    return { revisionId: id, targetId: row.target_id!, digest: row.digest!, createdAt: row.created_at!, ...summary };
  }
}
export function assertApplicationSchemaBinding(db: DashboardDatabase, org: string, input: ApplicationMappingInput) {
  const b = input.schemaBinding;
  if (!b) return;
  const service = new ApplicationSchemaService(db),
    schema = service.result(org, b.revisionId),
    row = db.db
      .prepare("SELECT context_digest FROM application_schema_revisions WHERE id=? AND organization_id=?")
      .get(b.revisionId, org) as { context_digest: string };
  if (
    schema.targetId !== input.targetId ||
    schema.digest !== b.digest ||
    adaptiveDigest(schemaTarget(db, org, input.targetId)) !== row.context_digest
  )
    throw Error("WORKBENCH_SCHEMA_BINDINGS_CHANGED");
  if (
    b.selections.length !== input.routes.length ||
    new Set(b.selections.map((s) => s.routeId)).size !== input.routes.length ||
    new Set(b.selections.map((s) => s.candidateId)).size !== b.selections.length
  )
    throw Error("WORKBENCH_SCHEMA_EXACT_SELECTION_REQUIRED");
  const origin = String(schemaTarget(db, org, input.targetId).base_origin);
  for (const r of input.routes) {
    const selection = b.selections.find((s) => s.routeId === r.id),
      candidate = schema.candidates.find((c) => c.id === selection?.candidateId);
    if (
      !selection ||
      !candidate ||
      r.pathTemplate !== candidate.template ||
      r.url !== new URL(concreteSchemaPath(candidate, selection.slots), origin).href
    )
      throw Error("WORKBENCH_SCHEMA_EXACT_SELECTION_REQUIRED");
  }
}
