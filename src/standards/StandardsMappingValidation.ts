import { moduleCatalog } from "../core/planning/ModuleCatalog.js";
import { activeVulnerabilityClasses } from "../modules/activeVulnerability/ActiveVulnerabilityTypes.js";
import { authenticationLifecycleCategories } from "../modules/authenticationLifecycle/AuthenticationLifecycleTypes.js";
import { apiGraphqlCheckKinds } from "../modules/apiGraphql/ApiGraphqlTypes.js";
import { protocolSecurityKinds } from "../modules/protocolSecurity/ProtocolSecurityTypes.js";
import { referencesFor } from "./StandardsCatalog.js";
import { mappingFor } from "./StandardsMappings.js";

/** Build/release gate: adding an engine or case enum requires a reviewed published mapping. */
export function validateBuiltInStandardsMappings(): Array<{ moduleId: string; discriminator: string; references: number }> {
  const kinds = new Map<string, readonly string[]>([["active-vulnerability-validation", activeVulnerabilityClasses], ["authentication-lifecycle", authenticationLifecycleCategories], ["api-graphql-authorization", [...apiGraphqlCheckKinds, "SCHEMA_INVENTORY"]], ["protocol-security", protocolSecurityKinds]]);
  const result = [];
  for (const moduleId of Object.keys(moduleCatalog).sort()) {
    // Aggregators do not execute security tests. Their constituent evidence must be mapped individually.
    if (moduleId === "assisted-review" || moduleId === "proof-mode") continue;
    for (const discriminator of kinds.get(moduleId) ?? [""]) {
      const references = referencesFor(mappingFor(moduleId, discriminator));
      if (!references.some((reference) => reference.strength === "DIRECT")) throw new Error(`STANDARDS_BUILTIN_MAPPING_MISSING ${moduleId}/${discriminator}`);
      result.push({ moduleId, discriminator, references: references.length });
    }
  }
  return result;
}
