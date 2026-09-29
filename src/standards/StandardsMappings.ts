import type { StandardsMapping } from "./StandardsCatalog.js";

const AUTHZ_OBJECT: StandardsMapping = { wstg: ["WSTG-ATHZ-04", "WSTG-APIT-02"], asvs: ["v5.0.0-8.2.2", "v5.0.0-8.3.1"], api: ["API1:2023"], cwe: ["CWE-639"] };
const AUTHZ_FIELD: StandardsMapping = { wstg: ["WSTG-APIT-03"], asvs: ["v5.0.0-8.2.3", "v5.0.0-8.3.1"], api: ["API3:2023"], cwe: ["CWE-200", "CWE-285"] };
const AUTHZ_FUNCTION: StandardsMapping = { wstg: ["WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-APIT-04"], asvs: ["v5.0.0-8.2.1", "v5.0.0-8.3.1"], api: ["API5:2023"], cwe: ["CWE-285", "CWE-862"] };
const BUSINESS_FLOW: StandardsMapping = { wstg: ["WSTG-BUSL-01", "WSTG-BUSL-05", "WSTG-BUSL-06", "WSTG-BUSL-07"], asvs: ["v5.0.0-2.3.1", "v5.0.0-2.3.2", "v5.0.0-2.4.1"], api: ["API6:2023"], cwe: ["CWE-799"] };

export function mappingFor(moduleId: string, discriminator = ""): StandardsMapping {
  const value = discriminator.toUpperCase();
  if (moduleId === "active-vulnerability-validation") return activeVulnerabilityMapping(value);
  if (moduleId === "protocol-security") return protocolMapping(value);
  if (moduleId === "authentication-lifecycle") return authenticationMapping(value);
  if (moduleId === "api-graphql-authorization") return graphqlMapping(value);
  if (moduleId === "supabase-authorization") return value.includes("FIELD") || value.includes("COLUMN") ? AUTHZ_FIELD : value.includes("RPC") ? AUTHZ_FUNCTION : AUTHZ_OBJECT;
  if (["object-pair-testing", "collection-authorization-testing", "file-authorization-testing"].includes(moduleId)) return AUTHZ_OBJECT;
  if (moduleId === "field-exposure-testing") return AUTHZ_FIELD;
  if (["authorization-matrix-testing", "equivalent-route-testing", "privilege-mutation-testing", "role-comparison"].includes(moduleId)) return AUTHZ_FUNCTION;
  if (moduleId === "bulk-authorization-testing") return merge(AUTHZ_OBJECT, AUTHZ_FIELD, AUTHZ_FUNCTION);
  if (["business-invariant", "billing-entitlement-security"].includes(moduleId)) return merge(BUSINESS_FLOW, moduleId === "billing-entitlement-security" ? { wstg: ["WSTG-BUSL-10"] } : {});
  if (moduleId === "controlled-race") return merge(BUSINESS_FLOW, { wstg: ["WSTG-BUSL-03", "WSTG-BUSL-04"], asvs: ["v5.0.0-2.3.3", "v5.0.0-2.3.4"], api: ["API4:2023"], cwe: ["CWE-362"] });
  if (moduleId === "link-portal-export-security") return merge(AUTHZ_OBJECT, AUTHZ_FUNCTION, { wstg: ["WSTG-SESS-07"], asvs: ["v5.0.0-7.4.1"] });
  if (moduleId === "operational-endpoint-security") return merge(AUTHZ_FUNCTION, { wstg: ["WSTG-CONF-05"], api: ["API8:2023"] });
  if (moduleId === "secret-boundary") return { wstg: ["WSTG-SESS-04", "WSTG-CLNT-12", "WSTG-APIT-03"], asvs: ["v5.0.0-3.3.4", "v5.0.0-3.5.7", "v5.0.0-14.2.1", "v5.0.0-14.2.3", "v5.0.0-14.2.6", "v5.0.0-14.3.3"], api: ["API3:2023", "API8:2023", "API10:2023"], cwe: ["CWE-200", "CWE-1004"] };
  if (moduleId === "authenticated-testing" || moduleId === "state-aware-api") return merge(AUTHZ_OBJECT, { wstg: ["WSTG-ATHN-04"], api: ["API2:2023"], cwe: ["CWE-287"] });
  if (moduleId === "identity-verification") return { wstg: ["WSTG-IDNT-01", "WSTG-ATHN-04"], asvs: ["v5.0.0-6.3.4", "v5.0.0-7.2.1"], api: ["API2:2023"], cwe: ["CWE-287"] };
  if (moduleId === "baseline" || moduleId === "path-discovery") return { wstg: ["WSTG-INFO-04", "WSTG-INFO-06"], api: ["API9:2023"] };
  if (moduleId === "tech-fingerprint") return { wstg: ["WSTG-INFO-02", "WSTG-INFO-08"] };
  if (moduleId === "js-intelligence") return { wstg: ["WSTG-INFO-05", "WSTG-INFO-06", "WSTG-CLNT-13"], asvs: ["v5.0.0-3.5.7"], api: ["API9:2023"], cwe: ["CWE-200"] };
  if (moduleId === "browser-crawler") return { wstg: ["WSTG-INFO-07", "WSTG-INFO-10", "WSTG-CLNT-12"], asvs: ["v5.0.0-14.3.3"] };
  if (moduleId === "api-mapper" || moduleId === "api-probe") return { wstg: ["WSTG-APIT-01", "WSTG-INFO-04"], api: ["API9:2023"] };
  if (moduleId === "auth-surface") return { wstg: ["WSTG-IDNT-04", "WSTG-ATHN-03", "WSTG-ATHN-04"], asvs: ["v5.0.0-6.3.1", "v5.0.0-6.3.8"], api: ["API2:2023"], cwe: ["CWE-287"] };
  if (moduleId === "parameter-analysis") return { wstg: ["WSTG-INFO-06", "WSTG-INJT-04"], asvs: ["v5.0.0-2.2.1"], cwe: ["CWE-20"] };
  if (moduleId === "nextjs-review") return { wstg: ["WSTG-CLNT-13", "WSTG-APIT-03"], asvs: ["v5.0.0-3.5.7", "v5.0.0-14.2.6"], api: ["API3:2023", "API8:2023"], cwe: ["CWE-200"] };
  if (moduleId === "vulnerability-workflows" || moduleId === "workflow-validation") return BUSINESS_FLOW;
  if (moduleId === "header-review") return { wstg: ["WSTG-CONF-07", "WSTG-CONF-12", "WSTG-CONF-14"], asvs: ["v5.0.0-3.4.3", "v5.0.0-3.4.4", "v5.0.0-12.2.1"], api: ["API8:2023"] };
  if (moduleId === "cookie-review") return { wstg: ["WSTG-SESS-02"], asvs: ["v5.0.0-3.3.4"], api: ["API2:2023"], cwe: ["CWE-1004"] };
  if (moduleId === "cors-review") return { wstg: ["WSTG-CLNT-07"], asvs: ["v5.0.0-3.4.2"], api: ["API8:2023"], cwe: ["CWE-942"] };
  if (moduleId === "method-review") return { wstg: ["WSTG-CONF-06", "WSTG-INJT-03"], asvs: ["v5.0.0-3.5.3"], api: ["API8:2023"] };
  if (moduleId === "exposure-review") return { wstg: ["WSTG-CONF-04", "WSTG-CONF-05", "WSTG-ERRH-01", "WSTG-ERRH-02"], asvs: ["v5.0.0-16.5.1"], api: ["API8:2023", "API9:2023"], cwe: ["CWE-200", "CWE-209"] };
  return {};
}

export function mappingForFinding(type: string): StandardsMapping {
  const normalized = type.toUpperCase();
  if (normalized.includes("SQL INJECTION")) return activeVulnerabilityMapping("SQL_INJECTION");
  if (normalized.includes("NOSQL")) return activeVulnerabilityMapping("NOSQL_INJECTION");
  if (normalized.includes("CROSS-SITE SCRIPTING")) return activeVulnerabilityMapping("REFLECTED_XSS");
  if (normalized.includes("AUTHORIZATION") || normalized.includes("OBJECT PATH")) return normalized.includes("FIELD") ? AUTHZ_FIELD : normalized.includes("OBJECT") || normalized.includes("FILE") ? AUTHZ_OBJECT : AUTHZ_FUNCTION;
  if (normalized.includes("AUTHENTICATION")) return mappingFor("auth-surface");
  if (normalized.includes("COOKIE") || normalized.includes("SESSION")) return mappingFor("cookie-review");
  if (normalized.includes("CORS")) return mappingFor("cors-review");
  if (normalized.includes("HEADER")) return mappingFor("header-review");
  if (normalized.includes("EXPOSURE") || normalized.includes("BACKUP") || normalized.includes("DIRECTORY LISTING") || normalized.includes("SOURCE MAP")) return mappingFor("exposure-review");
  if (normalized.includes("BUSINESS") || normalized.includes("PAYMENT") || normalized.includes("ENTITLEMENT")) return BUSINESS_FLOW;
  if (normalized.includes("RACE")) return mappingFor("controlled-race");
  for (const key of ["SSRF", "SERVER-SIDE REQUEST FORGERY", "COMMAND INJECTION", "TEMPLATE INJECTION", "PATH TRAVERSAL", "CROSS-SITE REQUEST FORGERY", "OPEN REDIRECT", "UNSAFE DESERIALIZATION", "XML EXTERNAL ENTITY", "HTTP DESYNCHRONIZATION", "PROTOTYPE POLLUTION", "JWT", "OAUTH", "CRLF", "FILE PROCESSING"]) if (normalized.includes(key)) return activeVulnerabilityMapping(key.replaceAll("-", "_").replaceAll(" ", "_"));
  return {};
}

function activeVulnerabilityMapping(value: string): StandardsMapping {
  if (value.includes("NOSQL")) return { wstg: ["WSTG-INJT-05"], asvs: ["v5.0.0-1.2.4"], cwe: ["CWE-943"], capec: ["CAPEC-676"] };
  if (value.includes("SQL")) return { wstg: ["WSTG-INJT-05"], asvs: ["v5.0.0-1.2.4"], cwe: ["CWE-89"], capec: ["CAPEC-66"] };
  if (value.includes("SECOND_ORDER")) return { wstg: ["WSTG-INJT-14"], asvs: ["v5.0.0-1.2.4", "v5.0.0-2.2.1"], cwe: ["CWE-74"] };
  if (value.includes("STORED_XSS")) return { wstg: ["WSTG-INJT-02"], asvs: ["v5.0.0-1.2.1"], cwe: ["CWE-79"], capec: ["CAPEC-63"] };
  if (value.includes("DOM") || value.includes("XSS")) return { wstg: ["WSTG-INJT-01", "WSTG-CLNT-01"], asvs: ["v5.0.0-1.2.1", "v5.0.0-3.4.3"], cwe: ["CWE-79"], capec: ["CAPEC-63"] };
  if (value.includes("SSRF") || value.includes("SERVER_SIDE_REQUEST_FORGERY")) return { wstg: ["WSTG-INJT-19"], asvs: ["v5.0.0-1.3.6"], api: ["API7:2023", "API10:2023"], cwe: ["CWE-918"], capec: ["CAPEC-664"] };
  if (value.includes("XXE") || value.includes("XML_EXTERNAL")) return { wstg: ["WSTG-INJT-07"], asvs: ["v5.0.0-1.5.3"], api: ["API8:2023", "API10:2023"], cwe: ["CWE-611"] };
  if (value.includes("COMMAND")) return { wstg: ["WSTG-INJT-12"], asvs: ["v5.0.0-1.2.5"], cwe: ["CWE-78"], capec: ["CAPEC-88"] };
  if (value.includes("TEMPLATE")) return { wstg: ["WSTG-INJT-18"], asvs: ["v5.0.0-1.3.7"], cwe: ["CWE-1336"] };
  if (value.includes("CRLF") || value.includes("RESPONSE_SPLITTING")) return { wstg: ["WSTG-INJT-15"], asvs: ["v5.0.0-1.2.1", "v5.0.0-4.2.4"], cwe: ["CWE-113"], capec: ["CAPEC-81"] };
  if (value.includes("PROTOTYPE")) return { wstg: ["WSTG-INJT-22"], asvs: ["v5.0.0-1.5.3"], cwe: ["CWE-1321"] };
  if (value.includes("JWT") || value.includes("JWK")) return { wstg: ["WSTG-SESS-10"], asvs: ["v5.0.0-9.1.1", "v5.0.0-9.1.2", "v5.0.0-9.1.3", "v5.0.0-9.2.1", "v5.0.0-9.2.3"], api: ["API2:2023"], cwe: ["CWE-347"] };
  if (value.includes("OAUTH") || value.includes("OIDC")) return { wstg: ["WSTG-ATHZ-05"], asvs: ["v5.0.0-10.2.1", "v5.0.0-10.2.2", "v5.0.0-10.3.1", "v5.0.0-10.5.3", "v5.0.0-10.5.4"], api: ["API2:2023"], cwe: ["CWE-287"] };
  if (value.includes("REQUEST_SMUGGLING") || value.includes("DESYNC")) return { wstg: ["WSTG-INJT-16"], asvs: ["v5.0.0-4.1.3", "v5.0.0-4.2.3"], api: ["API8:2023"], cwe: ["CWE-444"], capec: ["CAPEC-33"] };
  if (value.includes("FILE") || value.includes("ARCHIVE")) return { wstg: ["WSTG-BUSL-08", "WSTG-BUSL-09", "WSTG-ATHZ-01"], asvs: ["v5.0.0-5.2.1", "v5.0.0-5.2.2", "v5.0.0-5.2.3", "v5.0.0-5.2.4", "v5.0.0-5.2.5", "v5.0.0-5.3.2"], api: ["API4:2023"], cwe: ["CWE-22", "CWE-409"], capec: ["CAPEC-126"] };
  if (value.includes("PATH_TRAVERSAL")) return { wstg: ["WSTG-ATHZ-01"], asvs: ["v5.0.0-5.3.2"], cwe: ["CWE-22"], capec: ["CAPEC-126"] };
  if (value.includes("CSRF") || value.includes("CROSS_SITE_REQUEST_FORGERY")) return { wstg: ["WSTG-SESS-05"], asvs: ["v5.0.0-3.5.1"], cwe: ["CWE-352"], capec: ["CAPEC-62"] };
  if (value.includes("OPEN_REDIRECT")) return { wstg: ["WSTG-CLNT-04"], asvs: ["v5.0.0-1.2.1"], cwe: ["CWE-601"], capec: ["CAPEC-194"] };
  if (value.includes("CACHE_POISON")) return { wstg: ["WSTG-INJT-17"], asvs: ["v5.0.0-4.1.3", "v5.0.0-14.2.5"], api: ["API8:2023"], cwe: ["CWE-444", "CWE-524"] };
  if (value.includes("CACHE_DECEPTION")) return { asvs: ["v5.0.0-14.2.5"], api: ["API8:2023"], cwe: ["CWE-200", "CWE-524"] };
  if (value.includes("DESERIAL")) return { wstg: ["WSTG-INJT-23"], asvs: ["v5.0.0-1.5.3"], cwe: ["CWE-502"], capec: ["CAPEC-586"] };
  return { wstg: ["WSTG-INJT-11"], asvs: ["v5.0.0-2.2.1"], cwe: ["CWE-74"] };
}

function protocolMapping(value: string): StandardsMapping {
  if (value.includes("GRAPHQL")) return graphqlMapping(value);
  if (value.includes("WEBSOCKET")) return { wstg: ["WSTG-CLNT-10"], asvs: ["v5.0.0-4.4.1", "v5.0.0-4.4.2", "v5.0.0-4.4.3", "v5.0.0-4.4.4"], api: ["API2:2023", "API5:2023"], cwe: ["CWE-285", "CWE-287"] };
  if (value.includes("SMUGGL") || value.includes("DESYNCHRON")) return activeVulnerabilityMapping("REQUEST_SMUGGLING");
  if (value.includes("COMPRESSION") || value.includes("UPLOAD")) return { wstg: ["WSTG-BUSL-08", "WSTG-BUSL-09"], asvs: ["v5.0.0-5.2.1", "v5.0.0-5.2.3"], api: ["API4:2023"], cwe: ["CWE-400", "CWE-409"], capec: ["CAPEC-125"] };
  if (value.includes("CROSS_PROTOCOL_IDENTITY")) return merge(AUTHZ_FUNCTION, { asvs: ["v5.0.0-6.3.4"] });
  return { wstg: ["WSTG-APIT-01"], asvs: ["v5.0.0-4.1.3"], api: ["API8:2023", "API9:2023"] };
}

function authenticationMapping(value: string): StandardsMapping {
  if (value.includes("FIXATION")) return { wstg: ["WSTG-SESS-03"], asvs: ["v5.0.0-7.2.1"], api: ["API2:2023"], cwe: ["CWE-384"], capec: ["CAPEC-61"] };
  if (value.includes("ENUMERATION")) return mappingFor("auth-surface");
  if (value.includes("MFA")) return { wstg: ["WSTG-ATHN-11"], asvs: ["v5.0.0-6.3.4"], api: ["API2:2023"], cwe: ["CWE-287"] };
  if (value.includes("LOGOUT") || value.includes("EXPIR")) return { wstg: ["WSTG-SESS-06", "WSTG-SESS-07"], asvs: ["v5.0.0-7.4.1"], api: ["API2:2023"] };
  return { wstg: ["WSTG-ATHN-04", "WSTG-SESS-01", "WSTG-SESS-09"], asvs: ["v5.0.0-6.3.4", "v5.0.0-7.2.1"], api: ["API2:2023"], cwe: ["CWE-287"] };
}

function graphqlMapping(value: string): StandardsMapping {
  const base: StandardsMapping = { wstg: ["WSTG-APIT-99"], api: ["API8:2023", "API9:2023"] };
  if (value.includes("LIMIT") || value.includes("ALIAS") || value.includes("BATCH")) return merge(base, { asvs: ["v5.0.0-4.3.1"], api: ["API4:2023"], cwe: ["CWE-400"], capec: ["CAPEC-125"] });
  if (value.includes("INTROSPECTION")) return merge(base, { asvs: ["v5.0.0-4.3.2"] });
  if (value.includes("AUTH") || value.includes("SUBSCRIPTION")) return merge(base, AUTHZ_FUNCTION);
  return base;
}

function merge(...values: StandardsMapping[]): StandardsMapping {
  const result: Record<string, string[]> = {};
  for (const value of values) for (const key of ["wstg", "asvs", "api", "cwe", "capec"] as const) if (value[key]) result[key] = [...new Set([...(result[key] ?? []), ...value[key]!])];
  return result;
}
