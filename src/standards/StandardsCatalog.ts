import type { StandardsFramework, StandardsReference } from "./StandardsCoverageTypes.js";

export interface StandardsMapping {
  wstg?: readonly string[];
  asvs?: readonly string[];
  api?: readonly string[];
  cwe?: readonly string[];
  capec?: readonly string[];
}

type CatalogEntry = Omit<StandardsReference, "framework" | "strength">;

const WSTG_BASE = "https://wstg.owasp.org/latest/?search=";
const ASVS_BASE = "https://github.com/OWASP/ASVS/tree/v5.0.0/5.0";
const API_BASE = "https://api-security.owasp.org/editions/2023/en/";
const CWE_BASE = "https://cwe.mitre.org/data/definitions/";
const CAPEC_BASE = "https://capec.mitre.org/data/definitions/";

export const wstgAreas = [
  { id: "INFO", title: "Information Gathering" },
  { id: "CONF", title: "Configuration and Deployment Management Testing" },
  { id: "IDNT", title: "Identity Management Testing" },
  { id: "ATHN", title: "Authentication Testing" },
  { id: "ATHZ", title: "Authorization Testing" },
  { id: "SESS", title: "Session Management Testing" },
  { id: "INJT", title: "Input Validation Testing" },
  { id: "ERRH", title: "Error Handling" },
  { id: "CRYP", title: "Weak Cryptography" },
  { id: "BUSL", title: "Business Logic Testing" },
  { id: "CLNT", title: "Client-side Testing" },
  { id: "APIT", title: "API Testing" }
] as const;

const catalog: Record<StandardsFramework, Record<string, CatalogEntry>> = {
  OWASP_WSTG: Object.fromEntries([
    ["WSTG-INFO-02", "Fingerprint Web Server"], ["WSTG-INFO-04", "Attack Surface Identification"], ["WSTG-INFO-05", "Review Web Page Content for Information Leakage"], ["WSTG-INFO-06", "Identify Application Entry Points"], ["WSTG-INFO-07", "Map Execution Paths Through Application"], ["WSTG-INFO-08", "Fingerprint Web Application Framework"], ["WSTG-INFO-10", "Map Application Architecture"],
    ["WSTG-CONF-04", "Review Old Backup and Unreferenced Files"], ["WSTG-CONF-05", "Enumerate Administration Interfaces"], ["WSTG-CONF-06", "Test HTTP Methods"], ["WSTG-CONF-07", "Test HTTP Strict Transport Security"], ["WSTG-CONF-11", "Test Cloud Storage"], ["WSTG-CONF-12", "Test Content Security Policy"], ["WSTG-CONF-14", "Test HTTP Security Header Misconfigurations"],
    ["WSTG-IDNT-01", "Test Role Definitions"], ["WSTG-IDNT-04", "Test Account Enumeration"],
    ["WSTG-ATHN-01", "Test Credentials Transported over an Encrypted Channel"], ["WSTG-ATHN-03", "Test Weak Lockout Mechanism"], ["WSTG-ATHN-04", "Test Authentication Bypass"], ["WSTG-ATHN-09", "Test Password Change and Reset"], ["WSTG-ATHN-10", "Test Weaker Authentication in Alternative Channels"], ["WSTG-ATHN-11", "Test Multi-factor Authentication"],
    ["WSTG-ATHZ-01", "Test Directory Traversal and File Include"], ["WSTG-ATHZ-02", "Test Authorization Bypass"], ["WSTG-ATHZ-03", "Test Privilege Escalation"], ["WSTG-ATHZ-04", "Test Insecure Direct Object References"], ["WSTG-ATHZ-05", "Test OAuth Weaknesses"],
    ["WSTG-SESS-01", "Test Session Management Schema"], ["WSTG-SESS-02", "Test Cookie Attributes"], ["WSTG-SESS-03", "Test Session Fixation"], ["WSTG-SESS-04", "Test Exposed Session Variables"], ["WSTG-SESS-05", "Test Cross-Site Request Forgery"], ["WSTG-SESS-06", "Test Logout Functionality"], ["WSTG-SESS-07", "Test Session Timeout"], ["WSTG-SESS-09", "Test Session Hijacking"], ["WSTG-SESS-10", "Test JSON Web Tokens"], ["WSTG-SESS-11", "Test Concurrent Sessions"],
    ["WSTG-INJT-01", "Test Reflected Cross-Site Scripting"], ["WSTG-INJT-02", "Test Stored Cross-Site Scripting"], ["WSTG-INJT-03", "Test HTTP Verb Tampering"], ["WSTG-INJT-04", "Test HTTP Parameter Pollution"], ["WSTG-INJT-05", "Test SQL and NoSQL Injection"], ["WSTG-INJT-07", "Test XML Injection"], ["WSTG-INJT-11", "Test Code Injection"], ["WSTG-INJT-12", "Test Command Injection"], ["WSTG-INJT-14", "Test Incubated Vulnerabilities"], ["WSTG-INJT-15", "Test HTTP Response Splitting"], ["WSTG-INJT-16", "Test HTTP Request Smuggling"], ["WSTG-INJT-17", "Test Host Header Injection"], ["WSTG-INJT-18", "Test Server-side Template Injection"], ["WSTG-INJT-19", "Test Server-Side Request Forgery"], ["WSTG-INJT-20", "Test Mass Assignment"], ["WSTG-INJT-22", "Test Prototype Pollution"], ["WSTG-INJT-23", "Test Insecure Deserialization"],
    ["WSTG-ERRH-01", "Test Improper Error Handling"], ["WSTG-ERRH-02", "Test Stack Traces"],
    ["WSTG-CRYP-01", "Test Weak Transport Layer Security"], ["WSTG-CRYP-03", "Test Sensitive Information Sent via Unencrypted Channels"], ["WSTG-CRYP-04", "Test Weak Cryptographic Primitives"],
    ["WSTG-BUSL-01", "Test Business Logic Data Validation"], ["WSTG-BUSL-02", "Test Ability to Forge Requests"], ["WSTG-BUSL-03", "Test Integrity Checks"], ["WSTG-BUSL-04", "Test Process Timing"], ["WSTG-BUSL-05", "Test Function Use Limits"], ["WSTG-BUSL-06", "Test Workflow Circumvention"], ["WSTG-BUSL-07", "Test Defenses Against Application Misuse"], ["WSTG-BUSL-08", "Test Upload of Unexpected File Types"], ["WSTG-BUSL-09", "Test Upload of Malicious Files"], ["WSTG-BUSL-10", "Test Payment Functionality"],
    ["WSTG-CLNT-01", "Test DOM-based Cross-Site Scripting"], ["WSTG-CLNT-04", "Test Client-side URL Redirect"], ["WSTG-CLNT-07", "Test Cross-Origin Resource Sharing"], ["WSTG-CLNT-09", "Test Clickjacking"], ["WSTG-CLNT-10", "Test WebSockets"], ["WSTG-CLNT-12", "Test Browser Storage"], ["WSTG-CLNT-13", "Test Cross-Site Script Inclusion"], ["WSTG-CLNT-15", "Test Client-Side Template Injection"],
    ["WSTG-APIT-01", "API Reconnaissance"], ["WSTG-APIT-02", "Test API Broken Object Level Authorization"], ["WSTG-APIT-03", "Test Excessive Data Exposure"], ["WSTG-APIT-04", "Test API Broken Function Level Authorization"], ["WSTG-APIT-99", "Test GraphQL"]
  ].map(([id, title]) => [id!, { id: id!, title: title!, url: `${WSTG_BASE}${encodeURIComponent(id!)}` }])),
  OWASP_ASVS: Object.fromEntries([
    ["v5.0.0-1.2.1", "Context-aware output encoding"], ["v5.0.0-1.2.4", "Database query injection prevention"], ["v5.0.0-1.2.5", "Operating-system command injection prevention"], ["v5.0.0-1.3.6", "Server-side request forgery prevention"], ["v5.0.0-1.3.7", "Template injection prevention"], ["v5.0.0-1.5.3", "Consistent parser behavior"],
    ["v5.0.0-2.2.1", "Business input validation"], ["v5.0.0-2.3.1", "Business-flow sequencing"], ["v5.0.0-2.3.2", "Business-logic limits"], ["v5.0.0-2.3.3", "Business transaction integrity"], ["v5.0.0-2.3.4", "Business resource locking"], ["v5.0.0-2.4.1", "Anti-automation controls"], ["v5.0.0-2.4.2", "Realistic business-flow timing"],
    ["v5.0.0-3.3.4", "HttpOnly session cookies"], ["v5.0.0-3.4.2", "CORS origin validation"], ["v5.0.0-3.4.3", "Content Security Policy"], ["v5.0.0-3.4.4", "Content type sniffing prevention"], ["v5.0.0-3.5.1", "Cross-site request forgery prevention"], ["v5.0.0-3.5.3", "Safe HTTP methods for sensitive functions"], ["v5.0.0-3.5.7", "Authorization data excluded from scripts"], ["v5.0.0-3.6.1", "External resource integrity"],
    ["v5.0.0-4.1.3", "Intermediary header integrity"], ["v5.0.0-4.2.3", "HTTP/2 and HTTP/3 connection-header validation"], ["v5.0.0-4.2.4", "HTTP/2 and HTTP/3 CRLF validation"], ["v5.0.0-4.3.1", "GraphQL query resource limits"], ["v5.0.0-4.3.2", "GraphQL introspection policy"], ["v5.0.0-4.4.1", "WebSocket TLS"], ["v5.0.0-4.4.2", "WebSocket Origin validation"], ["v5.0.0-4.4.3", "WebSocket session tokens"], ["v5.0.0-4.4.4", "WebSocket session transition"],
    ["v5.0.0-5.2.1", "File processing size limits"], ["v5.0.0-5.2.2", "File type and content validation"], ["v5.0.0-5.2.3", "Archive expansion limits"], ["v5.0.0-5.2.4", "Per-user file quotas"], ["v5.0.0-5.2.5", "Archive symlink controls"], ["v5.0.0-5.3.2", "Trusted file path construction"], ["v5.0.0-5.4.2", "Download filename encoding"],
    ["v5.0.0-6.3.1", "Authentication abuse controls"], ["v5.0.0-6.3.4", "Consistent authentication pathways"], ["v5.0.0-6.3.8", "Account enumeration resistance"],
    ["v5.0.0-7.2.1", "Trusted backend session-token verification"], ["v5.0.0-7.4.1", "Session termination"],
    ["v5.0.0-8.2.1", "Function-level authorization"], ["v5.0.0-8.2.2", "Data-specific object authorization"], ["v5.0.0-8.2.3", "Field-level authorization"], ["v5.0.0-8.3.1", "Trusted service-layer authorization"],
    ["v5.0.0-9.1.1", "Self-contained token signature validation"], ["v5.0.0-9.1.2", "Self-contained token algorithm allowlist"], ["v5.0.0-9.1.3", "Trusted self-contained token key sources"], ["v5.0.0-9.2.1", "Self-contained token validity period"], ["v5.0.0-9.2.3", "Self-contained token audience validation"],
    ["v5.0.0-10.2.1", "OAuth client request-forgery defense"], ["v5.0.0-10.2.2", "OAuth authorization-server mix-up defense"], ["v5.0.0-10.3.1", "OAuth resource-server audience validation"], ["v5.0.0-10.5.3", "OIDC issuer metadata validation"], ["v5.0.0-10.5.4", "OIDC ID Token audience validation"],
    ["v5.0.0-11.1.1", "Cryptographic key lifecycle policy"], ["v5.0.0-11.2.1", "Industry-validated cryptographic implementations"],
    ["v5.0.0-12.1.1", "Recommended TLS versions"], ["v5.0.0-12.1.2", "Recommended cipher suites"], ["v5.0.0-12.2.1", "TLS for external HTTP services"], ["v5.0.0-12.3.1", "Encrypted service-to-service communication"],
    ["v5.0.0-14.1.1", "Sensitive-data classification"], ["v5.0.0-14.2.1", "Sensitive data excluded from URLs"], ["v5.0.0-14.2.3", "Sensitive data excluded from untrusted parties"], ["v5.0.0-14.2.5", "Sensitive dynamic content excluded from caches"], ["v5.0.0-14.2.6", "Minimum sensitive-data disclosure"], ["v5.0.0-14.3.3", "Sensitive data excluded from browser storage"],
    ["v5.0.0-16.5.1", "Generic error messages without internal data"], ["v5.0.0-16.5.2", "Secure external-resource failure handling"]
  ].map(([id, title]) => [id!, { id: id!, title: title!, url: ASVS_BASE }])),
  OWASP_API_TOP_10: Object.fromEntries([
    ["API1:2023", "Broken Object Level Authorization", "0xa1-broken-object-level-authorization/"],
    ["API2:2023", "Broken Authentication", "0xa2-broken-authentication/"],
    ["API3:2023", "Broken Object Property Level Authorization", "0xa3-broken-object-property-level-authorization/"],
    ["API4:2023", "Unrestricted Resource Consumption", "0xa4-unrestricted-resource-consumption/"],
    ["API5:2023", "Broken Function Level Authorization", "0xa5-broken-function-level-authorization/"],
    ["API6:2023", "Unrestricted Access to Sensitive Business Flows", "0xa6-unrestricted-access-to-sensitive-business-flows/"],
    ["API7:2023", "Server Side Request Forgery", "0xa7-server-side-request-forgery/"],
    ["API8:2023", "Security Misconfiguration", "0xa8-security-misconfiguration/"],
    ["API9:2023", "Improper Inventory Management", "0xa9-improper-inventory-management/"],
    ["API10:2023", "Unsafe Consumption of APIs", "0xaa-unsafe-consumption-of-apis/"]
  ].map(([id, title, path]) => [id!, { id: id!, title: title!, url: `${API_BASE}${path}` }])),
  CWE: Object.fromEntries([
    ["CWE-20", "Improper Input Validation"], ["CWE-22", "Path Traversal"], ["CWE-74", "Injection"], ["CWE-77", "Command Injection"], ["CWE-78", "OS Command Injection"], ["CWE-79", "Cross-site Scripting"], ["CWE-89", "SQL Injection"], ["CWE-113", "HTTP Response Splitting"], ["CWE-200", "Exposure of Sensitive Information"], ["CWE-209", "Generation of Error Message Containing Sensitive Information"], ["CWE-285", "Improper Authorization"], ["CWE-287", "Improper Authentication"], ["CWE-319", "Cleartext Transmission of Sensitive Information"], ["CWE-326", "Inadequate Encryption Strength"], ["CWE-347", "Improper Verification of Cryptographic Signature"], ["CWE-352", "Cross-Site Request Forgery"], ["CWE-362", "Race Condition"], ["CWE-384", "Session Fixation"], ["CWE-400", "Uncontrolled Resource Consumption"], ["CWE-409", "Improper Handling of Highly Compressed Data"], ["CWE-444", "HTTP Request/Response Smuggling"], ["CWE-502", "Deserialization of Untrusted Data"], ["CWE-524", "Use of Cache Containing Sensitive Information"], ["CWE-601", "Open Redirect"], ["CWE-611", "Improper Restriction of XML External Entity Reference"], ["CWE-639", "Authorization Bypass Through User-Controlled Key"], ["CWE-799", "Improper Control of Interaction Frequency"], ["CWE-862", "Missing Authorization"], ["CWE-918", "Server-Side Request Forgery"], ["CWE-942", "Permissive Cross-domain Policy"], ["CWE-943", "Improper Neutralization in Data Query Logic"], ["CWE-1004", "Sensitive Cookie Without HttpOnly Flag"], ["CWE-1321", "Prototype Pollution"], ["CWE-1336", "Template Engine Injection"]
  ].map(([id, title]) => [id!, { id: id!, title: title!, url: `${CWE_BASE}${id!.slice(4)}.html` }])),
  CAPEC: Object.fromEntries([
    ["CAPEC-33", "HTTP Request Smuggling"], ["CAPEC-61", "Session Fixation"], ["CAPEC-62", "Cross Site Request Forgery"], ["CAPEC-63", "Cross-Site Scripting"], ["CAPEC-66", "SQL Injection"], ["CAPEC-81", "Web Server Logs Tampering"], ["CAPEC-88", "OS Command Injection"], ["CAPEC-125", "Flooding"], ["CAPEC-126", "Path Traversal"], ["CAPEC-194", "Fake the Source of Data"], ["CAPEC-586", "Object Injection"], ["CAPEC-664", "Server Side Request Forgery"], ["CAPEC-676", "NoSQL Injection"]
  ].map(([id, title]) => [id!, { id: id!, title: title!, url: `${CAPEC_BASE}${id!.slice(6)}.html` }]))
};

export function referencesFor(mapping: StandardsMapping): StandardsReference[] {
  const groups: Array<[StandardsFramework, readonly string[] | undefined]> = [["OWASP_WSTG", mapping.wstg], ["OWASP_ASVS", mapping.asvs], ["OWASP_API_TOP_10", mapping.api], ["CWE", mapping.cwe], ["CAPEC", mapping.capec]];
  const values: StandardsReference[] = [];
  for (const [framework, ids] of groups) for (const id of ids ?? []) {
    const entry = catalog[framework][id];
    if (!entry) throw new Error(`Unknown standards reference ${framework}/${id}.`);
    values.push({ framework, ...entry, strength: framework === "CWE" || framework === "CAPEC" ? "SUPPORTING" : "DIRECT" });
  }
  return values;
}

export function wstgAreaFor(id: string): string | undefined {
  return /^WSTG-([A-Z]+)-/.exec(id)?.[1];
}

export function assertStandardsCatalog(): void {
  for (const [framework, entries] of Object.entries(catalog)) for (const [id, entry] of Object.entries(entries)) {
    if (id !== entry.id || !entry.title || !URL.canParse(entry.url)) throw new Error(`Invalid standards catalog entry ${framework}/${id}.`);
  }
}

assertStandardsCatalog();
