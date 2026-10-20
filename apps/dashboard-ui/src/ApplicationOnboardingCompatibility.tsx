import React, { useState } from "react";
import {
  assessApplicationOnboardingCompatibility,
  unknownOnboardingCompatibility,
  type ApplicationOnboardingCompatibilityInput
} from "../../../src/dashboard/contracts/ApplicationOnboardingCompatibility";

/** Runs locally before credentials are entered. It sends and persists nothing. */
export function ApplicationOnboardingCompatibility() {
  const [facts, setFacts] = useState<ApplicationOnboardingCompatibilityInput>({ ...unknownOnboardingCompatibility });
  const result = assessApplicationOnboardingCompatibility(facts);
  const questions = [
    [
      "tenantIdentity",
      "Verified tenant identity exists",
      [
        ["PRESENT", "Present"],
        ["ABSENT", "Application has no tenant identity"]
      ]
    ],
    [
      "actorProfiles",
      "Legitimate target-bound actor profiles",
      [
        ["THREE_DISTINCT", "Three distinct principals available"],
        ["INSUFFICIENT", "Not available"]
      ]
    ],
    [
      "getEffects",
      "GET handler and middleware effects",
      [
        ["READ_ONLY", "Reviewed as non-mutating"],
        ["WRITES", "Writes state, including session metadata"]
      ]
    ],
    [
      "runtimeIsolation",
      "Local database and outbound-service isolation",
      [
        ["CONFIRMED", "Separately established"],
        ["UNCONFIRMED", "Not established"]
      ]
    ],
    [
      "resourceShape",
      "Ownership observation shape",
      [
        ["SCALAR_MARKERS", "Exact scalar identity and ownership markers"],
        ["COLLECTION_ONLY", "Only collections or self endpoints available"]
      ]
    ]
  ] as const;
  return (
    <details>
      <summary>Check application compatibility before entering credentials</summary>
      <section aria-label="Offline application compatibility">
        <p>
          Review source facts first. This check sends no requests, reads no credentials and saves nothing. Missing
          tenant support must never be worked around with invented identity fields.
        </p>
        {questions.map(([key, label, options]) => (
          <label key={key}>
            {label}
            <select
              aria-label={label}
              value={facts[key]}
              onChange={(e) => setFacts((current) => ({ ...current, [key]: e.target.value }))}
            >
              <option value="UNKNOWN">Not established</option>
              {options.map(([value, text]) => (
                <option key={value} value={value}>
                  {text}
                </option>
              ))}
            </select>
          </label>
        ))}
        <div aria-live="polite">
          <p>Compatibility: {result.status}</p>
          <ul>
            {result.blockers.map((b) => (
              <li key={b.code}>{b.message}</li>
            ))}
          </ul>
          {result.unknown.length > 0 && (
            <p>Unestablished facts: {result.unknown.length}. Resolve these before declaring readiness.</p>
          )}
          <p>{result.notice}</p>
          {result.status === "BLOCKED" && (
            <p>
              Stop setup here until these blockers are resolved. This advisory cannot grant or change server
              authorization.
            </p>
          )}
        </div>
      </section>
    </details>
  );
}
