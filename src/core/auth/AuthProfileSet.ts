import type { AuthProfile, AuthProfileSummary } from "./AuthProfile.js";
import { loadAuthProfile, summarizeAuthProfile } from "./AuthProfile.js";

export interface AuthProfileSet {
  accountA: AuthProfile;
  accountB: AuthProfile;
}

export interface AuthProfileSetSummary {
  enabled: boolean;
  accountA?: AuthProfileSummary;
  accountB?: AuthProfileSummary;
  redactionApplied: boolean;
  notes: string[];
}

export async function loadAuthProfileSet(accountAPath: string, accountBPath: string): Promise<AuthProfileSet> {
  const [accountA, accountB] = await Promise.all([loadAuthProfile(accountAPath), loadAuthProfile(accountBPath)]);
  return { accountA, accountB };
}

export function summarizeAuthProfileSet(profileSet: AuthProfileSet | undefined): AuthProfileSetSummary {
  if (!profileSet) {
    return {
      enabled: false,
      redactionApplied: true,
      notes: ["No account A/account B auth profiles supplied. Role comparison was skipped."]
    };
  }

  return {
    enabled: true,
    accountA: summarizeAuthProfile(profileSet.accountA),
    accountB: summarizeAuthProfile(profileSet.accountB),
    redactionApplied: true,
    notes: [
      "Account A and Account B auth material was used only for comparison requests and redacted from reports.",
      "Role comparison results are access-control hypotheses that need manual verification against the application's intended authorization model."
    ]
  };
}
