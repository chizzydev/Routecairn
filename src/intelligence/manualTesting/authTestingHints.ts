export const authTestingHints = {
  enumeration: "Check whether responses reveal which accounts, emails, or usernames exist.",
  bruteForce: "Test rate limiting and lockout behavior for authentication attempts within authorized limits.",
  resetAbuse: "Test password reset token handling, email flooding controls, and reset flow enumeration.",
  otpAbuse: "Test OTP rate limits, replay behavior, expiration, and delivery abuse controls.",
  sessionReview: "Review session endpoint behavior for cache control, auth state leakage, and cross-role visibility.",
  oauthReview: "Review OAuth callback and provider routes for redirect handling and account linking edge cases."
} as const;
