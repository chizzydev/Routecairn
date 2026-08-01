export function isConfigPath(pathname: string): boolean {
  return /(?:^|\/)(?:\.env|config(?:\.json|\.js|\.yml|\.yaml)?|settings(?:\.json|\.py)?|firebase\.json|vercel\.json|netlify\.toml)$/i.test(pathname);
}
