const backupExtensionPattern = /(?:^|[._-])(?:backup|bak|old|dump|db|database|sql)(?:[._-][a-z0-9-]+)*\.(?:zip|tar|tgz|tar\.gz|bak|backup|old|sql|dump|7z|rar)$/i;
const explicitArchivePattern = /\.(?:zip|tar|tgz|tar\.gz|bak|backup|old|sql|dump|7z|rar)$/i;

export function isBackupPath(pathname: string): boolean {
  const filename = pathname.split("/").filter(Boolean).at(-1) ?? pathname;
  return explicitArchivePattern.test(filename) || backupExtensionPattern.test(filename);
}

export function hasBackupResponseEvidence(input: { pathname: string; contentType?: string | undefined; bodyPreview?: string | undefined }): boolean {
  const pathname = input.pathname.toLowerCase();
  const contentType = input.contentType?.toLowerCase() ?? "";
  const bodyPreview = input.bodyPreview ?? "";

  if (!isBackupPath(pathname)) {
    return false;
  }

  if (contentType.includes("text/html")) {
    return false;
  }

  if (/\.(?:js|css|map|png|jpe?g|gif|webp|svg|ico|woff2?)$/i.test(pathname)) {
    return false;
  }

  if (/\.(?:zip|jar|war|ear)$/i.test(pathname)) {
    return bodyPreview.startsWith("PK") || !contentType || contentType.includes("zip") || contentType.includes("octet-stream");
  }

  if (/\.(?:tar|tgz|tar\.gz|7z|rar)$/i.test(pathname)) {
    return !contentType || contentType.includes("octet-stream") || contentType.includes("gzip") || contentType.includes("x-tar") || contentType.includes("x-7z") || contentType.includes("rar");
  }

  if (/\.(?:sql|dump)$/i.test(pathname)) {
    return /(?:create\s+table|insert\s+into|mysqldump|postgresql database dump|--\s*dump)/i.test(bodyPreview) || contentType.startsWith("text/plain") || contentType.includes("sql") || !contentType;
  }

  return true;
}
